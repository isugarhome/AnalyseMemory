#include "AnalyseLeak.h"
#include <QString>
#include <QByteArray>
#include <QFile>
#include <QDebug>
#include <QRegExp>
#include <QCryptographicHash>
#include <QTextStream>
#include <QFileDialog>
#include <QFileInfo>
#include <QProcess>

bool operator<(const LeakBlock&l, const LeakBlock&r)
{
	if (l.activity > r.activity)
	{
		return true;
	}
	else  if (l.activity == r.activity)
	{
		if (l.leakTotalSize > r.leakTotalSize)
		{
			return true;
		}
		else if (l.leakTotalSize < r.leakTotalSize)
		{
			return false;
		}
		else
		{
			return l.uuid >= r.uuid;
		}
	}
	else
	{
		return false;
	}
}

AnalyseLeak::AnalyseLeak(QWidget *parent)
	: QMainWindow(parent)
{
	ui.setupUi(this);
	connect(ui.btnAnalyseLeak, SIGNAL(clicked(bool)), this, SLOT(onBtnAnalyseClicked(bool)));
	connect(ui.btnLoadResultFile, SIGNAL(clicked(bool)), this, SLOT(onBtnLoadResultFileClicked(bool)));
	
	QFileInfo fileInfo(QCoreApplication::applicationName());
	m_appSettingsFilePath = QCoreApplication::applicationDirPath() + QDir::separator() + fileInfo.baseName() + "Setting.ini";

	// 初始化文本框的内容和默认打开的路径
	QSettings appSettings(m_appSettingsFilePath, QSettings::IniFormat, this);
	QString prevFilePath = appSettings.value("lastFilePath", QCoreApplication::applicationDirPath()).toString();
	QDir dir(prevFilePath);
	m_prevDirPath = dir.absolutePath();
	ui.lineEditResultFile->setText(prevFilePath);
}

void AnalyseLeak::onBtnLoadResultFileClicked(bool)
{
	QString fileName = QFileDialog::getOpenFileName(this, tr("Open File"),
		m_prevDirPath, tr("LeakFile (*.txt *.*)"));
	if (fileName.isEmpty())
	{
		return;
	}

	m_inFile = fileName;

	// 设置文本框的内容
	ui.lineEditResultFile->setText(m_inFile);

	QDir dir(m_inFile);
	m_prevDirPath = dir.absolutePath();

	// 记录上一次的打开的文件路径
	QSettings appSettings(m_appSettingsFilePath, QSettings::IniFormat, this);
	appSettings.setValue("lastFilePath", m_inFile);
}

void doParseSymbol(const QString &byarrLine, const bool isBaseAddress, qint64 *pBaseAddr, LeakBlock *pBlock)
{
	if (nullptr == pBaseAddr || nullptr == pBlock)
	{
		return;
	}

	LeakBlock &block = *pBlock;
	QList<QString> strList = byarrLine.split("   ", QString::SkipEmptyParts);
	bool isNoAddressLine = false;
	if (strList.count() <= 1)
	{
		isNoAddressLine = true;
	}

	// 到这里都认为是context的内容
	int i = 0;
	for (QString &str : strList)
	{
		str = str.trimmed();
		++i;

		// 由于每次加载的库的地址都不一样，为了保证
		// 堆栈的唯一性，需要对地址进行特殊处理，如果是
		// 库地址，则直接跳过，如果是库中某个符号的地址，
		// 则减去对应库的地址，取相对地址
		if (1 == i && !isNoAddressLine)
		{
			if (isBaseAddress)
			{
				bool isOk = false;
				*pBaseAddr = str.toLongLong(&isOk, 16);
				continue;
			}
			else
			{
				bool isOk = false;
				qint64 addressOfSymbol = str.toLongLong(&isOk, 16);
				qint64 addressOfSymbolRelative = addressOfSymbol - *pBaseAddr;
				str = QString("%1 ").arg(addressOfSymbolRelative, 16, 16, QLatin1Char('0'));
			}
		}

		block.context += "  " + str;
	}

	block.context += "\r\n";				
	return;
}

bool addLeakBlockToResult(const LeakBlock& leakBlock, QHash<QByteArray, LeakBlock> *pLeakBlockResult)
{
	bool ret = true;
	if (nullptr == pLeakBlockResult)
	{
		return false;
	}

	QHash<QByteArray, LeakBlock>::iterator iterResult;
	QHash<QByteArray, LeakBlock> &leakBlockResult = *pLeakBlockResult;

	// 如果找到了，则累加到前一次的结果中去
	iterResult = leakBlockResult.find(leakBlock.uuid);
	if (iterResult != leakBlockResult.end())
	{
		if (leakBlock.leakBlockSize != iterResult->leakBlockSize)
		{
			qDebug() << "leakBlock and iterResult's alloc size is different";
			ret = false;
		}

		iterResult->leakNum += leakBlock.leakNum;
		iterResult->strAllocID += "+" + leakBlock.strAllocID;
		iterResult->leakTotalSize = iterResult->leakNum * iterResult->leakBlockSize;
		if (leakBlock.leakNum != 0)
		{
			// 如果泄露总的大小超过了底线总大小则更新底线总大小
			if (iterResult->deadlineTotalSize < leakBlock.leakTotalSize)
			{
				iterResult->deadlineTotalSize = leakBlock.leakTotalSize;
				++iterResult->activity;
			}
			else if (leakBlock.leakTotalSize <= 0) // 如果小于等于0了则活跃度置为0
			{
				iterResult->activity = 0;
			}
		}
		else // 如果本次没有变化
		{
			// do nonthing 
		}
	}
	else // 如果是第一次，则插入到结果中去
	{
		LeakBlock tmpLeakBlock = leakBlock;
		if (tmpLeakBlock.leakTotalSize > 0)
		{
			++tmpLeakBlock.activity;
		}
		else // 如果当前的泄露大小小于等于0，则不做活跃度处理，默认为0
		{
			// do nonthing;
		}

		// 如果泄露总的大小超过了底线总大小则更新底线总大小
		if (tmpLeakBlock.deadlineTotalSize < leakBlock.leakTotalSize)
		{
			tmpLeakBlock.deadlineTotalSize = leakBlock.leakTotalSize;
		}

		leakBlockResult[tmpLeakBlock.uuid] = tmpLeakBlock;
	}

	return ret;
}

bool getLeakResult(const QHash<QByteArray, LeakBlock>&firstLeakBlock,
	const QHash<QByteArray, LeakBlock>&secondLeakBlock, QHash<QByteArray, LeakBlock> *pLeakBlockResult)
{
	if (nullptr == pLeakBlockResult)
	{
		return false;
	}

	QHash<QByteArray, LeakBlock>tmpsecondLeakBlock = secondLeakBlock;
	
	QHash<QByteArray, LeakBlock>::const_iterator cIterL = firstLeakBlock.begin();
	QHash<QByteArray, LeakBlock>::const_iterator cIterR;
	for (; cIterL != firstLeakBlock.end(); ++cIterL)
	{
		// 如果在第二次找到了，则将第二次剪掉第一次
		cIterR = secondLeakBlock.find(cIterL.key());
		if (cIterR != secondLeakBlock.end())
		{
			if (cIterL->leakBlockSize != cIterR->leakBlockSize)
			{
				qDebug() << "iterL and iterR is different";
			}

			LeakBlock leakBlockDiff = cIterR.value();
			leakBlockDiff.leakNum = cIterR->leakNum - cIterL->leakNum;
			leakBlockDiff.strAllocID += "-" + cIterL->strAllocID;
			leakBlockDiff.leakTotalSize = leakBlockDiff.leakNum * leakBlockDiff.leakBlockSize;
			addLeakBlockToResult(leakBlockDiff, pLeakBlockResult);
			tmpsecondLeakBlock.remove(cIterR->uuid);
		}
		else
		{
			LeakBlock leakBlockDiff = cIterL.value();
			leakBlockDiff.leakNum = -leakBlockDiff.leakNum;
			leakBlockDiff.leakTotalSize = -leakBlockDiff.leakTotalSize;
			addLeakBlockToResult(leakBlockDiff, pLeakBlockResult);
		}
	}

	// 将R中剩余的部分添加到Result里面
	QHash<QByteArray, LeakBlock>::const_iterator tmpIterR = tmpsecondLeakBlock.begin();
	for (; tmpIterR != tmpsecondLeakBlock.end(); ++tmpIterR)
	{
		addLeakBlockToResult(tmpIterR.value(), pLeakBlockResult);
	}

	return true;
}

bool AnalyseLeak::doAnalyse(const QString &filePath, QVector<LeakBlock> *pvecLeakBlockResult, int *pnActivite)
{
	if (nullptr == pvecLeakBlockResult)
	{
		qDebug() << "pvecLeakBlockResult is null";
		return false;
	}

	if (nullptr == pnActivite)
	{
		qDebug() << "pnActivite is null";
		return false;
	}

	QVector<LeakBlock> &vecLeakBlockResult = *pvecLeakBlockResult;

	bool isEof = false;
	LeakBlock block;
	QRegExp rxLeakInfoStartLine("^leaks:.*");
	QRegExp rxLeakInfoEndLine("^  sum:.*");
	QRegExp rxLeakBlockStartLine("\\(#[0-9]+\\)");
	QRegExp rxLeakBlockCnt(" \\* ");
	QRegExp rxLeakContextWithNoAddress("^[ ]{8,}.*");
	QRegExp rxBaseDLLAddress("^[ ]{4,4}0x.*");	// 包含dll和exe
	QRegExp rxSymbolAddress("^[ ]{6,6}.*");	// 包含无地址的和有地址的行
	qint64 totalLeakByte = 0;
	qint64 totalLeakCount = 0;
	bool result = true;
	qint64 baseAddr = 0;

	QFile fileAnalyse(filePath);
	if (!fileAnalyse.open(QIODevice::ReadOnly | QIODevice::Text))
	{
		qDebug() << "open file " << filePath << " failed";
		return false;
	}

	QHash<QByteArray, LeakBlock> *pFirstBlockList = NULL;
	QHash<QByteArray, LeakBlock> *pSecondBlockList = NULL;
	QHash<QByteArray, LeakBlock>::iterator iter;
	QHash<QByteArray, LeakBlock> tmpLeakBlockResult;
	bool isBaseAddress = false;

	QFileInfo fileInfo(filePath);
	int nTotalSize = fileInfo.size();
	const double minPercentPerUpdate = 1.0;
	double nextUpdatePercent = 1;
	
	while (!isEof)
	{
		QString byarrLine = fileAnalyse.readLine();
		if (fileAnalyse.atEnd())
		{
			isEof = true;
			break;
		}

		int nCurrPos = fileAnalyse.pos();
		double nCurrPercent = (100.0 * nCurrPos) / nTotalSize;
		if (nCurrPercent > nextUpdatePercent)
		{
			nextUpdatePercent += minPercentPerUpdate;
			
			ui.progressBarAnalsyLeak->setValue((int)nCurrPercent);

			QCoreApplication::processEvents();
		}

		// 跳过空行
		if (byarrLine.trimmed().isEmpty())
		{
			continue;
		}
		
		// 查找符号地址开始的行
		if (-1 != rxSymbolAddress.indexIn(byarrLine))
		{
			isBaseAddress = false;
			doParseSymbol(byarrLine, isBaseAddress, &baseAddr, &block);
			continue;
		}
			
		// 查找基础库和dll模块库
		if (-1 != rxBaseDLLAddress.indexIn(byarrLine))
		{
			isBaseAddress = true;
			doParseSymbol(byarrLine, isBaseAddress, &baseAddr, &block);
			continue;
		}

		// 查找LeakBlock开始的行
		if (-1 != rxLeakBlockStartLine.indexIn(byarrLine))
		{
			if (!block.context.isEmpty())
			{
				// 根据context 计算uuid
				QByteArray byarrContext = block.context.toUtf8();
				byarrContext += QString("%1").arg(block.leakBlockSize);
				block.uuid = QCryptographicHash::hash(byarrContext, QCryptographicHash::Sha256);
				block.uuid = block.uuid.toHex();
				// 此处做个安全判断, 如果在现有的map中找的到这个
				// uuid, 说明hash256算法冲突了，结果可能是错误的（hash256冲突的概率比较小，暂不考虑）
				// 此处认为是同一个堆栈，将其合并
				iter = pSecondBlockList->find(block.uuid);
				if (iter != pSecondBlockList->end())
				{
					qDebug() << "this hash256 is exist in this context in AllocID " <<
						iter->strAllocID << ":" << block.strAllocID;
					if (iter->leakTotalSize != block.leakBlockSize)
					{
						qDebug() << "this hash256 is wrong in this context in AllocID " <<
							iter->strAllocID << ":" << block.strAllocID;
						result = false;
					}

					iter->strAllocID = iter->strAllocID + "+" + block.strAllocID;
					iter->leakNum += block.leakNum;
					iter->leakTotalSize = iter->leakNum * iter->leakBlockSize;
				}
				else
				{
					pSecondBlockList[0][block.uuid] = block;
				}
			}

			// 初始化下一个泄露块的信息
			block.context.clear();
			block.strAllocID.clear();

			QList<QString> strList = byarrLine.split(" ", QString::SkipEmptyParts);
			block.leakBlockSize = strList[0].toLongLong();
			if (strList.count() >= 8)
			{
				block.leakNum = strList[3].toLongLong();
				block.leakTotalSize = strList[5].toLongLong();
				block.strAllocID = strList[7].trimmed();
			}
			else
			{
				block.leakNum = 1;
				block.leakTotalSize = block.leakBlockSize;
				block.strAllocID = strList[2].trimmed();
			}
			continue;
		}

		// 查找leaks：开头的行
		if (-1 != rxLeakInfoStartLine.indexIn(byarrLine))
		{
			// 将上一次的结果和这次的结果做一次统计
			if ((nullptr != pFirstBlockList) && 
				(nullptr != pSecondBlockList))
			{
				getLeakResult(*pFirstBlockList, *pSecondBlockList, &tmpLeakBlockResult);
				++(*pnActivite);
			}

			// 将此次结果变为上一次的结果，解析下一次的结果
			if (nullptr != pFirstBlockList)
			{
				delete pFirstBlockList;
				pFirstBlockList = nullptr;
			}

			pFirstBlockList = pSecondBlockList;
			pSecondBlockList = new QHash<QByteArray, LeakBlock>();
			continue;
		}

		// 是否已经到泄露信息的结尾
		if (-1 != rxLeakInfoEndLine.indexIn(byarrLine))
		{
			QList<QString>byarrElems = byarrLine.split(" ", QString::SkipEmptyParts);
			totalLeakByte = byarrElems[1].toLongLong();
			totalLeakCount = byarrElems[4].toLongLong();

			// 根据context 计算uuid
			QByteArray byarrContext = block.context.toUtf8();
			byarrContext += QString("%1").arg(block.leakBlockSize);
			block.uuid = QCryptographicHash::hash(byarrContext, QCryptographicHash::Sha256);
			block.uuid = block.uuid.toHex();
			// 此处做个安全判断, 如果在现有的map中找的到这个
			// uuid, 说明hash256算法冲突了，结果可能是错误的（hash256冲突的概率比较小，暂不考虑）
			// 此处认为是同一个堆栈，将其合并
			iter = pSecondBlockList->find(block.uuid);
			if (iter != pSecondBlockList->end())
			{
				qDebug() << "this hash256 is exist in this context in AllocID " <<
					iter->strAllocID << ":" << block.strAllocID;
				if (iter->leakTotalSize != block.leakBlockSize)
				{
					qDebug() << "this hash256 is wrong in this context in AllocID " <<
						iter->strAllocID << ":" << block.strAllocID;
					result = false;
				}
				
				iter->strAllocID = iter->strAllocID + "+" + block.strAllocID;
				iter->leakNum += block.leakNum;
				iter->leakTotalSize = iter->leakNum * iter->leakBlockSize;
			}
			else
			{
				pSecondBlockList[0][block.uuid] = block;
			}

			// 这个是一次报告的结尾，需要清空block
			block.reset();
			continue;
		}
	}

	// 添加最后一个LeakBlock
	if (!block.context.isEmpty())
	{
		// 根据context 计算uuid
		QByteArray byarrContext = block.context.toUtf8();
		byarrContext += QString("%1").arg(block.leakBlockSize);
		block.uuid = QCryptographicHash::hash(byarrContext, QCryptographicHash::Sha256);
		block.uuid = block.uuid.toHex();
		// 此处做个安全判断, 如果在现有的map中找的到这个
		// uuid, 说明hash256算法冲突了，结果可能是错误的（hash256冲突的概率比较小，暂不考虑）
		// 此处认为是同一个堆栈，将其合并
		iter = pSecondBlockList->find(block.uuid);
		if (iter != pSecondBlockList->end())
		{
			qDebug() << "this hash256 is exist in this context in AllocID " <<
				iter->strAllocID << ":" << block.strAllocID;
			if (iter->leakTotalSize != block.leakBlockSize)
			{
				qDebug() << "this hash256 is wrong in this context in AllocID " <<
					iter->strAllocID << ":" << block.strAllocID;
				result = false;
			}

			iter->strAllocID = iter->strAllocID + "+" + block.strAllocID;
			iter->leakNum += block.leakNum;
			iter->leakTotalSize = iter->leakNum * iter->leakBlockSize;
		}
		else
		{
			pSecondBlockList[0][block.uuid] = block;
		}

		block.reset();
	}

	// 将上一次的结果和这次的结果做一次统计
	if ((nullptr != pFirstBlockList) &&
		(nullptr != pSecondBlockList))
	{
		getLeakResult(*pFirstBlockList, *pSecondBlockList, &tmpLeakBlockResult);
		++(*pnActivite);
	}

	// 将此次结果变为上一次的结果，解析下一次的结果
	if (nullptr != pFirstBlockList)
	{
		delete pFirstBlockList;
		pFirstBlockList = nullptr;
	}

	if (nullptr != pSecondBlockList)
	{
		delete pSecondBlockList;
		pSecondBlockList = nullptr;
	}

	// 获取结果
	foreach(const LeakBlock&leakBlock, tmpLeakBlockResult)
	{
		vecLeakBlockResult.push_back(leakBlock);
	}

	// 进行排序
	std::sort(vecLeakBlockResult.begin(), vecLeakBlockResult.end());

	fileAnalyse.close();

	return result;
}

void AnalyseLeak::onBtnAnalyseClicked(bool)
{
	m_inFile = ui.lineEditResultFile->text();
	QFileInfo fileInfo(m_inFile);
	m_outFile = fileInfo.absolutePath() + QDir::separator() + fileInfo.baseName() + "-compare." + fileInfo.completeSuffix();

	// 如果输入文件和输出文件有一个为空则直接返回
	if (m_inFile.isEmpty() || m_outFile.isEmpty())
	{
		return;
	}

	// 进度条清0
	ui.progressBarAnalsyLeak->setValue(0);

	QVector<LeakBlock> resultLeakBlock;
	int nActivite = 0;
	doAnalyse(m_inFile, &resultLeakBlock, &nActivite);

	QFile outFile(m_outFile);
	if (!outFile.open(QIODevice::WriteOnly))
	{
		qDebug() << "open " << m_outFile << " failed!";
		return;
	}
	QTextStream outputStream(&outFile);

	outputStream << "leaks: " << nActivite << "\r\n";

	// 打印结果
	foreach(const LeakBlock &leakBlock, resultLeakBlock)
	{
		outputStream << "uuid: " << leakBlock.uuid << " allocID: " << leakBlock.strAllocID << " activity: " << leakBlock.activity << "\r\n";
		outputStream << "Total: " << leakBlock.leakTotalSize << " = " <<
			 leakBlock.leakBlockSize << " * " << leakBlock.leakNum << "\r\n";
		outputStream << "context:\r\n";
		outputStream << leakBlock.context;
		outputStream << "\r\n";
	}

	outFile.close();

	// 全部完成后置为100
	ui.progressBarAnalsyLeak->setValue(100);

	// 完成后自动使用Notepad++打开文本
	//QString strNotepadPlusPlus = "notepad++.exe";
	//QStringList listParam;
	//listParam.push_back(m_outFile);
	//QProcess::startDetached(strNotepadPlusPlus, listParam);
}
