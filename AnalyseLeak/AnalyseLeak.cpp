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

	// ��ʼ���ı�������ݺ�Ĭ�ϴ򿪵�·��
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

	// �����ı��������
	ui.lineEditResultFile->setText(m_inFile);

	QDir dir(m_inFile);
	m_prevDirPath = dir.absolutePath();

	// ��¼��һ�εĴ򿪵��ļ�·��
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

	// �����ﶼ��Ϊ��context������
	int i = 0;
	for (QString &str : strList)
	{
		str = str.trimmed();
		++i;

		// ����ÿ�μ��صĿ�ĵ�ַ����һ����Ϊ�˱�֤
		// ��ջ��Ψһ�ԣ���Ҫ�Ե�ַ�������⴦�������
		// ���ַ����ֱ������������ǿ���ĳ�����ŵĵ�ַ��
		// ���ȥ��Ӧ��ĵ�ַ��ȡ��Ե�ַ
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

	// ����ҵ��ˣ����ۼӵ�ǰһ�εĽ����ȥ
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
			// ���й¶�ܵĴ�С�����˵����ܴ�С����µ����ܴ�С
			if (iterResult->deadlineTotalSize < leakBlock.leakTotalSize)
			{
				iterResult->deadlineTotalSize = leakBlock.leakTotalSize;
				++iterResult->activity;
			}
			else if (leakBlock.leakTotalSize <= 0) // ���С�ڵ���0�����Ծ����Ϊ0
			{
				iterResult->activity = 0;
			}
		}
		else // �������û�б仯
		{
			// do nonthing 
		}
	}
	else // ����ǵ�һ�Σ�����뵽�����ȥ
	{
		LeakBlock tmpLeakBlock = leakBlock;
		if (tmpLeakBlock.leakTotalSize > 0)
		{
			++tmpLeakBlock.activity;
		}
		else // �����ǰ��й¶��СС�ڵ���0��������Ծ�ȴ���Ĭ��Ϊ0
		{
			// do nonthing;
		}

		// ���й¶�ܵĴ�С�����˵����ܴ�С����µ����ܴ�С
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
		// ����ڵڶ����ҵ��ˣ��򽫵ڶ��μ�����һ��
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

	// ��R��ʣ��Ĳ�����ӵ�Result����
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
	QRegExp rxBaseDLLAddress("^[ ]{4,4}0x.*");	// ����dll��exe
	QRegExp rxSymbolAddress("^[ ]{6,6}.*");	// �����޵�ַ�ĺ��е�ַ����
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

		// ��������
		if (byarrLine.trimmed().isEmpty())
		{
			continue;
		}
		
		// ���ҷ��ŵ�ַ��ʼ����
		if (-1 != rxSymbolAddress.indexIn(byarrLine))
		{
			isBaseAddress = false;
			doParseSymbol(byarrLine, isBaseAddress, &baseAddr, &block);
			continue;
		}
			
		// ���һ������dllģ���
		if (-1 != rxBaseDLLAddress.indexIn(byarrLine))
		{
			isBaseAddress = true;
			doParseSymbol(byarrLine, isBaseAddress, &baseAddr, &block);
			continue;
		}

		// ����LeakBlock��ʼ����
		if (-1 != rxLeakBlockStartLine.indexIn(byarrLine))
		{
			if (!block.context.isEmpty())
			{
				// ����context ����uuid
				QByteArray byarrContext = block.context.toUtf8();
				byarrContext += QString("%1").arg(block.leakBlockSize);
				block.uuid = QCryptographicHash::hash(byarrContext, QCryptographicHash::Sha256);
				block.uuid = block.uuid.toHex();
				// �˴�������ȫ�ж�, ��������е�map���ҵĵ����
				// uuid, ˵��hash256�㷨��ͻ�ˣ���������Ǵ���ģ�hash256��ͻ�ĸ��ʱȽ�С���ݲ����ǣ�
				// �˴���Ϊ��ͬһ����ջ������ϲ�
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

			// ��ʼ����һ��й¶�����Ϣ
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

		// ����leaks����ͷ����
		if (-1 != rxLeakInfoStartLine.indexIn(byarrLine))
		{
			// ����һ�εĽ������εĽ����һ��ͳ��
			if ((nullptr != pFirstBlockList) && 
				(nullptr != pSecondBlockList))
			{
				getLeakResult(*pFirstBlockList, *pSecondBlockList, &tmpLeakBlockResult);
				++(*pnActivite);
			}

			// ���˴ν����Ϊ��һ�εĽ����������һ�εĽ��
			if (nullptr != pFirstBlockList)
			{
				delete pFirstBlockList;
				pFirstBlockList = nullptr;
			}

			pFirstBlockList = pSecondBlockList;
			pSecondBlockList = new QHash<QByteArray, LeakBlock>();
			continue;
		}

		// �Ƿ��Ѿ���й¶��Ϣ�Ľ�β
		if (-1 != rxLeakInfoEndLine.indexIn(byarrLine))
		{
			QList<QString>byarrElems = byarrLine.split(" ", QString::SkipEmptyParts);
			totalLeakByte = byarrElems[1].toLongLong();
			totalLeakCount = byarrElems[4].toLongLong();

			// ����context ����uuid
			QByteArray byarrContext = block.context.toUtf8();
			byarrContext += QString("%1").arg(block.leakBlockSize);
			block.uuid = QCryptographicHash::hash(byarrContext, QCryptographicHash::Sha256);
			block.uuid = block.uuid.toHex();
			// �˴�������ȫ�ж�, ��������е�map���ҵĵ����
			// uuid, ˵��hash256�㷨��ͻ�ˣ���������Ǵ���ģ�hash256��ͻ�ĸ��ʱȽ�С���ݲ����ǣ�
			// �˴���Ϊ��ͬһ����ջ������ϲ�
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

			// �����һ�α���Ľ�β����Ҫ���block
			block.reset();
			continue;
		}
	}

	// ������һ��LeakBlock
	if (!block.context.isEmpty())
	{
		// ����context ����uuid
		QByteArray byarrContext = block.context.toUtf8();
		byarrContext += QString("%1").arg(block.leakBlockSize);
		block.uuid = QCryptographicHash::hash(byarrContext, QCryptographicHash::Sha256);
		block.uuid = block.uuid.toHex();
		// �˴�������ȫ�ж�, ��������е�map���ҵĵ����
		// uuid, ˵��hash256�㷨��ͻ�ˣ���������Ǵ���ģ�hash256��ͻ�ĸ��ʱȽ�С���ݲ����ǣ�
		// �˴���Ϊ��ͬһ����ջ������ϲ�
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

	// ����һ�εĽ������εĽ����һ��ͳ��
	if ((nullptr != pFirstBlockList) &&
		(nullptr != pSecondBlockList))
	{
		getLeakResult(*pFirstBlockList, *pSecondBlockList, &tmpLeakBlockResult);
		++(*pnActivite);
	}

	// ���˴ν����Ϊ��һ�εĽ����������һ�εĽ��
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

	// ��ȡ���
	foreach(const LeakBlock&leakBlock, tmpLeakBlockResult)
	{
		vecLeakBlockResult.push_back(leakBlock);
	}

	// ��������
	std::sort(vecLeakBlockResult.begin(), vecLeakBlockResult.end());

	fileAnalyse.close();

	return result;
}

void AnalyseLeak::onBtnAnalyseClicked(bool)
{
	m_inFile = ui.lineEditResultFile->text();
	QFileInfo fileInfo(m_inFile);
	m_outFile = fileInfo.absolutePath() + QDir::separator() + fileInfo.baseName() + "-compare." + fileInfo.completeSuffix();

	// ��������ļ�������ļ���һ��Ϊ����ֱ�ӷ���
	if (m_inFile.isEmpty() || m_outFile.isEmpty())
	{
		return;
	}

	// ��������0
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

	// ��ӡ���
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

	// ȫ����ɺ���Ϊ100
	ui.progressBarAnalsyLeak->setValue(100);

	// ��ɺ��Զ�ʹ��Notepad++���ı�
	//QString strNotepadPlusPlus = "notepad++.exe";
	//QStringList listParam;
	//listParam.push_back(m_outFile);
	//QProcess::startDetached(strNotepadPlusPlus, listParam);
}
