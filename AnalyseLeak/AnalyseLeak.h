#pragma once

#include <QtWidgets/QMainWindow>
#include "ui_AnalyseLeak.h"
#include <QSettings>
#include <QVector>


struct LeakBlock
{
	LeakBlock() :leakTotalSize(0),
		leakNum(0),
		leakBlockSize(0),
		activity(0)
	{
	}
	QByteArray uuid;
	QString strAllocID;
	QString context;
	qint64 leakTotalSize;
	qint64 leakNum;
	qint64 leakBlockSize;
	qint64 deadlineTotalSize;
	int	activity;

	void reset()
	{
		uuid.clear();
		strAllocID.clear();
		context.clear();
		leakTotalSize = 0;
		leakNum = 0;
		leakBlockSize = 0;
		activity = 0;
		deadlineTotalSize = 0;
	}
};


class AnalyseLeak : public QMainWindow
{
	Q_OBJECT

public:
	AnalyseLeak(QWidget *parent = Q_NULLPTR);

public:
	bool doAnalyse(const QString &filePath, QVector<LeakBlock> *pvecLeakBlockResult, int *pnActivite);

public slots:
	void onBtnAnalyseClicked(bool);
	void onBtnLoadResultFileClicked(bool);

private:
	Ui::AnalyseLeakClass ui;
	QString m_prevDirPath;
	QString m_inFile;
	QString m_outFile;
	QString m_appSettingsFilePath;
};
