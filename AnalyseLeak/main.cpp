#include "AnalyseLeak.h"
#include <QtWidgets/QApplication>

int main(int argc, char *argv[])
{
	QApplication a(argc, argv);
	AnalyseLeak w;
	w.show();
	return a.exec();
}
