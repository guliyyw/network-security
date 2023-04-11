#include "QtWa.h"
#include <QtWidgets/QApplication>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    QtWa w;
    w.show();
    return a.exec();
}

