#include "QtWa.h"
#include <QtWidgets/QApplication>

#include "QRegExpValidator"
#include "string"
#include "QButtonGroup"
#include "AES.h"
#include "des.h"
#include "vector"
#include "iostream"
int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    QtWa w;
    w.show();
    return a.exec();
}

