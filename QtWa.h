#pragma once

#include <QtWidgets/QMainWindow>
#include "ui_QtWa.h"

class QtWa : public QMainWindow
{
    Q_OBJECT

public:
    QtWa(QWidget *parent = nullptr);
    ~QtWa();

private:
    Ui::QtWaClass ui;

private slots://相应功能槽函数
    void encryption();//加密
    void deciphering();//解密
};
