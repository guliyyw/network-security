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

private slots://��Ӧ���ܲۺ���
    void encryption();//����
    void deciphering();//����
};
