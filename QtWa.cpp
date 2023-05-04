#include "iostream"

#include "QtWa.h"
#include "QRegExpValidator"
#include "string"
#include "QButtonGroup"
#include "AES.h"
#include "des.h"
#include "vector"
#include "RSA.h"
#include "md5.h"
using namespace std;

int exgcd(int a, int b, int& x, int& y);

QtWa::QtWa(QWidget *parent)
    : QMainWindow(parent)
{
    ui.setupUi(this);
    //设置正则表达式，可接受字母，数字类型的数据，但不超过11个
    //ui.Plaintext->setValidator(new QRegExpValidator(QRegExp("[A-Za-z]{1,20}")));

    //ui.Secretkey_b->setValidator(new QRegExpValidator(QRegExp("^([1-9]|[1-2][0-5])$")));

    //ui.Secretkey_a->setValidator(new QRegExpValidator(QRegExp("^3|5|7|9|11|15|17|19|21|23|25&")));

    //ui.key->setValidator(new QRegExpValidator(QRegExp("^[A-Za-z]{8,32}&")));
}

//结果 unsigned char 转QString 16进制
QString byteArrayToHexString(unsigned char* str, int lengthOfString)
{
    QString result = "";
    QString s;
    for (int i = 0; i < lengthOfString; ++i)
    {
        s = QString("%1").arg(str[i], 0, 16);
        if (s.length() == 1) {
            result.append("0");
        }
        result.append(s.toUpper());
    }

    return result;
}

//16进制string转unsigned char
vector<unsigned char> hexStringToByteArray(const QString& strMac)
{
    vector<unsigned char> vecMac;
    unsigned char* p = vecMac.data();
    for (int i = 0; i < strMac.size(); i += 2)
    {
        QString num = strMac.mid(i, 2);
        bool ok = false;
        vecMac.push_back(num.toUInt(&ok, 16));
        if (!ok)
        {
            return vector<unsigned char>();
        }
    }
    return vecMac;
}

//16进制unsigned char 转字符
unsigned char HexToAsc(unsigned char aChar) {

    if ((aChar >= 0x30) && (aChar <= 0x39)) {
        aChar = aChar - 0x30 + 48;
    }
    else if ((aChar >= 0x41) && (aChar <= 0x5A)) {//大写字母
        aChar = aChar - 0x41 + 65;
    }
    else if ((aChar >= 0x61) && (aChar <= 0x7A)) {//小写字母
        aChar = aChar - 0x61 + 97;
    }
    else aChar = 0xff;
    return aChar;
}


//加密 
void QtWa::encryption()
{

    //移位
    if (ui.tabWidget->currentIndex() == 0) {
        QString res = "";
        string text = ui.Plaintext_1->text().toStdString();
        int num = ui.Secretkey_1->text().toInt();
        for (char str : text) {
            int x = str;
            if (x >= 97 && x <= 122) {
                res += 'a' + (x - 97 + num) % 26;
            }
            else if (x >= 65 && x <= 90) {
                res += 'A' + (x - 65 + num) % 26;
            }
        }
        ui.ciphertext_1->setText(res);
    }

    //仿射
    else if(ui.tabWidget->currentIndex() == 1){
        QString res = "";
        string text = ui.Plaintext_2->text().toStdString();
        int num_a = ui.Secretkey_2_1->text().toInt();
        int num_b = ui.Secretkey_2_2->text().toInt();
        for (char str : text) {
            int x = str;
            if (x >= 97 && x <= 122) {
                res += 'a' + (((x - 97) * num_a) + num_b) % 26;
            }
            else if (x >= 65 && x <= 90) {
                res += 'A' + (((x - 65) * num_a) + num_b) % 26;
            }
        }
        ui.ciphertext_2->setText(res);
    }

    //des
    else if (ui.tabWidget->currentIndex() == 2) {
        QString res = "";
        string text = ui.Plaintext_3->text().toStdString();
        string c = "0";
        while (text.length() % 8 != 0)	//明文不足8位自动补0
            text += c;
        res = QString::fromStdString(ECB(text, ui.Secretkey_3->text().toStdString(),en));
        ui.ciphertext_3->setText(res);
    }

    //aes
    else if (ui.tabWidget->currentIndex() == 3) {
        QString res = "";
        string text = ui.Plaintext_4->text().toStdString();
        string ch = "0";
        while (text.length() % 16 != 0)	//明文不足16位自动补0
            text += ch;
        unsigned char* plain = new unsigned char [text.length() + 1];
        for (int i = 0; i < text.length();i++) {
            plain[i] = text[i];
        }
        if (ui.Secretkey_4->text().size() != 16) {
            ui.Secretkey_4->setText("The aes key must be 16 bits");
            return;
        }
        unsigned char key[16];
        string ui_key = ui.Secretkey_4->text().toStdString();
        for (int i = 0; i < 16; i++) {
            key[i] = ui_key[i];
        }

        AES aes(AESKeyLength::AES_128);
        unsigned char* c = aes.EncryptECB(plain, text.length(), key);
        res = byteArrayToHexString(c,text.length());
        ui.ciphertext_4->setText(res);
    }

    //rsa
    else if (ui.tabWidget->currentIndex() == 4) {
        vector<int> num = key(ui.Secretkey_p->text().toInt(), ui.Secretkey_q->text().toInt());
        ui.ciphertext_5->setText(QString::fromStdString(rsaen(num[0], num[2], ui.Plaintext_5->text().toStdString())));
        ui.Secretkey_e->setText(QString::fromStdString(to_string(num[0])));
        ui.Secretkey_n_1->setText(QString::fromStdString(to_string(num[2])));
        ui.Secretkey_n_2->setText(QString::fromStdString(to_string(num[2])));
        ui.Secretkey_d->setText(QString::fromStdString(to_string(num[1])));
    }

    //MD5
    else if (ui.tabWidget->currentIndex() == 5) {
        //QString res = QString::fromStdString(md5(ui.Plaintext_6->text().toStdString()));
        ui.ciphertext_6->setText(QString::fromStdString(md5(ui.Plaintext_6->text().toStdString())));
    }
}



//解密
void QtWa::deciphering() {

    //移位
    if (ui.tabWidget->currentIndex() == 0) {
        QString res = "";
        string text = ui.Plaintext_1->text().toStdString();
        int num = ui.Secretkey_1->text().toInt();
        for (char str : text) {
            int x = str;
            if (x >= 97 && x <= 122) {
                res += 'a' + floor((x - 97 - num + 26) % 26);
            }
            else if (x >= 65 && x <= 90) {
                res += 'A' + floor((x - 65 - num + 26) % 26);
            }
        }
        ui.ciphertext_1->setText(res);
    }

    //仿射
    else if (ui.tabWidget->currentIndex() == 1) {
        QString res = "";
        string text = ui.Plaintext_2->text().toStdString();
        int num_a = ui.Secretkey_2_1->text().toInt();
        int num_b = ui.Secretkey_2_2->text().toInt();
        int x, y;
        int r = exgcd(num_a, 26, x, y);
        int ans = (x % 26 + 26) % 26;
        for (char str : text) {
            int x = str;
            if (x >= 97 && x <= 122) {
                res += 'a' + (((x - 97) - num_b + 26) * ans) % 26;
            }
            else if (x >= 65 && x <= 90) {
                res += 'A' + (((x - 65) - num_b + 26) * ans) % 26;
            }
        }
        ui.ciphertext_2->setText(res);
    }

    //des
    else if (ui.tabWidget->currentIndex() == 2) {
        QString res = "";
        res = QString::fromStdString(ECB(ui.Plaintext_3->text().toStdString(), ui.Secretkey_3->text().toStdString(), de));
        ui.ciphertext_3->setText(res);
    }

    //aes
    else if (ui.tabWidget->currentIndex() == 3) {
        QString res = "";
        vector<unsigned char> plain = hexStringToByteArray(ui.Plaintext_4->text());
        string ui_key = ui.Secretkey_4->text().toStdString();

        vector<unsigned char> key;
        for (int i = 0; i < 16; i++) {
            key.push_back(ui_key[i]);
        }
        AES aes(AESKeyLength::AES_128);
        vector<unsigned char> c = aes.DecryptECB(plain,key);
        for (int i = 0; i < plain.size(); i++) {
            unsigned char ch = HexToAsc(c[i]);
            if (ch != '0') {
                res += ch;
            }
        }
        ui.ciphertext_4->setText(res);
    }

    //rsa
    else if (ui.tabWidget->currentIndex() == 4) {
        ui.ciphertext_5->setText(QString::fromStdString(rsade(ui.Secretkey_d->text().toInt(), ui.Secretkey_n_2->text().toInt(), ui.ciphertext_5->text().toStdString())));
    }

    else if (ui.tabWidget->currentIndex() == 5) {

    }
    
}

int exgcd(int a, int b, int& x, int& y) {
    if (b == 0) {
        x = 1;
        y = 0;
        return a;
    }
    int r = exgcd(b, a % b, y, x);
    y -= a / b * x;
    return r;
}


QtWa::~QtWa()
{}
