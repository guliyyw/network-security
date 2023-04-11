#include "iostream"

#include "QtWa.h"
#include "QRegExpValidator"
#include "string"
#include "QButtonGroup"
#include "AES.h"
#include "des.h"
#include "vector"

using namespace std;

int exgcd(int a, int b, int& x, int& y);

QtWa::QtWa(QWidget *parent)
    : QMainWindow(parent)
{
    ui.setupUi(this);
    //设置正则表达式，可接受字母，数字类型的数据，但不超过11个
    ui.Plaintext->setValidator(new QRegExpValidator(QRegExp("[A-Za-z]{1,20}")));

    ui.Secretkey_b->setValidator(new QRegExpValidator(QRegExp("^([1-9]|[1-2][0-5])$")));

    ui.Secretkey_a->setValidator(new QRegExpValidator(QRegExp("^3|5|7|9|11|15|17|19|21|23|25&")));

    ui.key->setValidator(new QRegExpValidator(QRegExp("^[A-Za-z]{8,32}&")));
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
    QString res = "";
    string text = ui.Plaintext->text().toStdString();

    //移位
    if (ui.gression->isChecked()) {
        int num = ui.Secretkey_b->text().toInt();
        for (char str : text) {
            int x = str;
            if (x >= 97 && x <= 122) {
                res += 'a' + (x - 97 + num) % 26;
            }
            else if (x >= 65 && x <= 90) {
                res += 'A' + (x - 65 + num) % 26;
            }
        }
    }

    //仿射
    else if(ui.affine->isChecked()){
        int num_a = ui.Secretkey_a->text().toInt();
        int num_b = ui.Secretkey_b->text().toInt();
        for (char str : text) {
            int x = str;
            if (x >= 97 && x <= 122) {
                res += 'a' + (((x - 97) * num_a) + num_b) % 26;
            }
            else if (x >= 65 && x <= 90) {
                res += 'A' + (((x - 65) * num_a) + num_b) % 26;
            }
        }
    }

    //des
    else if (ui.des->isChecked()) {
        string c = "0";
        while (text.length() % 8 != 0)	//明文不足8位自动补0
            text += c;
        res = QString::fromStdString(ECB(text, ui.key->text().toStdString(), en));
    }

    //aes
    else if (ui.aes->isChecked()) {
        string ch = "0";
        while (text.length() % 16 != 0)	//明文不足16位自动补0
            text += ch;
        unsigned char* plain = new unsigned char [text.length() + 1];
        for (int i = 0; i < text.length();i++) {
            plain[i] = text[i];
        }
        if (ui.key->text().size() != 16) {
            ui.key->setText("The aes key must be 16 bits");
            return;
        }
        unsigned char key[16];
        string ui_key = ui.key->text().toStdString();
        for (int i = 0; i < 16; i++) {
            key[i] = ui_key[i];
        }

        AES aes(AESKeyLength::AES_128);
        unsigned char* c = aes.EncryptECB(plain, text.length(), key);
        res = byteArrayToHexString(c,text.length());
    }
    ui.Ciphertext->setText(res);
}

//解密
void QtWa::deciphering() {
    QString res = "";
    string text = ui.Plaintext->text().toStdString();

    //移位
    if (ui.gression->isChecked()) {
        int num = ui.Secretkey_b->text().toInt();
        for (char str : text) {
            int x = str;
            if (x >= 97 && x <= 122) {
                res += 'a' + floor((x - 97 - num + 26) % 26);
            }
            else if (x >= 65 && x <= 90) {
                res += 'A' + floor((x - 65 - num + 26) % 26);
            }
        }
    }

    //仿射
    else if (ui.affine->isChecked()) {
        int num_a = ui.Secretkey_a->text().toInt();
        int num_b = ui.Secretkey_b->text().toInt();
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
    }

    //des
    else if (ui.des->isChecked()) {
        res = QString::fromStdString(ECB(ui.cipher->text().toStdString(), ui.key->text().toStdString(), de));
    }

    //aes
    else if (ui.aes->isChecked()) {
        vector<unsigned char> plain = hexStringToByteArray(ui.cipher->text());
        string ui_key = ui.key->text().toStdString();

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
    }
    ui.Ciphertext->setText(res);
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
