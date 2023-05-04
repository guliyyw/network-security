#include<iostream>
#include<cstdlib>
#include<algorithm>
#include<vector>
#include<string>
#include<math.h>
#include<stdlib.h>
#include<sys/timeb.h>
using namespace std;


bool oddJudge(int p) {
    // 素性检验;
    bool res = true;
    if (p < 10000) return false;
    for (int i = 2; i <= sqrt(p); i++) {
        if (p % i == 0) {
            res = false;
            break;
        }
    }
    return res;
}
vector<int> creatOddNum() {
    // 产生质数p,q;
    vector<int> pq(2);
    pq[0] = rand();
    pq[1] = rand();

    while (!(oddJudge(pq[0]) && oddJudge(pq[1]))) {
        pq[0] = rand();
        pq[1] = rand();
    }
    return pq;
}
int gcd(int a, int b, int& x, int& y) {
    // 利用欧几里得算法求最大公约数;
    if (a < b) swap(a, b);
    if (b == 0) {
        x = 1;
        y = 0;
        return a;
    }
    int ans = gcd(b, a % b, x, y);
    int temp = x;
    x = y;
    y = temp - a / b * y;
    return ans;
}

long long quickPow(long long m, int e, int n) {
    // 快速幂算法(m*m)%n=(m%n*m%n)%n;
    long long sum = 1;
    m = m % n;
    while (e > 0) {
        if (e % 2 == 1) sum = (sum * m) % n;
        e = e / 2;
        m = (m * m) % n; // 合并m,减小m的规模;
    }
    if (sum < 0) sum = sum + n;
    return sum;
}

int init() {
    srand((unsigned int)time(0));
    vector<int> pq(2);
    pq = creatOddNum();
    int p = pq[0], q = pq[1];
    return p, q;
}

vector<int> key(int p, int q) {
    int n = p * q;
    int phi_n = (p - 1) * (q - 1); // n的欧拉函数值;
    // 获得公钥e;
    int e = rand() % phi_n;
    int x, y;
    while (gcd(phi_n, e, x, y) != 1) e = rand() % phi_n;
    cout << " 公钥e= " << e << " 公钥n= " << n << endl;
    int d = y % phi_n;
    if (d < 0) d = d + phi_n;
    cout << " 私钥d= " << d << " 私钥n= " << n << endl << endl;
    vector<int> num = { e,d,n };
    return num;
}
//加密
string rsaen(int e, int n, string str) {
    int s_len = str.size();
    vector<int> m(s_len);
    vector<long long int> encode_m(s_len);
    string res = "";
    for (int i = 0; i < s_len; i++) {
        m[i] = str[i];
        encode_m[i] = quickPow(m[i], e, n);
        // encode_m = m^e % n;

        res += to_string(encode_m[i]);
        res += " ";
    }
    return res;
}
//解密
string rsade(int d, int n, string str) {
    int s_len = 0;
    vector<string> strs;
    int j = 0;
    for (int i = 0; i < str.size(); i++) {
        if (str[i] == ' ') {
            s_len++;
            strs.push_back(str.substr(j, i));
            j = i + 1;
        }
    }

    string res = "";
    for (int i = 0; i < s_len; i++) {
        str = strs[i];
        long long outcode_m = quickPow(atoi(str.c_str()), d, n);
        //cout << char(outcode_m);
        res += char(outcode_m);
    }

    return res;
}