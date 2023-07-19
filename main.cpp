#include <iostream>
#include <string>
#include <vector>
#include "AES.h"
#include <chrono>

using namespace std;

typedef std::chrono::high_resolution_clock Clock;



int main()
{
    string str="706173737ED6f72675123473B96d706B654b6579436173F3387453617365"; //明文
    string key="73696d706c654b657943617365313233"; // 密钥
    string IV= "f72645465773696d706c654b657323D8";//初始IV值
    string str2="6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710";
    string key2="2B7E151628AED2A6ABF7158809CF4F3C";
    string IV2="000102030405060708090A0B0C0D0E0F";
    /*State state(str);
    state.Print();
    State cipher=AES_128_OnState_Encrypt(str,key);
    State plain=AES_128_OnState_Decrypt(cipher,key);
    cipher.Print();
    plain.Print();*/

    string plaintext=Random1MString();

    auto time0 = Clock::now();
    string cipher=AES_128_Encrypt(str,key2,IV2);
    auto time1 = Clock::now();
    cout<<std::chrono::duration_cast<std::chrono::nanoseconds>(time1 - time0).count()<<endl;
    
    cout<<cipher<<endl;
    time0 = Clock::now();
    string decrytion=AES_128_Decrypt(cipher,key2,IV2);
    time1 = Clock::now();
    cout<<std::chrono::duration_cast<std::chrono::nanoseconds>(time1 - time0).count()<<endl;

    
    return 0;
}