#ifndef RANDOMSTRING_H
#define RANDOMSTRING_H

#include <stdlib.h> 
#include <time.h> 
#include <iostream>

using namespace std;

char toChar(char ch)
{
    if(ch<=9) return ch+'0';
    else return ch+'A'-10;
}

string Random1MString()
{
    srand(time(nullptr));
    string str="";
    int N=1<<15;
    while(N--)
    {
        uint randnum=rand();
        for(int i=0;i<8;i++)
        {
            str+=toChar(randnum&0xF);
            randnum>>=4;
        }
    }
    return str;
}

#endif