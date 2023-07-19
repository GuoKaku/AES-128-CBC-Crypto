#ifndef AES_H
#define AES_H

#include <iostream>
#include <string>
#include <vector>
#include "RandomString.h"

using namespace std;

typedef unsigned char uchar;

uchar TwoTime(uchar a)
{
    if((a&0x80)==0)
    {
        return a<<1;
    }
    else
    {
        return (a<<1)^0x1B;
    }
    
}

uchar multiply(uchar a,uchar b)
{
    if(b==0) return 0;
    uchar result=0;
    uchar now_pow=a;
    while(b!=0)
    {
        if((b&1)!=0)
        {
            result^=now_pow;
        }
        b>>=1;
        now_pow=TwoTime(now_pow);
    }
    return result;
}

char toHex(char ch)
{
    if(ch<='9') return ch-'0';
    else if(ch<='Z') return ch-'A'+10;
    else return ch-'a'+10;
}


uchar string_to_hex(char high,char low)
{
    return (toHex(high)<<4)+toHex(low);
}

const uchar Sbox[256]={0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

const uchar inverse_Sbox[256]={0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
};




class State
{
    uchar segments[4][4];
public: 
    State(){}

    State(string str)
    {
        for(int i=0;i<4;i++)
           for(int j=0;j<4;j++)
           {
              int pos=4*i+j;
              char low=str[2*pos+1];
              char high=str[2*pos];
              segments[j][i]=string_to_hex(high,low);
             // printf("%X\n",segments[j][i]);
           }
    }

    void SubByte() //加密字节替换
    {
        for(int i=0;i<4;i++)
        {
           for(int j=0;j<4;j++)
           {
              segments[i][j]=Sbox[segments[i][j]];
           }
        }
    }

    void InvSubByte() //解密字节替换
    {
        for(int i=0;i<4;i++)
        {
           for(int j=0;j<4;j++)
           {
              segments[i][j]=inverse_Sbox[segments[i][j]];
           }
        }
    }

    void ShiftRow() //加密行移位
    {
        uchar temp=segments[1][0];
        for(int j=0;j<3;j++) segments[1][j]=segments[1][j+1];
        segments[1][3]=temp;

        temp=segments[2][0];segments[2][0]=segments[2][2];segments[2][2]=temp;
        temp=segments[2][1];segments[2][1]=segments[2][3];segments[2][3]=temp;

        temp=segments[3][3];
        for(int j=3;j>0;j--) segments[3][j]=segments[3][j-1];
        segments[3][0]=temp;
    }

    void InvShiftRow()  //解密行移位
    {
        uchar temp=segments[1][3];
        for(int j=3;j>0;j--) segments[1][j]=segments[1][j-1];
        segments[1][0]=temp;

        temp=segments[2][0];segments[2][0]=segments[2][2];segments[2][2]=temp;
        temp=segments[2][1];segments[2][1]=segments[2][3];segments[2][3]=temp;

        temp=segments[3][0];
        for(int j=0;j<3;j++) segments[3][j]=segments[3][j+1];
        segments[3][3]=temp;
    }

    void MixColumn()  //加密列混合
    {
        for(int i=0;i<4;i++)
        {
            uchar new_col[4];
            new_col[0]=multiply(segments[0][i],0x02)^multiply(segments[1][i],0x03)^segments[2][i]^segments[3][i];
            new_col[1]=segments[0][i]^multiply(segments[1][i],0x02)^multiply(segments[2][i],0x03)^segments[3][i];
            new_col[2]=segments[0][i]^segments[1][i]^multiply(segments[2][i],0x02)^multiply(segments[3][i],0x03);
            new_col[3]=multiply(segments[0][i],0x03)^segments[1][i]^segments[2][i]^multiply(segments[3][i],0x02);
            for(int j=0;j<4;j++) segments[j][i]=new_col[j];
        }
    }

    void InvMixColumn()  //解密列混合
    {
        for(int i=0;i<4;i++)
        {
            uchar new_col[4];
            new_col[0]=multiply(segments[0][i],0x0E)^multiply(segments[1][i],0x0B)^multiply(segments[2][i],0x0D)^multiply(segments[3][i],0x09);
            new_col[1]=multiply(segments[0][i],0x09)^multiply(segments[1][i],0x0E)^multiply(segments[2][i],0x0B)^multiply(segments[3][i],0x0D);
            new_col[2]=multiply(segments[0][i],0x0D)^multiply(segments[1][i],0x09)^multiply(segments[2][i],0x0E)^multiply(segments[3][i],0x0B);
            new_col[3]=multiply(segments[0][i],0x0B)^multiply(segments[1][i],0x0D)^multiply(segments[2][i],0x09)^multiply(segments[3][i],0x0E);
            for(int j=0;j<4;j++) segments[j][i]=new_col[j];
        }
    }

    void AddRoundKey(vector<uint>& keys,int round)
    {
        for(int i=0;i<4;i++)
        {
            uint nowkey=keys[4*round+i];
            for(int j=0;j<4;j++)
            {
                segments[j][i]^=(nowkey>>(4*(6-2*j))&0xFF);
            }
        }
    }

    void operator^=(const State& other)
    {
        for(int i=0;i<4;i++)
        for(int j=0;j<4;j++)
            segments[i][j]^=other.segments[i][j];
    }

    
    State operator^(const State& other)
    {
        State temp=*this;
        for(int i=0;i<4;i++)
        for(int j=0;j<4;j++)
            temp.segments[i][j]^=other.segments[i][j];
        return temp;
    }

    string toString()
    {
        string result="";
        for(int i=0;i<4;i++)
        {
            for(int j=0;j<4;j++)
            {
                uchar temp=segments[j][i];
                result+=toChar(temp>>4);
                result+=toChar(temp&0xF);
            }
        }
        return result;
    }


    void Print()
    {
        for(int i=0;i<4;i++)
        {
           for(int j=0;j<4;j++)
           {
              printf("%X",segments[j][i]);
           }
           
        }
        printf("\n");
    }
};


static const int Rcon[10] = { 0x01000000, 0x02000000,
    0x04000000, 0x08000000,
    0x10000000, 0x20000000,
    0x40000000, 0x80000000,
    0x1b000000, 0x36000000 };

vector<uint> GenerateRoundKeys(string str)
{
    vector<uint> keys;
    //初始化密钥
    for(int i=0;i<4;i++)
    {
      uint result=0;
      for(int j=0;j<8;j++)
      {
         result^=toHex(str[8*i+j])<<(4*(7-j));
      }
      keys.push_back(result);
    }
    //密钥拓展
    for(int i=4;i<44;i++)
    {
        uint temp=keys[i-1];
        if(i%4==0)
        {
            temp=(temp<<8)^(temp>>24);
            temp=(((uint)Sbox[(temp>>24)&0xFF])<<24)^(((uint)Sbox[(temp>>16)&0xFF])<<16)^(((uint)Sbox[(temp>>8)&0xFF])<<8)^(((uint)Sbox[temp&0xFF]));
            temp^=Rcon[i/4-1];
        }
        keys.push_back(keys[i-4]^temp);
    }
    return keys;
}


State AES_128_OnState_Encrypt(State state,vector<uint> keys)  //state是明文的状态阵
{
    state.AddRoundKey(keys,0);
    for(int round=1;round<=9;round++)
    {
        state.SubByte();
        state.ShiftRow();
        state.MixColumn();
        state.AddRoundKey(keys,round);
    }
    state.SubByte();
    state.ShiftRow();
    state.AddRoundKey(keys,10);
    return state;
}

State AES_128_OnState_Encrypt(State state,string key)  //state是明文的状态阵
{
    vector<uint> keys=GenerateRoundKeys(key);
    return AES_128_OnState_Encrypt(state,keys);
}

State AES_128_OnState_Decrypt(State cipher,vector<uint> keys)
{
    cipher.AddRoundKey(keys,10);
    for(int round=9;round>=1;round--)
    {
        cipher.InvShiftRow();
        cipher.InvSubByte();
        cipher.AddRoundKey(keys,round);
        cipher.InvMixColumn();
    }

    cipher.InvShiftRow();
    cipher.InvSubByte();
    cipher.AddRoundKey(keys,0);

    return cipher;
}

State AES_128_OnState_Decrypt(State cipher,string key)
{
    vector<uint> keys=GenerateRoundKeys(key);
    return AES_128_OnState_Decrypt(cipher,keys);
}

string BytePadding(string plaintext)
{
    int residue=32-plaintext.size()%32;
    plaintext.push_back('8');
    residue--;
    plaintext.append(residue,'0');
    return plaintext;
}

string AES_128_Encrypt(string plaintext,string key,string IV)
{
    string padded_text=BytePadding(plaintext);
    int group_num=padded_text.size()>>5;
    string cipher_text="";
    vector<uint> keys=GenerateRoundKeys(key);
    State to_xor=State(IV);
    for(int i=0;i<group_num;i++)
    {
        State nowgroup_state(padded_text.substr(i<<5,32));
        nowgroup_state^=to_xor;
        to_xor=AES_128_OnState_Encrypt(nowgroup_state,keys);
        cipher_text+=to_xor.toString();
    }
    return cipher_text;
}

void DePadding(string& padded)
{
    int pos=padded.size()-1;
    while(padded[pos]!='8') pos--;
    padded.erase(padded.begin()+pos,padded.end());
}

string AES_128_Decrypt(string ciphertext,string key,string IV)
{
    int group_num=ciphertext.size()>>5;
    string padded_text="";
    vector<uint> keys=GenerateRoundKeys(key);
    State to_xor=State(IV);
    for(int i=0;i<group_num;i++)
    {
        State nowgroup_state(ciphertext.substr(i<<5,32));
        State decrypt_state=AES_128_OnState_Decrypt(nowgroup_state,keys);
        padded_text+=(decrypt_state^to_xor).toString();
        to_xor=nowgroup_state;
    }
    DePadding(padded_text);
    return padded_text;
}

#endif
