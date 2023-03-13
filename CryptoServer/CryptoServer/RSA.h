#include<iostream>
#include<time.h>
#include<tuple>
using namespace std;

#define KEY_LEN 10

long int quick_mul(long int a, long int b, long int mod);
long int quick_pow(long int a, long int b, long int mod);


long int RSA_Encrypt(long int msg, long int key_e, long int key_n);
long int RSA_Decrypt(long int msg, long int key_d, long int key_n);