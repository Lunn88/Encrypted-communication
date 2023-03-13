#include<iostream>
#include<time.h>
#include<tuple>
using namespace std;

#define KEY_LEN 10

long int quick_mul(long int a, long int b, long int mod);
long int quick_pow(long int a, long int b, long int mod);
bool miller_rabin_test(long int n, int k);

pair<long int, long int> gen_prime();
pair<long int, long int> get_pb_keys(long int p, long int q);
long int get_pv_keys(long int p, long int q);


pair<long int, long int> extended_euclidean(long int a, long int b);

long int RSA_Encrypt(long int msg, long int key_e, long int key_n);
long int RSA_Decrypt(long int msg, long int key_d, long int key_n);