#include"RSA.h"

long int quick_mul(long int a, long int b, long int mod) {
    long int ans = 0;
    for (a %= mod; b > 0; b >>= 1) {
        if (b % 2 == 1) ans = (ans + a) % mod;
        a = (a + a) % mod;
    }
    return ans;
}

long int quick_pow(long int a, long int b, long int mod) {
    long int ans = 1;
    for (a %= mod; b > 0; b >>= 1) {
        if (b % 2 == 1) ans = quick_mul(ans, a, mod);
        a = quick_mul(a, a, mod);
    }
    return ans;
}

long int RSA_Encrypt(long int msg, long int key_e, long int key_n) {
    long int tmp;
    tmp = quick_pow(msg, key_e, key_n);
    return tmp;
}

long int RSA_Decrypt(long int msg, long int key_d, long int key_n) {
    long int tmp;
    tmp = quick_pow(msg, key_d, key_n);
    return tmp;
}