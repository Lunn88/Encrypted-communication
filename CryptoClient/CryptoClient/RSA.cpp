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

bool miller_rabin_test(long int n, int k) {
    if (n % 2 == 1) {
        long int d = n - 1;
        int s = 0;
        while (d % 2 == 0) {
            d /= 2;
            s++;
        }
        for (int i = 0; i < k; i++) {
            long int a = rand() % (n - 1) + 1;
            long int x = quick_pow(a, d, n);
            if (x == 1 || x == n - 1)
                continue;
            for (int j = 0; j < s - 1; j++) {
                x = quick_mul(x, x, n);
                if (x == n - 1)
                    break;
            }
            if (x != n - 1)
                return false;
        }
        return true;
    }
    else
        return false;
}

pair<long int, long int> gen_prime() {
    srand(time(0));
    unsigned long seed = time(0);
    long int p = rand(), q = rand();
    while (miller_rabin_test(p, 10) == false) {
        p = rand();
    }
    while (miller_rabin_test(q, 10) == false) {
        q = rand();
    }
    return { p, q };
}

pair<long int, long int> get_pb_keys(long int p, long int q)
{
    long int e = 65537;
    long int n = p * q;
    return { e, n };
}

long int get_pv_keys(long int p, long int q)
{
    long int e = 65537;
    long int n = p * q;
    long int euler_n = (p - 1) * (q - 1), d;
    tie(d, ignore) = extended_euclidean(e, euler_n);
    d = (d % euler_n + euler_n) % euler_n;
    return d;
}

pair<long int, long int> extended_euclidean(long int a, long int b) {
    long int x, y;
    if (b == 0) {
        return { 1, 0 };
    }

    tie(x, y) = extended_euclidean(b, a % b);
    return { y, x - y * (a / b) };
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