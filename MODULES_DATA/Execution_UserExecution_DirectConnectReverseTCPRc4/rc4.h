#pragma once
#pragma once
#define N 256   // 2^8

static void swap(unsigned char* a, unsigned char* b) {
    int tmp = *a;
    *a = *b;
    *b = tmp;
}

static int KSA(char* key, unsigned char* S) {
    int len = strlen(key);
    unsigned int j = 0;

    for (int i = 0; i < N; i++) {
        S[i] = i;
    }

    for (int i = 0; i < N; i++) {
        j = (j + S[i] + key[i % len]) % N;
        swap(&S[i], &S[j]);
    }

    return 0;
}

static int PRGA(unsigned char* S, char* plaintext, int plainTextSize) {
    int i = 0;
    int j = 0;

    for (size_t n = 0, len = plainTextSize; n < len; n++) {
        i = (i + 1) % N;
        j = (j + S[i]) % N;
        swap(&S[i], &S[j]);
        int rnd = S[(S[i] + S[j]) % N];
        plaintext[n] ^= rnd;
    }

    return 0;
}

static int RC4(char* key, char* plaintext, int plainTextSize) {
    unsigned char S[N] = { 0 };
    KSA(key, S);
    PRGA(S, plaintext, plainTextSize);
    return 0;
}

/*
https://raw.githubusercontent.com/rapid7/metasploit-framework/master/data/headers/windows/rc4.h
*/
