#include <iostream>

#include "AESEngine.h"

//quick conversions from hex character to a value
char hex2Number[256] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0, 0, 0, 0, 
    0, 10, 11, 12, 13, 14, 15, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 10, 11, 12, 13, 14, 15, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

//for 128 bit AES
#define KEY_LENGTH128 4
#define ROUNDS128 11

//compute g(8) antilog
unsigned char antiLogTable[256] = {
    0x01, 0xe5, 0x4c, 0xb5, 0xfb, 0x9f, 0xfc, 0x12, 
    0x03, 0x34, 0xd4, 0xc4, 0x16, 0xba, 0x1f, 0x36, 
    0x05, 0x5c, 0x67, 0x57, 0x3a, 0xd5, 0x21, 0x5a, 
    0x0f, 0xe4, 0xa9, 0xf9, 0x4e, 0x64, 0x63, 0xee, 
    0x11, 0x37, 0xe0, 0x10, 0xd2, 0xac, 0xa5, 0x29, 
    0x33, 0x59, 0x3b, 0x30, 0x6d, 0xef, 0xf4, 0x7b, 
    0x55, 0xeb, 0x4d, 0x50, 0xb7, 0x2a, 0x07, 0x8d, 
    0xff, 0x26, 0xd7, 0xf0, 0xc2, 0x7e, 0x09, 0x8c, 
    0x1a, 0x6a, 0x62, 0x0b, 0x5d, 0x82, 0x1b, 0x8f, 
    0x2e, 0xbe, 0xa6, 0x1d, 0xe7, 0x9d, 0x2d, 0x8a, 
    0x72, 0xd9, 0xf1, 0x27, 0x32, 0xbc, 0x77, 0x85, 
    0x96, 0x70, 0x08, 0x69, 0x56, 0xdf, 0x99, 0x94, 
    0xa1, 0x90, 0x18, 0xbb, 0xfa, 0x7a, 0xb0, 0xa7, 
    0xf8, 0xab, 0x28, 0xd6, 0x15, 0x8e, 0xcb, 0xf2, 
    0x13, 0xe6, 0x78, 0x61, 0x3f, 0x89, 0x46, 0x0d, 
    0x35, 0x31, 0x88, 0xa3, 0x41, 0x80, 0xca, 0x17, 
    0x5f, 0x53, 0x83, 0xfe, 0xc3, 0x9b, 0x45, 0x39, 
    0xe1, 0xf5, 0x9e, 0x19, 0x5e, 0xb6, 0xcf, 0x4b, 
    0x38, 0x04, 0xb9, 0x2b, 0xe2, 0xc1, 0x4a, 0xdd, 
    0x48, 0x0c, 0xd0, 0x7d, 0x3d, 0x58, 0xde, 0x7c, 
    0xd8, 0x14, 0x6b, 0x87, 0x47, 0xe8, 0x79, 0x84, 
    0x73, 0x3c, 0xbd, 0x92, 0xc9, 0x23, 0x8b, 0x97, 
    0x95, 0x44, 0xdc, 0xad, 0x40, 0x65, 0x86, 0xa2, 
    0xa4, 0xcc, 0x7f, 0xec, 0xc0, 0xaf, 0x91, 0xfd, 
    0xf7, 0x4f, 0x81, 0x2f, 0x5b, 0xea, 0xa8, 0x1c, 
    0x02, 0xd1, 0x98, 0x71, 0xed, 0x25, 0xe3, 0x24, 
    0x06, 0x68, 0xb3, 0x93, 0x2c, 0x6f, 0x3e, 0x6c, 
    0x0a, 0xb8, 0xce, 0xae, 0x74, 0xb1, 0x42, 0xb4, 
    0x1e, 0xd3, 0x49, 0xe9, 0x9c, 0xc8, 0xc6, 0xc7, 
    0x22, 0x6e, 0xdb, 0x20, 0xbf, 0x43, 0x51, 0x52, 
    0x66, 0xb2, 0x76, 0x60, 0xda, 0xc5, 0xf3, 0xf6, 
    0xaa, 0xcd, 0x9a, 0xa0, 0x75, 0x54, 0x0e, 0x01 
};

//compute g(8) log
unsigned char logTable[256] = {
    0x00, 0xff, 0xc8, 0x08, 0x91, 0x10, 0xd0, 0x36, 
    0x5a, 0x3e, 0xd8, 0x43, 0x99, 0x77, 0xfe, 0x18, 
    0x23, 0x20, 0x07, 0x70, 0xa1, 0x6c, 0x0c, 0x7f, 
    0x62, 0x8b, 0x40, 0x46, 0xc7, 0x4b, 0xe0, 0x0e, 
    0xeb, 0x16, 0xe8, 0xad, 0xcf, 0xcd, 0x39, 0x53, 
    0x6a, 0x27, 0x35, 0x93, 0xd4, 0x4e, 0x48, 0xc3, 
    0x2b, 0x79, 0x54, 0x28, 0x09, 0x78, 0x0f, 0x21, 
    0x90, 0x87, 0x14, 0x2a, 0xa9, 0x9c, 0xd6, 0x74, 
    0xb4, 0x7c, 0xde, 0xed, 0xb1, 0x86, 0x76, 0xa4, 
    0x98, 0xe2, 0x96, 0x8f, 0x02, 0x32, 0x1c, 0xc1, 
    0x33, 0xee, 0xef, 0x81, 0xfd, 0x30, 0x5c, 0x13, 
    0x9d, 0x29, 0x17, 0xc4, 0x11, 0x44, 0x8c, 0x80, 
    0xf3, 0x73, 0x42, 0x1e, 0x1d, 0xb5, 0xf0, 0x12, 
    0xd1, 0x5b, 0x41, 0xa2, 0xd7, 0x2c, 0xe9, 0xd5, 
    0x59, 0xcb, 0x50, 0xa8, 0xdc, 0xfc, 0xf2, 0x56, 
    0x72, 0xa6, 0x65, 0x2f, 0x9f, 0x9b, 0x3d, 0xba, 
    0x7d, 0xc2, 0x45, 0x82, 0xa7, 0x57, 0xb6, 0xa3, 
    0x7a, 0x75, 0x4f, 0xae, 0x3f, 0x37, 0x6d, 0x47, 
    0x61, 0xbe, 0xab, 0xd3, 0x5f, 0xb0, 0x58, 0xaf, 
    0xca, 0x5e, 0xfa, 0x85, 0xe4, 0x4d, 0x8a, 0x05, 
    0xfb, 0x60, 0xb7, 0x7b, 0xb8, 0x26, 0x4a, 0x67, 
    0xc6, 0x1a, 0xf8, 0x69, 0x25, 0xb3, 0xdb, 0xbd, 
    0x66, 0xdd, 0xf1, 0xd2, 0xdf, 0x03, 0x8d, 0x34, 
    0xd9, 0x92, 0x0d, 0x63, 0x55, 0xaa, 0x49, 0xec, 
    0xbc, 0x95, 0x3c, 0x84, 0x0b, 0xf5, 0xe6, 0xe7, 
    0xe5, 0xac, 0x7e, 0x6e, 0xb9, 0xf9, 0xda, 0x8e, 
    0x9a, 0xc9, 0x24, 0xe1, 0x0a, 0x15, 0x6b, 0x3a, 
    0xa0, 0x51, 0xf4, 0xea, 0xb2, 0x97, 0x9e, 0x5d, 
    0x22, 0x88, 0x94, 0xce, 0x19, 0x01, 0x71, 0x4c, 
    0xa5, 0xe3, 0xc5, 0x31, 0xbb, 0xcc, 0x1f, 0x2d, 
    0x3b, 0x52, 0x6f, 0xf6, 0x2e, 0x89, 0xf7, 0xc0, 
    0x68, 0x1b, 0x64, 0x04, 0x06, 0xbf, 0x83, 0x38 
};

/**
 * bytes = keylen
 * */
static inline void printArr(const unsigned char* key, int bytes) {
    for(int i = 0; i < bytes; i++) {
        printf("%2x ", key[i]);
    }

    printf("\n");
}

//perform multiplication in g(8)
static inline unsigned char galMult(unsigned char number, unsigned char count) {
    int ret = 0;

    for (; count; count >>= 1) {
        if (count & 1) {
            ret ^= number;
        }
        if (number & 0b10000000) {
            number = (number << 1) ^ 0b100011011;
        }
        else {
            number <<= 1;
        }
    }

    return ret;
}

//use a lookuptable for inverse mult g(8) -> much faster than calculating it
static inline unsigned char galMultInverse(unsigned char input) {
    return input == 0? input : antiLogTable[255 - logTable[input]];
}

/**
 * RCON step AES
 * */
static inline unsigned char rcon(unsigned char count) {
    unsigned char ret = 1;

    if(count == 0) {
        return 0;
    }

    while(count != 1) {
        ret = galMult(ret, 2) ;
        count--;
    }

    return ret;
}

/**
 * Rotate step AES
 * */
static inline void rotate(unsigned char* input) {
    unsigned char first = *input;

    for(int i = 0; i < 3; i++) {
        input[i] = input[i + 1];
    }

    input[3] = first;
}

static inline void convertStringToHexArray(const char* text, unsigned char* output) {
    for(int i = 0; i < 32; i += 2) {
        output[i / 2] = hex2Number[text[i]] * 16 + hex2Number[text[i + 1]];
    }
}

//bytes = KEY_LEN
static inline void copyArr(const unsigned char* source, unsigned char* dest, int bytes) {
    for(int i = 0; i < bytes; i++) {
        dest[i] = source[i];
    }
}

/**
 * SBOX step
 * */
static inline unsigned char sBox(unsigned char input) {
    unsigned char s = galMultInverse(input);
    unsigned char ret = s;
    
    for (int i = 0; i < 4; i++) {
        s = (s << 1) | (s >> 7);
        ret ^= s;
    }

    return ret ^ 0x63;
}

/**
 * Calculate key[i]
 * */
static inline void calculateKey(unsigned char* key, int i) {
    rotate(key);
    
    for(int j = 0; j < 4; j++) {
        key[j] = sBox(key[j]);
    }

    key[0] ^= rcon(i);
}

static inline void scheduleKeys128(const unsigned char* key, unsigned char keys[11][16]) {
    //k[i] = k[i] for i < N
    unsigned char temp[4];
    unsigned char* pPtr = nullptr;
    unsigned char* fourAgo = nullptr;
    int keyIndex = 0, fourAgoIndex = 0, fourAgoCounter = 0;

    copyArr(key, keys[0], KEY_LENGTH128);
    copyArr(key + KEY_LENGTH128, keys[0] + 4, KEY_LENGTH128);
    copyArr(key + (KEY_LENGTH128 * 2), keys[0] + 8, KEY_LENGTH128);
    copyArr(key + (KEY_LENGTH128 * 3), keys[0] + 12, KEY_LENGTH128);

    pPtr = keys[0] + 12;
    fourAgo = keys[0];

    for(int i = 4; i < KEY_LENGTH128 * ROUNDS128; i++) {
        unsigned char* keyPtr;
        copyArr(pPtr, temp, KEY_LENGTH128);

        if(i % 4 == 0) {
            calculateKey(temp, ++keyIndex);
        }

        keyPtr = keys[keyIndex] + ((i % 4) * KEY_LENGTH128);

        //perform final copy and xor
        for(int j = 0; j < 4; j++) {
            keyPtr[j] = fourAgo[j] ^ temp[j];
        }

        //set data for next round
        pPtr = keyPtr;
        fourAgoCounter++;

        if(fourAgoCounter % 4 == 0) {
            fourAgoCounter = 0;
            fourAgoIndex++;
        }

        fourAgo = keys[fourAgoIndex] + (fourAgoCounter * KEY_LENGTH128);
    }
}

static inline void byteSubstitution(unsigned char* state) {
    for(int i = 0; i < 16; i++) {
        state[i] = sBox(state[i]);
    }
}

static inline void shiftRows(unsigned char* state) {
    //skip the first row
    //at this point, the input is laid out like this
    //0  4  8  12 -> 0  4  8  12
    //1  5  9  13 -> 5  9  13  1
    //2  6  10 14 -> 10 14 2   6 
    //3  7  11 15 -> 15 3  7  11
    //shifting the rows would move the row containing 1, 5, 9, 13 to be 5, 9, 13, 1. Other rows follow the same, but they move over more or less depending on their row index
    
    //shift row[1]
    unsigned char temp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = temp;

    //shift row[2]
    temp = state[2];
    unsigned char temp2 = state[6];
    state[2] = state[10];
    state[6] = state[14];
    state[10] = temp;
    state[14] = temp2;

    //shift row[3]
    temp = state[3];
    state[3] = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = temp;
}

static inline void mixColumns(unsigned char* state) {
    //multiply it by the following matrix in gf(2^8) -> transpose in my case :)
    // 2, 3, 1, 1
    // 1, 2, 3, 1
    // 1, 1, 2, 3
    // 3, 1, 1, 2

    unsigned char temp[16];
    for(int i = 0; i < 16; i += 4) {
        temp[i] = galMult(2, state[i]) ^ galMult(3, state[i + 1]) ^ state[i + 2] ^ state[i + 3];
        temp[i + 1] = state[i] ^ galMult(2, state[i + 1]) ^ galMult(3, state[i + 2]) ^ state[i + 3];
        temp[i + 2] = state[i] ^ state[i + 1] ^ galMult(2, state[i + 2]) ^ galMult(3, state[i + 3]);
        temp[i + 3] = galMult(3, state[i]) ^ state[i + 1] ^ state[i + 2] ^ galMult(2, state[i + 3]);
    }

    copyArr(temp, state, 16);
}

static inline void addRoundKey(unsigned char* state, const unsigned char* roundKey) {
    for(int i = 0; i < 16; i++) {
        state[i] = state[i] ^ roundKey[i];
    }
}

//creates the next block to encrypt
static inline void prepareAESBlock(const std::string& plainText, unsigned char* block, int blockIndex, int blockSize) {
    int cnt = 0;

    for(int i = blockSize * blockIndex; i < (blockSize * blockIndex) + blockSize; i++) {
        if(i < plainText.size()) {
            block[cnt] = plainText[i];
        }
        else {
            block[cnt] = 0;
        }

        cnt++;
    }
}

void AESEncryptBlock128(unsigned char* state, unsigned char roundKeys[ROUNDS128][16]) {
    addRoundKey(state, roundKeys[0]);

    for(int i = 1; i < ROUNDS128 - 1; i++) {
        byteSubstitution(state);
        shiftRows(state);
        mixColumns(state);
        addRoundKey(state, roundKeys[i]);
    }

    byteSubstitution(state);
    shiftRows(state);
    addRoundKey(state, roundKeys[ROUNDS128 - 1]);
}

void AESEncrypt128(const std::string& plainText, const unsigned char* key, char* buffer) {
    unsigned char state[16], roundKeys[ROUNDS128][16] = { 0 };

    //schedule all keys
    scheduleKeys128(key, roundKeys);

    //encrypt each block
    int totalBlocks = (plainText.size() / 16) + (plainText.size() % 16 != 0);

    for(int i = 0; i < totalBlocks; ++i) {
        prepareAESBlock(plainText, state, i, 16);
        AESEncryptBlock128(state, roundKeys);
        printArr(state, 16);
    }
}

void AESEngine::encyrptText(const std::string& plainText, std::string& cipherText) {
    switch(key->getType()) {
        case AESKeyType::AES_KEY128:
            char buffer[32];
            AESEncrypt128(plainText, key->getKey(), buffer);
            break;
        case AESKeyType::AES_KEY256:
            break;
    }
}

void AESEngine::decryptText(const std::string& plainText, std::string& cipherText) {

}