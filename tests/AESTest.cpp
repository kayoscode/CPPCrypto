#include "AESEngine.h"

#include <iostream>
#include <assert.h>

unsigned char initVector[] = "0000000000000000";

unsigned char keyData[] = { 
    0x42, 0x52, 0x59, 0x43, 0x45, 0x59, 0x4f, 0x55, 0x4e, 0x47, 0x27, 0x53, 0x4b, 0x45, 0x59, 0x21
};

//expected data indexed by feedback mode
unsigned char expectedCipherText[2][64] = { 
    {
        0x3d, 0xe6, 0x98, 0xef, 0xdb, 0x12, 0x8e, 0x5a, 0xa2, 0xb4, 0x13, 0x8f, 0x07, 0x70, 0x7b, 0x8f,
        0x77, 0xaa, 0x1c, 0x8c, 0x79, 0xbd, 0xe9, 0xf5, 0xb6, 0x66, 0x76, 0x9b, 0xca, 0xbf, 0x35, 0x2c,
        0x9a, 0x21, 0x1d, 0xa4, 0x51, 0xfb, 0xd6, 0x74, 0xc5, 0x34, 0xe7, 0x32, 0xd0, 0x9d, 0xc1, 0x34,
        0x95, 0x0e, 0x49, 0x41, 0x3e, 0x86, 0x65, 0x74, 0x99, 0xef, 0x80, 0x4c, 0x1a, 0x82, 0x37, 0x91, 
    },
    {
        0x2d,	0x39,	0x86,	0xd0,	0xdc,	0x88,	0xb1,	0x61,	0x40,	0x86,	0x6b,	0x04,	0x66,	0xa6,	0x36,	0xd8,
        0x8a,	0x76,	0x20,	0x98,	0x53,	0x44,	0x37,	0xf0,	0x38,	0x4d,	0x7d,	0xd0,	0xfb,	0x8c,	0x62,	0xf6,
        0x5e,	0x16,	0x72,	0xbe,	0x3d,	0xc6,	0xc7,	0xf0,	0x69,	0x5e,	0xda,	0xc9,	0x7e,	0xa3,	0xce,	0xf2,
        0x6c,	0x5b,	0x54,	0x93,	0x8d,	0x9a,	0x13,	0x87,	0xac,	0x0c,	0x59,	0xb0,	0x18,	0x04,	0x1d,	0x42,
    }
};

unsigned char keyData2[] = { 
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0xFF 
};

unsigned char expectedCipherText2[2][64] = { 
    {
        0xeb,	0xac,	0x55,	0x29,	0x95,	0x5c,	0xb2,	0xef,	0x10,	0x34,	0x10,	0xd8,	0x6c,	0x45,	0xc3,	0x86,
        0xb6,	0x0a,	0xc9,	0x40,	0xe7,	0x43,	0xcd,	0xdd,	0x0f,	0x65,	0x69,	0xbb,	0xc1,	0x71,	0x1e,	0x17,
        0xf7,	0x18,	0xdd,	0x65,	0x05,	0x28,	0x8f,	0xfd,	0x16,	0x0e,	0xbf,	0xc0,	0x4c,	0x18,	0x66,	0xdf,
        0x5b,	0x66,	0xc6,	0x58,	0xbc,	0x48,	0x1d,	0xce,	0xb9,	0x00,	0x28,	0x0c,	0x3e,	0x73,	0xef,	0x59,
    },
    {
        0x44,	0x2a,	0xa9,	0x1a,	0x84,	0x41,	0xfe,	0x72,	0x00,	0x01,	0x0c,	0xdc,	0x87,	0x6f,	0xee,	0x36,
        0x4c,	0x4c,	0x88,	0x04,	0x8b,	0x59,	0x45,	0x51,	0xcb,	0x9c,	0xc8,	0x4a,	0x8f,	0x67,	0xce,	0x1c,
        0xea,	0x9a,	0xe4,	0x56,	0xbe,	0xfe,	0xbf,	0x21,	0xfe,	0x1f,	0x10,	0x33,	0x10,	0xe3,	0x64,	0xd1,
        0xa3,	0x8f,	0x45,	0xf5,	0x92,	0x71,	0xd9,	0x3e,	0xda,	0xd6,	0xd6,	0x6f,	0xd6,	0x3b,	0x45,	0xa6,
    }
};

void testAES128(bool softwareAES, BlockCipherMode mode) {
    //set index to 1 given CBC mode testing
    int expectedIndex = mode == BlockCipherMode::CBC;

    char* encText;
    char* decText;

    //test with key 1
    char plainText[] = "this is a test of the AES block cipher in ECB mode";
    int plainTextSize = sizeof(plainText) / sizeof(plainText[0]);

    AESKey* key = new AESKey(keyData, AESKeyType::AES_KEY128, mode);
    AESEngine aes(key, softwareAES);
    key->setInitVector(initVector);

    int cipherTextSize = aes.getOutputTextSize(plainTextSize);
    encText = new char[cipherTextSize];
    decText = new char[cipherTextSize];

    aes.encyrptText(plainText, plainTextSize, encText);

    std::cout << "Testing AES cipher 1: Output:\n";
    aes.printHex(encText, cipherTextSize);
    std::cout << "Expected Output:\n";
    aes.printHex((char*)expectedCipherText[expectedIndex], cipherTextSize);

    //make sure it's the same as the expected output
    assert(memcmp(expectedCipherText[expectedIndex], encText, cipherTextSize) == 0);
    std::cout << "TEST PASSED!\n";

    std::cout << "Testing decryption\nDeciphered text:";
    //make sure it decrypts to the starting text
    aes.decryptText(encText, cipherTextSize, decText);
    std::cout << decText << "\n";
    assert(memcmp(decText, plainText, plainTextSize) == 0);
    std::cout << "TEST PASSED!\n";

    key->setKeyData(keyData2, AESKeyType::AES_KEY128, mode);
    aes.encyrptText(plainText, plainTextSize, encText);

    std::cout << "Testing AES cipher 2: Output:\n";
    aes.printHex(encText, cipherTextSize);
    std::cout << "Expected Output:\n";
    aes.printHex((char*)expectedCipherText2[expectedIndex], cipherTextSize);

    assert(memcmp(expectedCipherText2[expectedIndex], encText, cipherTextSize) == 0);
    std::cout << "TEST PASSED!\n";

    //test decryption
    std::cout << "Testing decryption\nDeciphered Text:\n";
    aes.decryptText(encText, cipherTextSize, decText);
    std::cout << decText << "\n";
    assert(memcmp(decText, plainText, plainTextSize) == 0);
    std::cout << "TEST PASSED!\n";

    //test with a random key
    std::cout << "Starting random key test - test 3\n";
    AESKey* key2 = new AESKey(AESKeyType::AES_KEY128, mode);
    key2->setInitVector(initVector);
    AESEngine aes2(key2, softwareAES);

    aes2.encyrptText(plainText, plainTextSize, encText);
    std::cout << "Encrypted Output:\n";
    aes2.printHex(encText, cipherTextSize);
    aes2.decryptText(encText, cipherTextSize, decText);

    std::cout << "Testing decryption\nDeciphered Text:\n";
    std::cout << decText << "\n";
    assert(memcmp(decText, plainText, plainTextSize) == 0);
    std::cout << "TEST PASSED!\n";

    delete[] encText;
    delete[] decText;
}

int main() {
    std::cout << "Testing SOFTWARE AES ECB mode\n";
    testAES128(true, BlockCipherMode::ECB);

    if(AESEngine::checkAESHardwareSupport()) {
        std::cout << "Testing HARDWARE AES ECB mode\n";
        testAES128(false, BlockCipherMode::ECB);
    }
    else {
        std::cout << "Hardware implementation unsupported on this computer, aborting ECB HW testing\n";
    }

    //test cbc mode
    std::cout << "Testing software CBC mode\n";
    testAES128(true, BlockCipherMode::CBC);

    //software
    if(AESEngine::checkAESHardwareSupport()) {
        std::cout << "Testing HARDWARE AES CBC mode\n";
        testAES128(false, BlockCipherMode::CBC);
    }
    else {
        std::cout << "Hardware implementation unsupported on this computer, aborting CBC HW testing\n";
    }

    std::cout << "All test cases passed!\n";
    return 0;
}