#include "AESEngine.h"

#include <iostream>
#include <assert.h>

void testAES128() {
    char* encText;
    char* decText;

    //test with key 1
    unsigned char keyData[] = "BRYCEYOUNG'SKEY!";
    unsigned char expectedCipherText[] = { 
        0x3d, 0xe6, 0x98, 0xef, 0xdb, 0x12, 0x8e, 0x5a, 0xa2, 0xb4, 0x13, 0x8f, 0x07, 0x70, 0x7b, 0x8f,
        0x77, 0xaa, 0x1c, 0x8c, 0x79, 0xbd, 0xe9, 0xf5, 0xb6, 0x66, 0x76, 0x9b, 0xca, 0xbf, 0x35, 0x2c,
        0x9a, 0x21, 0x1d, 0xa4, 0x51, 0xfb, 0xd6, 0x74, 0xc5, 0x34, 0xe7, 0x32, 0xd0, 0x9d, 0xc1, 0x34,
        0x95, 0x0e, 0x49, 0x41, 0x3e, 0x86, 0x65, 0x74, 0x99, 0xef, 0x80, 0x4c, 0x1a, 0x82, 0x37, 0x91, 
    };

    char plainText[] = "this is a test of the AES block cipher in ECB mode";
    int plainTextSize = sizeof(plainText) / sizeof(plainText[0]);

    AESKey* key = new AESKey(keyData, AESKeyType::AES_KEY128);
    AESEngine aes(key);

    int cipherTextSize = aes.getOutputTextSize(plainTextSize);
    encText = new char[cipherTextSize];
    decText = new char[cipherTextSize];

    aes.encyrptText(plainText, plainTextSize, encText);

    std::cout << "Testing AES cipher 1: Output:\n";
    aes.printHex(encText, cipherTextSize);
    std::cout << "Expected Output:\n";
    aes.printHex((char*)expectedCipherText, cipherTextSize);

    //make sure it's the same as the expected output
    assert(memcmp(expectedCipherText, encText, cipherTextSize) == 0);
    std::cout << "TEST PASSED!\n";

    std::cout << "Testing decryption\nDeciphered text:";
    //make sure it decrypts to the starting text
    aes.decryptText(encText, cipherTextSize, decText);
    std::cout << decText << "\n";
    assert(memcmp(decText, plainText, plainTextSize) == 0);
    std::cout << "TEST PASSED!\n";

    //test with key 2 - hex key
    unsigned char keyData2[] = { 
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0xFF 
    };

    unsigned char expectedCipherText2[] = { 
        0xeb,	0xac,	0x55,	0x29,	0x95,	0x5c,	0xb2,	0xef,	0x10,	0x34,	0x10,	0xd8,	0x6c,	0x45,	0xc3,	0x86,
        0xb6,	0x0a,	0xc9,	0x40,	0xe7,	0x43,	0xcd,	0xdd,	0x0f,	0x65,	0x69,	0xbb,	0xc1,	0x71,	0x1e,	0x17,
        0xf7,	0x18,	0xdd,	0x65,	0x05,	0x28,	0x8f,	0xfd,	0x16,	0x0e,	0xbf,	0xc0,	0x4c,	0x18,	0x66,	0xdf,
        0x5b,	0x66,	0xc6,	0x58,	0xbc,	0x48,	0x1d,	0xce,	0xb9,	0x00,	0x28,	0x0c,	0x3e,	0x73,	0xef,	0x59,
    };

    key->setKeyData(keyData2, AESKeyType::AES_KEY128);
    aes.encyrptText(plainText, plainTextSize, encText);

    std::cout << "Testing AES cipher 2: Output:\n";
    aes.printHex(encText, cipherTextSize);
    std::cout << "Expected Output:\n";
    aes.printHex((char*)expectedCipherText2, cipherTextSize);

    assert(memcmp(expectedCipherText2, encText, cipherTextSize) == 0);
    std::cout << "TEST PASSED!\n";

    //test decryption
    std::cout << "Testing decryption\nDeciphered Text";
    aes.decryptText(encText, cipherTextSize, decText);
    std::cout << decText << "\n";
    assert(memcmp(decText, plainText, plainTextSize) == 0);
    std::cout << "TEST PASSED!\n";

    //test with a random key
    std::cout << "Starting random key test - test 3\n";
    AESKey* key2 = new AESKey(AESKeyType::AES_KEY128);
    AESEngine aes2(key2);

    aes2.encyrptText(plainText, plainTextSize, encText);
    std::cout << "Encrypted Output:\n";
    aes2.printHex(encText, cipherTextSize);
    aes2.decryptText(encText, cipherTextSize, decText);

    std::cout << "Testing decryption\nDeciphered Text:";
    std::cout << decText << "\n";
    assert(memcmp(decText, plainText, plainTextSize) == 0);
    std::cout << "TEST PASSED!\n";

    delete[] encText;
    delete[] decText;
}

int main() {
    testAES128();
    std::cout << "All test cases passed!\n";
    return 0;
}