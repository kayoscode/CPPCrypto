#ifndef INCLUDE_CPP_ENCRYPT_H
#define INCLUDE_CPP_ENCRYPT_H

#include <string>

#include "SecureRandom.h"

/**
 * Mode of operation for block cipher
 * @author Bryce Young
 * */
enum class BlockCipherMode {
    ECB,
    CBC,
};

/**
 * Basic interface for implementing cryptographic engines
 * AES, etc
 * @author Bryce Young April 12, 2021
 * */
class CryptoEngine {
    public:
        CryptoEngine() {
        }

        ~CryptoEngine() {
        }

        /**
         * Returns the size of the ciphertext
         * for this cipher engine
         * @return the size of the cipher text in bytes
         * */
        virtual int getOutputTextSize(int textSize) = 0;

        /**
         * Takes plaintext text and generates cipher text
         * @param text the plaintext
         * @param cipherText output result of the function passed as reference to remove copies
         * @param key key to encrypt plaintext
         * @param keyLen length of the key in bytes
         * */
        virtual void encyrptText(char* text, int textSize, char* cipherText) = 0;

        /**
         * Takes ciphertext and generates plaintext
         * @param text the plaintext
         * @param plainText output result of the function passed as reference to remove copies
         * @param key key to encrypt plaintext
         * @param keyLen length of the key in bytes
         * */
        virtual void decryptText(char* cipherText, int cipherTextSize, char* output) = 0;

        /**
         * Prints a string's hex value
         * */
        static void printHex(char* hex, int size);

    private:
};

#endif