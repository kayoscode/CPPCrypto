#ifndef INCLUDE_RSAENGINE_H
#define INCLUDE_RSAENGINE_H

#include <memory.h>

#include "CPPCrypto.h"
#include "SecureRandom.h"

/**
 * handles math between RSA numbers
 * */
struct RSANumber {
    RSANumber(int* value, int bits) 
        :bits(bits)
    {
        memcpy(this->value, value, bits / 32);
    }

    RSANumber() 
        :bits(0)
    {}

    //value 128 because 128 * 32 = 4096 -> max bits for RSA key
    int value[128] = { 0 };

    void generatePrime(int bits);

    private:
        int bits;
};

/**
 * Holds a key for RSA encryption
 * @author Bryce Young April 14, 2021
 * */
struct RSAKey {
    RSAKey(int bits) 
        :bits(bits)
    {}

    private:
        int bits;
        RSANumber publicKey, privateKey;
};

/**
 * RSA encryption impl
 * @author Bryce Young April 12, 2021
 * */
class RSAEngine : public CryptoEngine {
    public:
        /**
         * Class takes ownership of @param key
         * Be sure to initialize the key in dynamic memory
         * */
        RSAEngine(RSAKey* key) 
            :key(key)
        {
        }

        ~RSAEngine(){
            delete key;
        }

        int getOutputTextSize(int plainTextSize);

        /**
         * RSA implementation generating ciphertext
         * */
        void encyrptText(char* plainText, int plainTextSize, char* output);

        /**
         * RSA implementation inverting cipher process
         * */
        void decryptText(char* cipherText, int cipherTextSize, char* output);

    private:
        RSAKey* key;
};

#endif