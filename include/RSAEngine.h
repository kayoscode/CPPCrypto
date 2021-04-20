#ifndef INCLUDE_RSAENGINE_H
#define INCLUDE_RSAENGINE_H

#include <memory.h>

#include "CPPCrypto.h"
#include "SecureRandom.h"

//number of indices for an RSA number (32 bit indices)
constexpr int ARR_SIZE = 128;

/**
 * handles math between RSA numbers
 * Note: bits for this number are stored literally as a stream of bits
 * The first bit is the most significant bit and the last bit is the least significant bit!
 * @author Bryce Young April 14, 2021
 * */
class RSANumber {
    public:
        /**
         * Copy constructor
         * @param num the number to copy from
         * */
        RSANumber(const RSANumber& num) 
        {
            memcpy(this->value, num.value, sizeof(uint32_t) * ARR_SIZE);
        }

        /**
         * Creates the RSA number from a base 10 initialization
         * @param num the number in base 10
         * */
        RSANumber(uint32_t num);

        /**
         * Default constructor
         * */
        RSANumber() 
        {}

        RSANumber& operator=(const RSANumber& num) {
            memcpy(this->value, num.value, sizeof(uint32_t) * ARR_SIZE);
            return *this;
        }

        void setBit(int index) {
            value[ARR_SIZE - (index / 32) - 1] |= (1 << (index %32));
        }

        void clearBit(int index) {
            value[ARR_SIZE - (index / 32) - 1] &= ~(1 << (index %32));
        }

        RSANumber operator>>(int c);
        RSANumber operator<<(int c);
        RSANumber& operator>>=(int c);
        RSANumber& operator<<=(int c);

        bool operator>(const RSANumber& num);
        bool operator<(const RSANumber& num);
        bool operator>=(const RSANumber& num);
        bool operator<=(const RSANumber& num);
        bool operator==(const RSANumber& num);

        RSANumber operator+(const RSANumber& num);
        RSANumber operator-(const RSANumber& num);
        RSANumber& operator+=(const RSANumber& num);
        RSANumber& operator-=(const RSANumber& num);

        RSANumber operator%(const RSANumber& num);
        RSANumber& operator%=(const RSANumber& num);

        RSANumber operator*(const RSANumber& num) {
            RSANumber ret;
            return ret;
        }

        RSANumber operator/(const RSANumber& num) {
            RSANumber ret;
            return ret;
        }

        RSANumber& operator*=(const RSANumber& num) {
            return *this;
        }

        RSANumber& operator/=(const RSANumber& num) {
            return *this;
        }

        uint32_t* getNum() {
            return value;
        }

        uint32_t& operator[](int index) {
            if(index < 0) {
                index = 0;
            }
            else if(index >= ARR_SIZE) {
                index = ARR_SIZE - 1;
            }

            return value[index];
        }

        /**
         * Returns the number in a certain base
         * @param base the base to convert
         * */
        std::string toString(int base);

        /**
         * Generates a random prime number within a certain bit range
         * @param bits the max number of bits
         * */
        void generatePrime(int bits);

    private:
        //value 128 because 128 * 32 = 4096 -> max bits for RSA key
        uint32_t value[ARR_SIZE] = { 0 };
        friend void rsaNumLSL(RSANumber& num, int c, RSANumber& output);
        friend void rsaNumLSR(RSANumber& num, int c, RSANumber& output);

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