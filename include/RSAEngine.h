#ifndef INCLUDE_RSAENGINE_H
#define INCLUDE_RSAENGINE_H

#include <memory.h>
#include <iostream>
#include <bitset>
#include <string>

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
        RSANumber(uint32_t num) {
            this->value[ARR_SIZE - 1] = num;
        }

        /**
         * Default constructor
         * */
        RSANumber() 
        {}

        /**
         * A function designed to calculate both the quotient and the mod in one go!
         * Avoids having to calculate them both separately to save CPU cycles
         * */
        static void div(const RSANumber& N, const RSANumber& D, RSANumber& result, RSANumber& mod);

        /**
         * calculates ( @param base ^ @param exp ) mod @param mod
         * and stores the result in @param result
         * */
        static void expMod(RSANumber base, RSANumber exp, const RSANumber& mod, RSANumber& result);

        /**
         * Assignment operator
         * */
        RSANumber& operator=(const RSANumber& num) {
            memcpy(this->value, num.value, sizeof(uint32_t) * ARR_SIZE);
            return *this;
        }

        /**
         * Sets the number from a binary string
         * @param binary the value of the number in binary with the least significant bit furthest to the right
         * */
        inline void setFromBinary(const std::string& binary) {
            *this = 0;
            int index = 0;

            for(int i = binary.size() - 1; i >= 0; --i) {
                if(binary[i] == '1') {
                    setBit(index);
                }

                index++;
            }
        }

        /**
         * Sets a single bit
         * */
        inline void setBit(uint32_t index) {
            if(index < 0) {
                return;
            }
            else if(index >= sizeof(uint32_t) * 8 * ARR_SIZE) {
                return;
            }

            value[ARR_SIZE - (index / (sizeof(uint32_t) * 8)) - 1] |= (1 << (index % (sizeof(uint32_t) * 8)));
        }

        /**
         * Clears a single bit
         * */
        inline void clearBit(uint32_t index) {
            if(index < 0) {
                return;
            }
            else if(index >= sizeof(uint32_t) * ARR_SIZE * 8) {
                return;
            }

            value[ARR_SIZE - (index / (sizeof(uint32_t) * 8)) - 1] &= ~(1 << (index % (sizeof(uint32_t) * 8)));
        }

        /**
         * Returns a single bit value
         * */
        inline bool getBit(uint32_t index) const {
            if(index < 0) {
                return 0;
            }
            else if(index >= sizeof(uint32_t) * ARR_SIZE * 8) {
                return 0;
            }

            return (value[ARR_SIZE - (index / (sizeof(uint32_t) * 8)) - 1] & (1 << (index % (sizeof(uint32_t) * 8)))) != 0;
        }

        /**
         * Prints the number in binary but ignores the first chunks which are zero
         * */
        void printBinary() const {
            std::cout << getBinary() << "\n";
        }

        std::string getBinary() const {
            std::string ret;
            int highestBit = this->getMostSignificantBitIndex();

            for(int i = highestBit; i >= 0; --i) {
                if(getBit(i)) {
                    ret += '1';
                }
                else {
                    ret += '0';
                }
            }

            return ret;
        }

        void printOctal() const {
            std::cout << getOctal() << "\n";
        }

        /**
         * gets the number as an octal string
         * */
        std::string getOctal() const {
            std::string ret;
            RSANumber copy(*this);
            RSANumber zero(0), r, eight(8);

            while(copy > zero) {
                RSANumber::div(copy, eight, copy, r);
                ret += (r[ARR_SIZE - 1] + '0');
            }

            for(int i = 0; i < ret.size() / 2; ++i) {
                std::swap(ret[i], ret[ret.size() - i - 1]);
            }

            return ret;
        }

        void printDecimal() const {
            std::cout << getDecimal() << "\n";
        }

        std::string getDecimal() const {
            std::string ret;
            RSANumber copy(*this);
            RSANumber zero(0), r, eight(10);

            while(copy > zero) {
                RSANumber::div(copy, eight, copy, r);
                ret += (r[ARR_SIZE - 1] + '0');
            }

            for(int i = 0; i < ret.size() / 2; ++i) {
                std::swap(ret[i], ret[ret.size() - i - 1]);
            }

            return ret;
        }

        void printHex() const {
            std::cout << getHex() << "\n";
        }

        std::string getHex() const {
            const char* hexToStr = "0123456789ABCDEF";
            std::string ret;
            RSANumber copy(*this);
            RSANumber zero(0), r, eight(16);

            while(copy > zero) {
                RSANumber::div(copy, eight, copy, r);
                ret += hexToStr[(r[ARR_SIZE - 1])];
            }

            for(int i = 0; i < ret.size() / 2; ++i) {
                std::swap(ret[i], ret[ret.size() - i - 1]);
            }

            return ret;
        }

        void printB64() const {
            //std::cout << 
        }


        inline bool isNegative() const {
            return getBit((sizeof(uint32_t) * 8 * ARR_SIZE) - 1);
        }

        /**
         * A fast function returning the most significant power of 2
         * @return the position of the most significant bit
         * if 0 @return is -1
         * */
        inline int getMostSignificantBitIndex() const {
            int index = sizeof(uint32_t) * 8 * (ARR_SIZE - 1);

            for(int i = 0; i < ARR_SIZE; ++i) {
                if(value[i] != 0) {
                    float v = (float)value[i];
                    return (((*(int*)&v & 0x7F800000) >> 23) - 127) + index;
                }

                index -= 32;
            }

            return -1;
        }

        RSANumber pow(RSANumber& y) const;
        RSANumber& setPow(RSANumber& y);

        RSANumber operator>>(int c) const;
        RSANumber operator<<(int c) const;
        RSANumber& operator>>=(int c);
        RSANumber& operator<<=(int c);

        bool operator>(const RSANumber& num) const;
        bool operator<(const RSANumber& num) const;
        bool operator>=(const RSANumber& num) const;
        bool operator<=(const RSANumber& num) const;
        bool operator==(const RSANumber& num) const;
        bool operator!=(const RSANumber& num) const;

        RSANumber operator+(const RSANumber& num) const;
        RSANumber operator-(const RSANumber& num) const;
        RSANumber& operator+=(const RSANumber& num);
        RSANumber& operator-=(const RSANumber& num);

        //applicable logical operators
        RSANumber operator|(const RSANumber& num) const;
        RSANumber operator&(const RSANumber& num) const;
        RSANumber operator^(const RSANumber& num) const;
        RSANumber& operator|=(const RSANumber& num);
        RSANumber& operator&=(const RSANumber& num);
        RSANumber& operator^=(const RSANumber& num);

        /**
         * @return true iff the value is not equal to 0
         * */
        bool operator!() const {
            for(int i = 0; i < ARR_SIZE; ++i) {
                if(value[i] != 0) {
                    return true;
                }
            }

            return false;
        }

        RSANumber operator%(const RSANumber& num) const;
        RSANumber& operator%=(const RSANumber& num);

        RSANumber operator*(const RSANumber& num) const;
        RSANumber operator/(const RSANumber& num) const;
        RSANumber& operator*=(const RSANumber& num);
        RSANumber& operator/=(const RSANumber& num);

        RSANumber operator~();
        RSANumber operator-();

        uint32_t* getNum() {
            return value;
        }

        const uint32_t* getNum() const {
            return value;
        }

        /**
         * Const version of getting by index
         * */
        inline const uint32_t& operator[](int index) const {
            if(index < 0) {
                index = 0;
            }
            else if(index >= ARR_SIZE) {
                index = ARR_SIZE - 1;
            }

            return value[index];
        }

        /**
         * Get by index but non const
         * */
        inline uint32_t& operator[](int index) {
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
         * @param base the base to con 
 ;

        /**
         * Generates a random prime number within a certain bit range
         * @param bits the max number of bits
         * */
        void generatePrime(int bits);

    private:
        //value 128 because 128 * 32 = 4096 -> max bits for RSA key
        uint32_t value[ARR_SIZE] = { 0 };
        friend void rsaNumLSL(const RSANumber& num, int c, RSANumber& output);
        friend void rsaNumLSR(const RSANumber& num, int c, RSANumber& output);
        friend int rsaNumCmp(const RSANumber& n1, const RSANumber& n2);
        friend void rsaNumAdd(const RSANumber& n1, const RSANumber& n2, RSANumber& output);
        friend void rsaNumSub(const RSANumber& n1, const RSANumber& n2, RSANumber& output);
        friend void rsaNumberOr(const RSANumber& n1, const RSANumber& n2, RSANumber& dest);
        friend void rsaNumberAnd(const RSANumber& n1, const RSANumber& n2, RSANumber& dest);
        friend void rsaNumberXor(const RSANumber& n1, const RSANumber& n2, RSANumber& dest);
        friend void rsaNumberNegate(const RSANumber n1, RSANumber& dest);
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