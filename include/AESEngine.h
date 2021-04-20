#ifndef INCLUDE_CPPCRYPTO_H
#define INCLUDE_CPPCRYPTO_H

#include <memory.h>
#include "CPPCrypto.h"

/**
 * Different options for AES keytype
 * */
enum class AESKeyType {
    AES_KEY128,
    AES_KEY192,
    AES_KEY256
};

/**
 * Represents a key for AES encryption and decryption
 * @author Bryce Young April 12, 2021
 * */
struct AESKey {
    /**
     * Initializes a new AES key given a length
     * */
    AESKey(AESKeyType type, BlockCipherMode mode = BlockCipherMode::ECB) 
        :type(type),
        mode(mode)
    {
        bool genInitVector = false;
        if(mode == BlockCipherMode::CBC) {
            genInitVector = true;
        }

        switch(type) {
            case AESKeyType::AES_KEY128:
                generateRandomSequence((char*)key, 16);

                if(genInitVector) {
                    generateRandomSequence((char*)initVector, 16);
                }
                break;
            case AESKeyType::AES_KEY192:
                generateRandomSequence((char*)key, 24);

                if(genInitVector) {
                    generateRandomSequence((char*)initVector, 24);
                }
                break;
            case AESKeyType::AES_KEY256:
                generateRandomSequence((char*)key, 32);

                if(genInitVector) {
                    generateRandomSequence((char*)initVector, 32);
                }
                break;
            default:
                //shouldn't get here
                break;
        }
    }

    /**
     * Updates the value of the key
     * */
    void setKeyData(unsigned char* key, AESKeyType type, BlockCipherMode mode = BlockCipherMode::ECB) {
        this->type = type;
        this->mode = mode;
        copyData(key, this->key, type);
    }

    /**
     * Copy constructor
     * @param cpy the key to copy from
     * */
    AESKey(const AESKey& cpy) 
        :type(cpy.type),
        mode(cpy.mode)
    {
        copyData(cpy.key, this->key, cpy.type);
        copyData(cpy.initVector, this->initVector, cpy.type);
    }

    /**
     * Initailizes a new key with set data
     * @param key the data for the new key
     * @param type the type of key for AES
     * @param mode the mode of operation for this AES block cipher
     * */
    AESKey(unsigned char* key, AESKeyType type, BlockCipherMode mode = BlockCipherMode::ECB) 
        :type(type),
        mode(mode)
    {
        copyData(key, this->key, type);
    }

    BlockCipherMode getMode() {
        return mode;
    }
    
    void setMode(BlockCipherMode mode) {
        this->mode = mode;
    }

    /**
     * Returns the key type
     * */
    AESKeyType getType() const {
        return type;
    }

    /**
     * Returns the key but you can't modify it
     * @return const key
     * */
    const unsigned char* getKey() const {
        return key;
    }

    /**
     * @return the length of the key in bytes
     * */
    int getKeyLength() const {
        switch(type) {
            case AESKeyType::AES_KEY128:
                return 16;
            case AESKeyType::AES_KEY192:
                return 24;
            case AESKeyType::AES_KEY256:
                return 32;
        }

        return 0;
    }

    /**
     * Initialization vector for modes besides ECB
     * */
    void setInitVector(unsigned char* initVector) {
        copyData(initVector, this->initVector, type);
    }

    /**
     * Returns a const pointer to the init vector
     * */
    const unsigned char* getInitVector() const {
        return initVector;
    }

    private:
        //the key type len
        AESKeyType type;
        BlockCipherMode mode;

        //maybe slightly inefficient but it won't make a difference in any application
        //speed is prio here rather than allocating less data dynamically
        unsigned char key[32] = { 0 };
        unsigned char initVector[32] = { 0 };

        /**
         * Copies the key over 
         * Not in public interface
         * @param data the raw data for the key
         * @param type the type of the new key
         * */
        void copyData(const unsigned char* data, unsigned char* dest, AESKeyType type) {
            switch(type) {
                case AESKeyType::AES_KEY128:
                    memcpy(dest, data, sizeof(char) * 16);
                    break;
                case AESKeyType::AES_KEY192:
                    memcpy(dest, data, sizeof(char) * 24);
                    break;
                case AESKeyType::AES_KEY256:
                    memcpy(dest, data, sizeof(char) * 32);
                    break;
            }
        }
};

/**
 * Implements AES encryption
 * @author Bryce Young April 12, 2021
 * */
class AESEngine : public CryptoEngine { 
    public:
        /**
         * AES Engine constructor
         * TRANSFERS OWNERSHIP of AES KEY
         * @param key a dynamically allocated AES key
         * */
        AESEngine(AESKey* key, bool forceSoftwareAES = false) 
            :key(key),
            forceSoftwareAES(forceSoftwareAES)
        {
        }

        ~AESEngine() {
            delete key;
        }

        int getOutputTextSize(int textSize);

        /**
         * AES implementation generating ciphertext
         * */
        void encyrptText(char* plainText, int plainTextSize, char* cipherText);

        /**
         * AES implementation inverting cipher process
         * */
        void decryptText(char* cipherText, int cipherTextSize, char* plainText);

        /**
         * returns whether this computer supports the hardware implementation of AES
         * */
        static bool checkAESHardwareSupport();

    private:
        AESKey* key;
        bool forceSoftwareAES;
};

#endif