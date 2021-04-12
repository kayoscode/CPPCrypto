#ifndef INCLUDE_RSAENGINE_H
#define INCLUDE_RSAENGINE_H

#include "CPPCrypto.h"

/**
 * RSA encryption impl
 * @author Bryce Young April 12, 2021
 * */
class RSAEngine : CryptoEngine {
    public:
        RSAEngine() {
        }

        ~RSAEngine(){
        }

        /**
         * RSA implementation generating ciphertext
         * */
        void encyrptText(const std::string& text, std::string& cipherText);

        /**
         * RSA implementation inverting cipher process
         * */
        void decryptText(const std::string& text, std::string& plainText);

    private:
};

#endif