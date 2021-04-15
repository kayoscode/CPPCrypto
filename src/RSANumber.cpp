#include "RSAEngine.h"

bool millerRabinPrimeTest(int* value, int bits) {

}

void RSANumber::generatePrime(int bitCount) {
    int bits = bitCount / 2;

    generateRandomSequence((char*)value, (bits / 8) + (bits % 8 != 0));
}