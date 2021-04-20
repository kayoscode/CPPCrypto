#include "RSAEngine.h"
#include <iostream>

uint32_t ZERO[ARR_SIZE] = { 0 };

//determines with a high degree of accuracy if a number is prime using the millerRabinPrimality test
//assumes:
//1. The input number is greater than 2
//2. The input number is odd
//@return the return is not guaranteed to be correct! It's just to a high degree of probatilitic accuracy
//N may be written as 2^s*d + 1 where s and d are positive integers and d is odd
//find number such that a^d mod n == 1 or a^2^(r*d) mod n == -1
bool millerRabinPrimeTest(int* value, int bits) {
    int k = 1;

    for(int i = 0; i < k; i++) {
        //pick a random number in the range 2, n-2
    }

    return true;
}

void RSANumber::generatePrime(int bitCount) {
    int bits = bitCount / 2;

    generateRandomSequence((char*)value, (bits / 8) + (bits % 8 != 0));

    //while(!millerRabinPrimeTest(value, bits));

    //the number should now be prime, but we have to test it for real, just once because otherwise the entire alrogithm will fail!
}

RSANumber::RSANumber(uint32_t value) {
    this->value[ARR_SIZE - 1] = value;
}

inline void rsaNumLSL(RSANumber& num, int c, RSANumber& output) {
    if(c < 0) {
        c = 0;
    }
    else if(c > 8 * sizeof(uint32_t) * ARR_SIZE) {
        c = 8 * sizeof(uint32_t) * ARR_SIZE;
    }

	uint32_t overflow = 0;
    int count = c % 32;
    int shifts = c / 32;

    output = num;

    if(shifts) {
        for(int i = 0; i < ARR_SIZE - shifts; ++i) {
            output.value[i] = output.value[i + shifts];
        }

        memcpy(output.value + (ARR_SIZE - shifts), ZERO, sizeof(uint32_t) * shifts);
    }

	for(int i = ARR_SIZE - 1; i >= 0; --i) {
        uint64_t tmp = output.value[i];
        tmp <<= count;
        output.value[i] = tmp;
        output.value[i] |= overflow;
        overflow = tmp >> 32;
	}
}

inline void rsaNumLSR(RSANumber& num, int c, RSANumber& output) {
    if(c < 0) {
        c = 0;
    }
    else if(c > 8 * sizeof(uint32_t) * ARR_SIZE) {
        c = 8 * sizeof(uint32_t) * ARR_SIZE;
    }

	uint32_t overflow = 0;
    int count = c % 32;
    int shifts = c / 32;

    output = num;

    if(shifts) {
        for(int i = ARR_SIZE - 1; i >= shifts; --i) {
            output.value[i] = output.value[i - shifts];
        }

        memcpy(output.value, ZERO, sizeof(uint32_t) * shifts);
    }

	for(int i = 0; i <= ARR_SIZE; ++i) {
        uint64_t tmp = ((uint64_t)output.value[i] << 32);
        tmp >>= count;
        output.value[i] = (tmp >> 32);
        output.value[i] |= overflow;
        overflow = tmp & 0xFFFFFFFF;
	}
}

RSANumber RSANumber::operator>>(int c) {
    RSANumber ret;
    rsaNumLSR(*this, c, ret);
    return ret;
}

RSANumber RSANumber::operator<<(int c) {
    RSANumber ret;
    rsaNumLSL(*this, c, ret);
    return ret;
}

RSANumber& RSANumber::operator>>=(int c) {
    rsaNumLSR(*this, c, *this);
    return *this;
}

RSANumber& RSANumber::operator<<=(int c) {
    rsaNumLSL(*this, c, *this);
    return *this;
}

bool RSANumber::operator>(const RSANumber& num) {
    return false;
}

bool RSANumber::operator<(const RSANumber& num) {
    return false;
}

bool RSANumber::operator>=(const RSANumber& num) {
    return false;
}

bool RSANumber::operator<=(const RSANumber& num) {
    return false;
}

bool RSANumber::operator==(const RSANumber& num) {
    return false;
}

RSANumber RSANumber::operator+(const RSANumber& num) {
    RSANumber ret;
    return ret;
}

RSANumber RSANumber::operator-(const RSANumber& num) {
    RSANumber ret;
    return ret;
}

RSANumber& RSANumber::operator+=(const RSANumber& num) {
    return *this;
}

RSANumber& RSANumber::operator-=(const RSANumber& num) {
    return *this;
}

RSANumber RSANumber::operator%(const RSANumber& num) {
    RSANumber ret;
    return ret;
}

RSANumber& RSANumber::operator%=(const RSANumber& num) {
    return *this;
}

