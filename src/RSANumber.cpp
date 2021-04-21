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

inline void rsaNumLSL(const RSANumber& num, int c, RSANumber& output) {
    if(c < 0) {
        c = 0;
    }
    else if(c > 8 * sizeof(uint32_t) * ARR_SIZE) {
        c = 8 * sizeof(uint32_t) * ARR_SIZE;
    }

	uint32_t overflow = 0;
    uint64_t tmp = 0;
    int count = c % (sizeof(uint32_t) * 8);
    int shifts = c / (sizeof(uint32_t) * 8);

    output = num;

    if(shifts) {
        for(int i = 0; i < ARR_SIZE - shifts; ++i) {
            output.value[i] = output.value[i + shifts];
        }

        memcpy(output.value + (ARR_SIZE - shifts), ZERO, sizeof(uint32_t) * shifts);
    }

	for(int i = ARR_SIZE - 1; i >= 0; --i) {
        tmp = output.value[i];
        tmp <<= count;
        output.value[i] = tmp;
        output.value[i] |= overflow;
        overflow = tmp >> (sizeof(uint32_t) * 8);
	}
}

inline void rsaNumLSR(const RSANumber& num, int c, RSANumber& output) {
    if(c < 0) {
        c = 0;
    }
    else if(c > 8 * sizeof(uint32_t) * ARR_SIZE) {
        c = 8 * sizeof(uint32_t) * ARR_SIZE;
    }

	uint32_t overflow = 0;
    uint64_t tmp = 0;
    int count = c % (sizeof(uint32_t) * 8);
    int shifts = c / (sizeof(uint32_t) * 8);

    output = num;

    if(shifts) {
        for(int i = ARR_SIZE - 1; i >= shifts; --i) {
            output.value[i] = output.value[i - shifts];
        }

        memcpy(output.value, ZERO, sizeof(uint32_t) * shifts);
    }

	for(int i = 0; i <= ARR_SIZE; ++i) {
        tmp = ((uint64_t)output.value[i] << (sizeof(uint32_t) * 8));
        tmp >>= count;
        output.value[i] = (tmp >> (sizeof(uint32_t) * 8));
        output.value[i] |= overflow;
        overflow = tmp & 0xFFFFFFFF;
	}
}

inline int rsaNumCmp(const RSANumber& n1, const RSANumber& n2) {
    for(int i = 0; i < ARR_SIZE; ++i) {
		uint32_t c = n1.value[i] - n2.value[i];

		if(c != 0) {
			return n1.value[i] > n2.value[i]? 1 : -1;
		}
	}

	return 0;
}

inline void rsaNumAdd(const RSANumber& n1, const RSANumber& n2, RSANumber& dest) {
	uint32_t carry = 0;
    uint64_t tmp = 0;

	for(int i = ARR_SIZE - 1; i >= 0; --i) {
		tmp = (uint64_t)n1.value[i] + (uint64_t)n2.value[i] + (uint64_t)carry;
		dest.value[i] = tmp & 0xFFFFFFFF;
		carry = tmp >> (sizeof(uint32_t) * 8);
	}
}

inline void rsaNumberNegate(const RSANumber n1, RSANumber& dest) {
    //take the compliment and add 1 all in a single step preferably
	uint32_t carry = 0;
    uint64_t tmp = (uint64_t)(~n1.value[ARR_SIZE - 1]) + (uint64_t)1;
    dest.value[ARR_SIZE - 1] = tmp & 0xFFFFFFFF;
    carry = tmp >> (sizeof(uint32_t) * 8);

	for(int i = ARR_SIZE - 2; i >= 0; --i) {
		tmp = (uint64_t)(~n1.value[i]) + (uint64_t)carry;
		dest.value[i] = tmp & 0xFFFFFFFF;
		carry = tmp >> (sizeof(uint32_t) * 8);
	}
}

//structured as n1 - n2
//n1 should be negated and added to n1
inline void rsaNumSub(const RSANumber& n1, const RSANumber& n2, RSANumber& dest) {
	uint32_t carry = 0;
    uint64_t tmp = 0;

    tmp = (uint64_t)(n1.value[ARR_SIZE - 1]) + (uint64_t)(~n2.value[ARR_SIZE - 1]) + (uint64_t)1;
    dest.value[ARR_SIZE - 1] = tmp & 0xFFFFFFFF;
    carry += tmp >> (sizeof(uint32_t) * 8);

	for(int i = ARR_SIZE - 2; i >= 0; --i) {
		tmp = (uint64_t)n1.value[i] + (uint64_t)(~n2.value[i]) + (uint64_t)carry;
		dest.value[i] = tmp & 0xFFFFFFFF;
		carry = tmp >> (sizeof(uint32_t) * 8);
	}
}

//Special thanks to wikipedia for this one XD
inline void rsaNumberDiv(RSANumber N, RSANumber D, RSANumber& q, RSANumber& r) {
    //compute n/m = m|-n
    //n is dividend, m is divisor
    //store remainder in mod
    q = 0;
    r = 0;

    //handle divide by zero
    if(D == 0) {
        return;
    }

    int dividendIndex = N.getMostSignificantBitIndex();

    for(int i = dividendIndex; i >= 0; --i) {
        r <<= 1;

        if(N.getBit(i)) {
            r.setBit(0);
        }

        if(r >= D) {
            r -= D;
            q.setBit(i);
        }
    }
}

void RSANumber::div(const RSANumber& N, const RSANumber& D, RSANumber& result, RSANumber& mod) {
    rsaNumberDiv(N, D, result, mod);
}

//if there is a faster way of doing this, I don't know of it
//with the efficient implementations of the copy constructor, assignment operator, shifts, and subtraction, this should be a relatively fast algorithm
//it tends to be fairly slow (a couple milliseconds) when calculating mod for very very large numbers
void rsaModulus(const RSANumber& a, const RSANumber& b, RSANumber& ret) {
    //this is still faster than integer division and getting the remainders!
	RSANumber x(b);
	RSANumber adiv2(a >> 1);
    ret = a;

    int xBits = x.getMostSignificantBitIndex();
    int adiv2Bits = adiv2.getMostSignificantBitIndex();

    if(adiv2Bits - xBits > 1) {
        x <<= (adiv2Bits - xBits - 1);
    }

	while(x <= adiv2) {
        x <<= 1;
	}

	while(ret >= b) {
		if(ret >= x) {
            ret -= x;
		}

        x >>= 1;
	}
}

RSANumber RSANumber::operator>>(int c) const {
    RSANumber ret;
    rsaNumLSR(*this, c, ret);
    return ret;
}

RSANumber RSANumber::operator<<(int c) const {
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

bool RSANumber::operator>(const RSANumber& num) const {
    return rsaNumCmp(*this, num) > 0;
}

bool RSANumber::operator<(const RSANumber& num) const {
    return rsaNumCmp(*this, num) < 0;
}

bool RSANumber::operator>=(const RSANumber& num) const {
    return rsaNumCmp(*this, num) >= 0;
}

bool RSANumber::operator<=(const RSANumber& num) const {
    return rsaNumCmp(*this, num) <= 0;
}

bool RSANumber::operator==(const RSANumber& num) const {
    return rsaNumCmp(*this, num) == 0;
}

bool RSANumber::operator!=(const RSANumber& num) const {
    return rsaNumCmp(*this, num) != 0;
}

RSANumber RSANumber::operator~() {
    RSANumber ret = *this;

    for(int i = 0; i < ARR_SIZE; ++i) {
        ret.value[i] = ~value[i];
    }

    return ret;
}

RSANumber RSANumber::operator-() {
    RSANumber ret;
    rsaNumberNegate(*this, ret);
    return ret;
}

RSANumber RSANumber::operator+(const RSANumber& num) const {
    RSANumber ret;
    rsaNumAdd(*this, num, ret);
    return ret;
}

RSANumber RSANumber::operator-(const RSANumber& num) const {
    RSANumber ret;
    rsaNumSub(*this, num, ret);
    return ret;
}

RSANumber& RSANumber::operator+=(const RSANumber& num) {
    rsaNumAdd(*this, num, *this);
    return *this;
}

RSANumber& RSANumber::operator-=(const RSANumber& num) {
    rsaNumSub(*this, num, *this);
    return *this;
}

RSANumber RSANumber::operator%(const RSANumber& num) const {
    RSANumber ret;
    rsaModulus(*this, num, ret);
    return ret;
}

RSANumber& RSANumber::operator%=(const RSANumber& num) {
    rsaModulus(*this, num, *this);
    return *this;
}

inline void rsaNumberOr(const RSANumber& n1, const RSANumber& n2, RSANumber& dest) {
    for(int i = 0; i < ARR_SIZE; ++i) {
        dest[i] = n1[i] | n2[i];
    }
}

inline void rsaNumberAnd(const RSANumber& n1, const RSANumber& n2, RSANumber& dest) {
    for(int i = 0; i < ARR_SIZE; ++i) {
        dest[i] = n1[i] & n2[i];
    }
}

inline void rsaNumberXor(const RSANumber& n1, const RSANumber& n2, RSANumber& dest) {
    for(int i = 0; i < ARR_SIZE; ++i) {
        dest[i] = n1[i] ^ n2[i];
    }
}

RSANumber RSANumber::operator|(const RSANumber& num) const {
    RSANumber ret;
    rsaNumberOr(*this, num, ret);
    return ret;
}

RSANumber RSANumber::operator&(const RSANumber& num) const {
    RSANumber ret;
    rsaNumberAnd(*this, num, ret);
    return ret;
}

RSANumber RSANumber::operator^(const RSANumber& num) const {
    RSANumber ret;
    rsaNumberXor(*this, num, ret);
    return ret;
}

RSANumber& RSANumber::operator|=(const RSANumber& num) {
    rsaNumberOr(*this, num, *this);
    return *this;
}

RSANumber& RSANumber::operator&=(const RSANumber& num) {
    rsaNumberAnd(*this, num, *this);
    return *this;
}

RSANumber& RSANumber::operator^=(const RSANumber& num) {
    rsaNumberXor(*this, num, *this);
    return *this;
}

/**
 * One of the rare instances where passing by value is more efficient.
 * */
inline void rsaNumberMul(RSANumber n, RSANumber m, RSANumber& ret) {
    int count = 0;
    ret = 0;

    int mostSignificantBit = m.getMostSignificantBitIndex();

    while(count <= mostSignificantBit) {
        if(m.getBit(count) == 1) {
            ret += (n << count);
        }

        count++;
    }

   /**
    * OLD: slower impl
    while(m.getMostSignificantBitIndex() >= 0) {
        if(m.getBit(0) == 1) {
            ret += (n << count);
        }

        count++;
        m >>= 1;
    }
    */
}

RSANumber RSANumber::operator*(const RSANumber& num) const {
    RSANumber ret;
    rsaNumberMul(*this, num, ret);
    return ret;
}

RSANumber RSANumber::operator/(const RSANumber& num) const {
    RSANumber ret;
    RSANumber mod;
    rsaNumberDiv(*this, num, ret, mod);
    return ret;
}

RSANumber& RSANumber::operator*=(const RSANumber& num) {
    rsaNumberMul(*this, num, *this);
    return *this;
}

RSANumber& RSANumber::operator/=(const RSANumber& num) {
    RSANumber mod;
    rsaNumberDiv(*this, num, *this, mod);
    return *this;
}

//https://www.geeksforgeeks.org/modular-exponentiation-power-in-modular-arithmetic/
RSANumber RSANumber::pow(RSANumber& y) const {
    RSANumber ret;
    return ret;
}

RSANumber& RSANumber::setPow(RSANumber& y) {
    return *this;
}