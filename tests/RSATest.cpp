#include <iostream>

#include "RSAEngine.h"
#include "cassert"

void testRSANumberLSLLSLR() {
    std::cout << "Testing logical shifts\n";
    uint32_t start = 32;
    RSANumber n1(start);
    RSANumber n2 = n1 << 1;
    start <<= 1;

    assert(start == n2.getNum()[ARR_SIZE- 1]);

    while(start) {
        start >>= 1;
        n2 >>= 1;
        assert(start == n2.getNum()[ARR_SIZE- 1]);
    }

    start = 7;
    n2.getNum()[ARR_SIZE - 1] = start;
    assert(start == n2.getNum()[ARR_SIZE- 1]);

    for(int i = 0; i < 32; ++i) {
        start <<=1;
        n2 <<= 1;
        assert(start == n2.getNum()[ARR_SIZE - 1]);
    }

    uint32_t test = 7;
    n2 = n1 = RSANumber(test);
    n1 <<= 1556;

    n2 = n1;
    n2 >>= 1556;

    n1 >>= 1556;

    assert(n1.getNum()[ARR_SIZE - 1] == test);
    assert(n2.getNum()[ARR_SIZE - 1] == test);

    n2 <<= 1556;
    n2 <<= 66;
    n2 >>= 1556;
    n2 >>= 66;
    assert(n2.getNum()[ARR_SIZE - 1] == test);

    n1 = (n2 << 1556);
    n1 <<= 66;
    n1 >>= 1622;
    assert(n1.getNum()[ARR_SIZE - 1] == test);

    n1 = n2 = RSANumber(0);
    n1.getNum()[0] = 0xFFFFFFFF;

    n1 >>= ((ARR_SIZE - 1) * 32 + 16);
    assert(n1.getNum()[ARR_SIZE - 1] == 0x0000FFFF);

    n2 = n1 << 16;
    assert(n2.getNum()[ARR_SIZE - 1] == 0xFFFF0000);

    n2 <<= 8;
    assert(n2.getNum()[ARR_SIZE - 1] == 0xFF000000);
    assert(n2.getNum()[ARR_SIZE - 2] == 0x000000FF);

    //now let's try a really big number to make sure the zeros are being filled properly
    n2 = RSANumber(0);
    assert(n2.getNum()[ARR_SIZE - 1] == 0);
    assert(n2.getNum()[ARR_SIZE - 2] == 0);
    assert(n2.getNum()[ARR_SIZE - 3] == 0);
    assert(n2.getNum()[ARR_SIZE - 4] == 0);

    n2.getNum()[ARR_SIZE - 1] = 0xDEADBEEF;
    n2.getNum()[ARR_SIZE - 2] = 0x3F3F3F3F;
    n2.getNum()[ARR_SIZE - 3] = 0x11111111;
    
    n1 = n2 << 45;

    assert(n1.getNum()[ARR_SIZE - 1] == 0);
    assert(n1.getNum()[ARR_SIZE - 2] == 0xB7DDE000);
    assert(n1.getNum()[ARR_SIZE - 3] == 0xE7E7FBD5);
    assert(n1.getNum()[ARR_SIZE - 4] == 0x222227E7);
    assert(n1.getNum()[ARR_SIZE - 5] == 0x222);

    n1 <<= 166;

    n1 >>= (166 + 45);
    assert(n1.getNum()[ARR_SIZE - 1] == 0xDEADBEEF);
    assert(n1.getNum()[ARR_SIZE - 2] == 0x3F3F3F3F);
    assert(n1.getNum()[ARR_SIZE - 3] == 0x11111111);

    //shift value edge cases
    n1 = RSANumber(0xFFFFFFFF);
    n1 <<= 0x7000;

    for(int i = 0; i < ARR_SIZE; ++i) {
        assert(n1.getNum()[i] == 0);
    }

    //negative shifts are equivalent to shifting by 0
    n1 = RSANumber(0xFFFFFFFF);
    n1 >>= -1;

    for(int i = 0; i < ARR_SIZE - 1; ++i) {
        assert(n1.getNum()[i] == 0);
    }

    assert(n1.getNum()[ARR_SIZE - 1] == 0xFFFFFFFF);

    n1 <<= (32);
    assert(n1.getNum()[ARR_SIZE - 2] == 0xFFFFFFFF);

    n1 >>= (32);
    assert(n1.getNum()[ARR_SIZE - 1] == 0xFFFFFFFF);

    n1 <<= (sizeof(uint32_t) * 8 * (ARR_SIZE - 1));
    assert(n1.getNum()[0] == 0xFFFFFFFF);

    for(int i = 1; i < ARR_SIZE - 1; ++i) {
        assert(n1.getNum()[i] == 0);
    }

    std::cout << "Passed all logical shift tests :D\n";
}

void testRSAConstAssign() {
    std::cout << "Testing constructors and assignment operators\n";
    RSANumber n1(32);

    assert(n1[ARR_SIZE - 1] == 32);

    for(int i = 0; i < ARR_SIZE - 1; ++i) {
        assert(n1[i] == 0);
    }

    n1 = RSANumber(0xDEADBEEF);

    //make sure it's correct
    assert(n1[ARR_SIZE - 1] == 0xDEADBEEF);

    for(int i = 0; i < ARR_SIZE - 1; ++i) {
        assert(n1[i] == 0);
    }

    //test copy constructor
    RSANumber n2(n1);
    assert(n2[ARR_SIZE - 1] == 0xDEADBEEF);

    for(int i = 0; i < ARR_SIZE - 1; ++i) {
        assert(n2[i] == 0);
    }

    //test operator=
    RSANumber n3 = n2;
    assert(n3[ARR_SIZE - 1] == 0xDEADBEEF);

    for(int i = 0; i < ARR_SIZE - 1; ++i) {
        assert(n3[i] == 0);
    }

    //test operator chaining
    n1 = n2 = n3 = RSANumber(0xFFFFFFFF);
    assert(n1[ARR_SIZE - 1] == 0xFFFFFFFF);
    assert(n2[ARR_SIZE - 1] == 0xFFFFFFFF);
    assert(n3[ARR_SIZE - 1] == 0xFFFFFFFF);

    for(int i = 0; i < ARR_SIZE - 1; ++i) {
        assert(n1[i] == 0);
        assert(n2[i] == 0);
        assert(n3[i] == 0);
    }

    //test cases for numbers which include many many bits
    for(int i = 0; i < ARR_SIZE; ++i) {
        n1[i] = i;
    }

    //test copy constructor and operator= all at once
    n2 = RSANumber(n1);
    for(int i = 0; i < ARR_SIZE; ++i) {
        assert(n1[i] == i);
        assert(n2[i] == i);
    }

    std::cout << "All constructor and assignment tests passed\n";
}

void testRSANumberAssignment() {
    std::cout << "Testing assignment operators\n";
}

void testRSANumberComparators() {
    std::cout << "Testing RSA number comparisons\n";
}

void testRSANumberOperations() {
    uint32_t n1Int = 32;
    uint32_t n2Int = 64;
    RSANumber n1(n1Int);
    RSANumber n2(n2Int);

    std::cout << "Verifying correct values\n";
    for(int i = 0; i < ARR_SIZE - 1; ++i) {
        assert(n1.getNum()[i] == 0);
        assert(n2.getNum()[i] == 0);
    }

    assert(n1.getNum()[ARR_SIZE - 1] == n1Int);
    assert(n2.getNum()[ARR_SIZE - 1] == n2Int);

    //test assignment operator
    testRSANumberAssignment();

    //test shifting
    testRSANumberLSLLSLR();
}

int main() {
    testRSAConstAssign();
    testRSANumberOperations();
    std::cout << "All test cases passed successfully\n";
    return 0;
}