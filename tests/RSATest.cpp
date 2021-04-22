#include <iostream>

#include "RSAEngine.h"
#include "cassert"

void testRSANumberLSLLSLR() {
    std::cout << "Testing logical shifts\n";

    uint32_t start = 32;
    RSANumber n1(start);
    RSANumber n2 = n1 << 1;
    start <<= 1;

    assert(start == n2.getNum()[ARR_SIZE - 1]);

    while(start) {
        start >>= 1;
        n2 >>= 1;
        assert(start == n2.getNum()[ARR_SIZE - 1]);
    }

    start = 7;
    n2.getNum()[ARR_SIZE - 1] = start;
    assert(start == n2.getNum()[ARR_SIZE - 1]);

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
    //going out of range of the integer
    n1 <<= sizeof(uint32_t) * 8 * ARR_SIZE * 4;

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

void testRSANumberComparators() {
    std::cout << "Testing RSA number comparisons\n";
    RSANumber n1(0x1);
    RSANumber n2(0x1);

    //at this point, n2 should be exactly equal to n1
    assert(n1 == n1);
    assert(n1 == n2);
    assert(n1 < n2 == false);
    assert(n1 > n2 == false);
    assert(n1 >= n2);
    assert(n1 <= n2);
    assert(n1 != n2 == false);

    n1 = RSANumber(0xFFFFFFFF);
    n2 = RSANumber(0x7FFFFFFF);
    n2 <<= 1;

    //n1 should be strictly greater than n2 
    assert(n1 != n2);
    assert(n1 == n2 == false);
    assert(n1 <= n2 == false);
    assert(n1 < n2 == false);
    assert(n1 >= n2);
    assert(n1 > n2);

    n1 <<= 587;
    n2 <<= 700;

    //now n2 should be greater than n1
    assert(n1 != n2);
    assert(n1 == n2 == false);
    assert(n2 > n1 && n2 >= n1);
    assert(n1 <= n2 && n1 < n2);

    n2 = RSANumber(0xFFFFFFFF);
    n2 <<= 587;

    //again they should be equal
    assert(n1 == n2);
    assert(n1 >= n2 && n1 <= n2);
    assert(n1 < n2 == false);
    assert(n1 > n2 == false);
    assert(n1 != n2 == false);
    assert(n2 < n1 == false);
    assert(n2 > n1 == false);

    std::cout << "Passed all comparison test cases\n";
}

void testRSANumberCompliment() {
    std::cout << "Testing RSA number compliment and bit manipulation\n";
    //test compliment

    RSANumber n1(1);
    assert(n1[ARR_SIZE - 1] == 1);

    RSANumber n2 = ~n1;
    assert(n1[ARR_SIZE - 1] == 1);

    ~n2;
    for(int i = 0; i < ARR_SIZE - 1; ++i) {
        assert(n2[i] == 0xFFFFFFFF);
    }

    assert(n2[ARR_SIZE - 1] == ~1);

    //test bit setting and getting while were here
    n2 = ~n2;
    for(int i = 0; i < ARR_SIZE - 1; ++i) {
        assert(n2[i] == 0);
    }

    assert(n2[ARR_SIZE - 1] == 1);

    n2.setBit(1);
    assert(n2[ARR_SIZE - 1] == 3);
    n2.clearBit(1);
    n2.clearBit(0);
    assert(n2[ARR_SIZE - 1] == 0);

    n1 = ~n2;
    n1.setBit(62);
    n1.setBit(34);

    for(int i = 0; i < ARR_SIZE; ++i) {
        assert(n1[i] == 0xFFFFFFFF);
    }

    n1.clearBit(64);

    assert(n1.getBit(64) != true);
    assert(n1.getBit(63) == true);
    assert(n1.getBit(65) == true);

    n1.setBit(64);
    assert(n1.getBit(64) && n1.getBit(63) && n1.getBit(65));

    //test bounds overflowing
    //expected behavior: do not change anything
    n1 = RSANumber(0);
    n1.setBit(ARR_SIZE * sizeof(uint32_t) * 8 + 1000);
    n1.setBit(ARR_SIZE * sizeof(uint32_t) * 8 + 2000);

    assert(n1.getBit(ARR_SIZE * sizeof(uint32_t) * 8 + 1000) == false);
    assert(n1.getBit(ARR_SIZE * sizeof(uint32_t) * 8 + 2000) == false);

    for(int i = 0; i < ARR_SIZE; ++i) {
        assert(n1[i] == 0);
    }

    std::cout << "Compliment operator and bit manipulation tests passed\n";
}

void testRSANumberAdditionLogicalOps() {
    std::cout << "Testing addition and logical operators\n";

    //test basic addition arithmetic
    RSANumber n1(1);
    RSANumber n2(7);
    n1 += n2;

    assert(n1 == RSANumber(8));
    n1 += RSANumber(0xFF);
    assert(n1 == RSANumber(8 + 0xFF));

    //test basic carrying functionlity
    //NOTE: if this fails, it could also be the shifting at fault, but considering that's already been tested at this point, it's less likely
    n1 = RSANumber(1);
    RSANumber max(1);
    RSANumber curr(1);
    max <<= 192;

    while(n1 < max) {
        n1 += n1;
        curr <<= 1;
        assert(n1 == curr);
    }

    //test addition with large carry and implicit casting
    n1 = 0xFFFFFFFF;
    n1 += 1;

    assert(n1[ARR_SIZE - 2] == 1);
    assert(n1[ARR_SIZE - 1] == 0);

    n1.clearBit(32);
    assert(n1 == 0);

    //TEST negations
    n1 = 1;
    n1 = -n1;

    assert(n1[ARR_SIZE - 1] == 0xFFFFFFFF);
    n1 = -n1;
    assert(n1[ARR_SIZE - 1] == 1);

    //TODO: test subtraction
    n1 = 2;
    n1 -= 1;
    assert(n1 == 1);

    n1 = 0;
    n1 -= 1;

    assert(n1.isNegative());

    for(int i = 0; i < ARR_SIZE; ++i) {
        assert(n1[i] == 0xFFFFFFFF);
    }
    n1 -= 5;

    assert(-n1 == 6);
    n1 <<= 80;
    n1 = -n1;

    //testing to make sure the result of -6 shifted left then negated is the same
    //result as 6 shifted left 
    //only the 81st and 82nd bit should be set
    assert(n1.getBit(81) && n1.getBit(82));
    n1.clearBit(81);
    n1.clearBit(82);
    assert(n1 == 0);

    n1 = 0;
    //TEST LOGICAL OPERATORS
    for(int i = 0; i < ARR_SIZE; ++i) {
        n1 = n1 | (RSANumber(1) << (32 * i));
    }

    n2 = n1;
    n2 <<= 1;
    n1 |= n2;

    for(int i = 0; i < ARR_SIZE; ++i) {
        assert(n1[i] == 3);
    }

    //test xor
    n2 >>= 1;
    n1 ^= n2;

    for(int i = 0; i < ARR_SIZE; ++i) {
        assert(n1[i] == 2);
    }

    //test and
    n2 <<= 1;
    n1 &= n2;

    for(int i = 0; i < ARR_SIZE; ++i) {
        assert(n1[i] == 2);
    }

    n2 >>= 1;
    n1 &= n2;

    for(int i = 0; i < ARR_SIZE; ++i) {
        assert(n1[i] == 0);
    }

    assert(n1 + n2 == n2 + n1);

    //ensure associativity
    RSANumber expectedResult = -(n1 + n2);
    assert((n1 + n2) + expectedResult == (expectedResult + n1) + n2 && (n1 + n2) + expectedResult == (expectedResult + n2) + n1);

    std::cout << "Addition and logical operator tests passed\n";
}

void testRSANumberModulusOperation() {
    std::cout << "Testing RSA modulus\n";

    //test the most significant bit index
    RSANumber n1(0);
    assert(n1.getMostSignificantBitIndex() == -1);
    n1 = 1;
    assert(n1.getMostSignificantBitIndex() == 0);
    n1 <<= 64;
    assert(n1.getMostSignificantBitIndex() == 64);
    //NOTE: this one can fail if there is a problem with addition as well!
    n1 += n1;
    assert(n1.getMostSignificantBitIndex() == 65);

    n1 = 33;
    RSANumber n2(64);
    RSANumber mod;

    assert(n1 % n2 == 33);
    n1 %= n2;
    assert(n1 == 33);

    n2 >>= 1;
    assert(n1 % n2 == 1);

    for(int i = 0; i < ARR_SIZE; ++i) {
        n1[i] = i;
    }

    n2 = 2;
    //make sure the number is odd
    n1.setBit(0);
    mod = n1 % n2;
    assert(n1.getBit(0));
    assert(mod == 1);

    //make sure the number is even
    n1.clearBit(0);
    mod = n1 % n2;
    assert(n1.getBit(0) == false);
    assert(mod == 0);

    //one modulus test with two very big integers
    n1 = 0;
    n1[ARR_SIZE - 1] = 0xDEADBEEF;
    n1[ARR_SIZE - 2] = 0x11111111;
    n1[ARR_SIZE - 3] = 0xFFFFFFFF;
    n1[ARR_SIZE - 4] = 0x12345678;

    n2[ARR_SIZE - 1] = 0x11111111;
    n2[ARR_SIZE - 2] = 0x11111111;
    n2[ARR_SIZE - 3] = 0x11111111;
    n2[ARR_SIZE - 4] = 0x11111111;
    n2 >>= 1;

    std::cout << "Calculating big modulus\n";
    n1.printBinary();
    std::cout << "%\n";
    n2.printBinary();

    mod = n1 % n2;
    mod.printBinary();

    std::cout << "Expected:\n00000001001000110100010101100111111011101110111011101110111011100000000000000000000000000000000011001101100111001010110111011111\n";
    RSANumber test;
    test.setFromBinary("1001000110100010101100111111011101110111011101110111011100000000000000000000000000000000011001101100111001010110111011111");
    assert(test == mod);

    mod = n2 % n1;
    assert(mod == n2);

    //zero mod test
    n1 = n2 = 10;
    n1[0] = 100;
    n2[0] = 100;
    assert(n1 % n2 == 0);
    assert(n1 % n1 == 0);
    assert(n2 % n2 == 0);

    std::cout << "RSA modulus tests passed\n";
}

void testRSANumberMultiplicationOperaton() {
    RSANumber n1(10), n2(10), result;

    result = n1 * n2;
    assert(result[ARR_SIZE - 1] == 100);

    //test with much larger number
    RSANumber expectedResult;
    n1.setFromBinary("1001010100000010111110010000000000");
    n2.setFromBinary("1011011101110111101111100111111001");
    expectedResult.setFromBinary("1101010110010101101001101000010011100001000010101001100010000000000");

    n1 *= n2;
    n1.printBinary();
    expectedResult.printBinary();
    assert((n1 == expectedResult) == true);

    //test with even larger numbers
    n2.setFromBinary("11001110101101100100010000111001000100001100110000010100010101110101010011110100101010110011101");
    n1.setFromBinary("1000000000010000001001001100110111100");
    expectedResult.setFromBinary("11001110110100000101011001110001010101001100011001110101010111000000100111010101100100010010101100011011111011101011011010001001100");

    n1.printBinary();
    std::cout << "*\n";
    n2.printBinary();
    std::cout << "=\n";
    std::cout << "0000000000000000000000000000011001110110100000101011001110001010101001100011001110101010111000000100111010101100100010010101100011011111011101011011010001001100\n";

    result = n1 * n2;

    std::cout << "Expected result:\n";
    expectedResult.printHex();
    std::cout << "Actual result: \n";
    result.printHex();

    assert(result == expectedResult);

    //test even larger numbers as the final test to be sure
    n1.setFromBinary("1010101011111111111111111111111111111111000000000000000000000001101010101010101010111101010101010001001010010101000001010101010101010100010010100100101010101000000010010100010101010010010101010111101");
    n2.setFromBinary("11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111110000000000000000000000000101100100101001100110101100000000000000000000000000000000000000000000000001111111111111111111111111111111111111111100000000000000000001101010101010101010101001010101010101010101010101000100100100000100100100100101011");
    expectedResult.setFromBinary("101010101111111111111111111111111111111100000000000000000000000110101010101010101011110101010101000100101001010001011010010101010101010010000101110110100111001001100111100000110100111010000001001000100111111110011101011111100001000001000110101101001000000010111001011100110011101010111000101000101011100111101010001101100111001100011000011010100010010010110101100111001010010111111111101000100111100111001001101110110000000010110011111010011111001011101011110001111001001101010000110100010111100110101110101101101001010111010111100101000001001010111111");
    RSANumber ans = n1 * n2;

    assert(expectedResult == ans);

    //ensure commutivity
    (n2 * n1).printHex();
    (n1 * n2).printHex();
    assert(n1 * n2 == n2 * n1);

    //ensure associativity
    assert((n1 * n2) * expectedResult == (expectedResult * n1) * n2 && (n1 * n2) * expectedResult == (expectedResult * n2) * n1);

    //TEST DIVISION
    n1 = 16;
    n2 = 4;
    n1 /= n2;
    std::cout << "Division result\n";
    n1.printBinary();
    assert(n1 == 4);

    n1 = 90;
    n2 = 30;
    n1 /= n2;
    std::cout << "Division result\n";
    n1.printBinary();
    assert(n1 == 3);

    n1 = 20;
    n2 = 4;
    n1 /= n2;
    std::cout << "Division result\n";
    n1.printBinary();

    n1.setFromBinary("11010111110100010011");
    n2.setFromBinary("1010");
    expectedResult.setFromBinary("10101100101001110");

    RSANumber integer = n1 / n2;
    std::cout << "Division result\n";
    integer.printBinary();

    assert(integer == expectedResult);

    n1 = 8;
    n2 = RSANumber(1);
    n1 /= n2;
    assert(n1 == 8);

    //very big numbers for testing
    n1.setFromBinary("1000111001000001000001111100101001011101000100010100100111011101110111011100011011111101000011011111100000111001000000000010000001001001100110111100");
    n2.setFromBinary("11001110101101100100010000111001000100001100110000010100010101110101010011110100101010110011101");
    expectedResult.setFromBinary("10110000001011000011110101100000100100010000011100001");
    n1 /= n2;
    n1.printBinary();
    assert(n1 == expectedResult);

    n1.printDecimal();
    n1.printOctal();
    expectedResult.printHex();
}

void testRSANumberModExp() {
    std::cout << "Testing modular exponentiation\n";
    RSANumber base;
    RSANumber exp;
    RSANumber mod;
    RSANumber result;
    RSANumber expectedResult;

    base.setFromBinary("1000111001000001000001111100101001011101000100010100100111011101110111011100011011111101000011011111100000111001000000000010000001001001100110111100");
    exp.setFromBinary("1010001010100101001000000100100101000101010000100100100100010100001010001010100100100100101010000000100010101001001001010001000010001001001010000101001010101010010101001001010010100100001000101000");
    mod.setFromBinary("101010111111111111111111111111111111111111110010010100100001111111111111111111111111111111110000001010010111000010101010101011111");
    expectedResult.setFromBinary("100100111000000101111111000010111100010111010110111011011001110010000110101011101001001110011101101011100101111010100100101001010");

    RSANumber::expMod(base, exp, mod, result);
    std::cout << "Result\n";
    result.printDecimal();
    std::cout << "Expected\n";
    expectedResult.printDecimal();
    assert(result == expectedResult);
}

void testRSANumberOperations() {
    //make sure numbers can be assigned and constructed properly
    testRSAConstAssign();

    //test shifting
    testRSANumberLSLLSLR();

    //test comparators
    testRSANumberComparators();

    //test negation and stuff
    testRSANumberCompliment();

    //test addition and subtraction
    testRSANumberAdditionLogicalOps();

    //test modulus arithmetic
   testRSANumberModulusOperation();

    //test multiplication arithmetic
    testRSANumberMultiplicationOperaton();

    //make sure fast mod expoentiation works properly
    testRSANumberModExp();
}

int main() {
    testRSANumberOperations();
    std::cout << "All test cases passed successfully\n";
    return 0;
}