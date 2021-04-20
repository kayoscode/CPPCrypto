#include <random>

#include "SecureRandom.h"

typedef std::mt19937 rng;
std::random_device rd;
std::uniform_int_distribution<int> distribution(0, 255);

//MEH this isn't a secure random number generator but it will work for now. Let's fix this later
//TODO!!!! XD
//Probably a good idea to put the bytes through some kind of secure hashing algorithm
void generateRandomSequence(char* bytes, int len) {
    //create a new random generator
    rng random(rd());

    //generate n bytes of random data
    for(int i = 0; i < len; i++) {
        bytes[i] = distribution(random);
    }
}
