#include <stdio.h>

/*
after working on this for a period of time, this is not going to work out. 

going to write real code below that will actually pull out a bit of a string at any certain time
typedef struct {
    unsigned char bit : 1;
} bit;

typedef struct {
    unsigned char nibble : 4;
} nibble;


union betterByte {
    bit bits[8];
    // unsigned long long byte;
    //nibble nibbles[2];
};

typedef struct {
    union betterByte blockBytes[16];
} block;

int main() {

    union betterByte byte1;
    printf("%d\n", sizeof(byte1));

    for (int i = 0; i < 8; i++) {
        byte1.bits[i].bit = 0x01;
        printf("%d\n", byte1.bits[i].bit);
    }
    //printf("\n%d\n", byte1.byte);
}

*/

/* bytes are returned in right-to-left. So the most right bit is bit 0 (also called the Least Significant Bit).
   similarly, the left most bit is bit 7 (also called the most significant bit)
*/

unsigned char getBit(unsigned char* byte, unsigned char bitValue) {
    if (bitValue > 7 || bitValue < 0) {
        return -1;
    }
    unsigned char byteValue = *byte;
    unsigned char mask = 1 << bitValue;
    unsigned char returnByte = (byteValue & mask) >> bitValue;
    return returnByte;
}


int main() {

    unsigned char byte = 0x0F;
    for (int i = 0; i < 8; i++) {
        unsigned char byte2 = getBit(&byte, i);
        printf("%d: %d\n", i, byte2);
    }

    //printf("\n%d\n", byte1.byte);
}