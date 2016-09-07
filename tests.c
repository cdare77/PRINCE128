//
//  tests.c
//  PRINCE-128
//
//  Created by Dare, Christopher E. (Assoc) on 6/9/16.
//  Copyright © 2016 Dare, Christopher E. (Assoc). All rights reserved.
//

#include "tests.h"
#include "prince.h"


/* tests the cipher algorithm based off the test vectors given below"
 
 plaintext           k0                  k1          ciphertext
 0000000000000000 0000000000000000 0000000000000000 818665aa0d02dfda
 ffffffffffffffff 0000000000000000 0000000000000000 604ae6ca03c20ada
 0000000000000000 ffffffffffffffff 0000000000000000 9fb51935fc3df524
 0000000000000000 0000000000000000 ffffffffffffffff 78a54cbe737bb7ef
 0123456789abcdef 0000000000000000 fedcba9876543210 ae25ad3ca8fa9ccf
 */
void testEncryptionVerbose(uint8_t* state, uint8_t* Key, uint8_t* ctext, uint8_t round)
{
    uint8_t subkey[8];
    
    printf("ENCRYPTION TEST %d\n\t\t   plaintext:\t\t\tciphertext:\n___________________________________________ \n\t\t", round);
    printState(state);
    printf("\t");
    
    
    keySchedule(Key, subkey);
    cipher(state, Key, subkey);
    
    printState(state);
    
    if (blockCheck(state, ctext))
        printf("\n___________________________________________ \nPASSED\n\n\n");
    else
    {
        state = ctext;
        printf("\n___________________________________________ \nFAILED - expected (");
        printState(state);
        printf(")\n\n\n");
    } // end else-statement
    
} // end testEncryptionVerbose()

/* tests the decipher algorithm based off the test vectors given below
 
 plaintext           k0                  k1          ciphertext
 0000000000000000 0000000000000000 0000000000000000 818665aa0d02dfda
 ffffffffffffffff 0000000000000000 0000000000000000 604ae6ca03c20ada
 0000000000000000 ffffffffffffffff 0000000000000000 9fb51935fc3df524
 0000000000000000 0000000000000000 ffffffffffffffff 78a54cbe737bb7ef
 0123456789abcdef 0000000000000000 fedcba9876543210 ae25ad3ca8fa9ccf
 */
void testDecryptionVerbose(uint8_t * state, uint8_t* Key, uint8_t* ptext, uint8_t round)
{
    uint8_t subkey[8];
    
    
    printf("DECRYPTION TEST %d\n\t\t   ciphertext:\t\t\tplaintext:\n___________________________________________ \n\t\t", round);
    printState(state);
    printf("\t");
    
    keySchedule(Key, subkey);
    decipher(state, Key, subkey);
    
    printState(state);
    
    if (blockCheck(state, ptext))
        printf("\n___________________________________________ \nPASSED\n\n\n");
    else
    {
        state = ptext;
        printf("\n___________________________________________ \nFAILED - expected (");
        printState(state);
        printf(")\n\n\n");
    } // End else-statement
    
} // End testDecryptVerbose

// tests the encryption and decryption against each test vector
void testPRINCE128()
{
    uint8_t in[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t key[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t ctext[] = {0x18, 0x68, 0x56, 0xaa, 0xd0, 0x20, 0xfd, 0xad};
    
    testEncryptionVerbose(in, key, ctext, 1);
    
    in[0] = 0xff;
    in[1] = 0xff;
    in[2] = 0xff;
    in[3] = 0xff;
    in[4] = 0xff;
    in[5] = 0xff;
    in[6] = 0xff;
    in[7] = 0xff;
    
    ctext[0] = 0x06;
    ctext[1] = 0xa4;
    ctext[2] = 0x6e;
    ctext[3] = 0xac;
    ctext[4] = 0x30;
    ctext[5] = 0x2c;
    ctext[6] = 0xa0;
    ctext[7] = 0xad;
    
    testEncryptionVerbose(in, key, ctext, 2);
    
    key[0] = 0xff;
    key[1] = 0xff;
    key[2] = 0xff;
    key[3] = 0xff;
    key[4] = 0xff;
    key[5] = 0xff;
    key[6] = 0xff;
    key[7] = 0xff;
    
    in[0] = 0x00;
    in[1] = 0x00;
    in[2] = 0x00;
    in[3] = 0x00;
    in[4] = 0x00;
    in[5] = 0x00;
    in[6] = 0x00;
    in[7] = 0x00;
    
    ctext[0] = 0xf9;
    ctext[1] = 0x5b;
    ctext[2] = 0x91;
    ctext[3] = 0x53;
    ctext[4] = 0xcf;
    ctext[5] = 0xd3;
    ctext[6] = 0x5f;
    ctext[7] = 0x42;
    
    testEncryptionVerbose(in, key, ctext, 3);
    
    key[0] = 0x00;
    key[1] = 0x00;
    key[2] = 0x00;
    key[3] = 0x00;
    key[4] = 0x00;
    key[5] = 0x00;
    key[6] = 0x00;
    key[7] = 0x00;
    key[8] = 0xff;
    key[9] = 0xff;
    key[10] = 0xff;
    key[11] = 0xff;
    key[12] = 0xff;
    key[13] = 0xff;
    key[14] = 0xff;
    key[15] = 0xff;
    
    in[0] = 0x00;
    in[1] = 0x00;
    in[2] = 0x00;
    in[3] = 0x00;
    in[4] = 0x00;
    in[5] = 0x00;
    in[6] = 0x00;
    in[7] = 0x00;
    
    ctext[0] = 0x87;
    ctext[1] = 0x5a;
    ctext[2] = 0xc4;
    ctext[3] = 0xeb;
    ctext[4] = 0x37;
    ctext[5] = 0xb7;
    ctext[6] = 0x7b;
    ctext[7] = 0xfe;
    
    testEncryptionVerbose(in, key, ctext, 4);
    
    key[0] = 0x00;
    key[1] = 0x00;
    key[2] = 0x00;
    key[3] = 0x00;
    key[4] = 0x00;
    key[5] = 0x00;
    key[6] = 0x00;
    key[7] = 0x00;
    key[8] = 0xef;
    key[9] = 0xcd;
    key[10] = 0xab;
    key[11] = 0x89;
    key[12] = 0x67;
    key[13] = 0x45;
    key[14] = 0x23;
    key[15] = 0x01;
    
    in[0] = 0x10;
    in[1] = 0x32;
    in[2] = 0x54;
    in[3] = 0x76;
    in[4] = 0x98;
    in[5] = 0xba;
    in[6] = 0xdc;
    in[7] = 0xfe;
    
    ctext[0] = 0xea;
    ctext[1] = 0x52;
    ctext[2] = 0xda;
    ctext[3] = 0xc3;
    ctext[4] = 0x8a;
    ctext[5] = 0xaf;
    ctext[6] = 0xc9;
    ctext[7] = 0xfc;
    
    testEncryptionVerbose(in, key, ctext, 5);
    
    in[0] = 0x18;
    in[1] = 0x68;
    in[2] = 0x56;
    in[3] = 0xaa;
    in[4] = 0xd0;
    in[5] = 0x20;
    in[6] = 0xfd;
    in[7] = 0xad;
    
    key[0] = 0x00;
    key[1] = 0x00;
    key[2] = 0x00;
    key[3] = 0x00;
    key[4] = 0x00;
    key[5] = 0x00;
    key[6] = 0x00;
    key[7] = 0x00;
    key[8] = 0x00;
    key[9] = 0x00;
    key[10] = 0x00;
    key[11] = 0x00;
    key[12] = 0x00;
    key[13] = 0x00;
    key[14] = 0x00;
    key[15] = 0x00;
    
    uint8_t ptext[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    
    testDecryptionVerbose(in, key, ptext, 1);
    
    in[0] = 0x06;
    in[1] = 0xa4;
    in[2] = 0x6e;
    in[3] = 0xac;
    in[4] = 0x30;
    in[5] = 0x2c;
    in[6] = 0xa0;
    in[7] = 0xad;
    
    ptext[0] = 0xff;
    ptext[1] = 0xff;
    ptext[2] = 0xff;
    ptext[3] = 0xff;
    ptext[4] = 0xff;
    ptext[5] = 0xff;
    ptext[6] = 0xff;
    ptext[7] = 0xff;
    
    
    testDecryptionVerbose(in, key, ptext, 2);
    
    ptext[0] = 0x00;
    ptext[1] = 0x00;
    ptext[2] = 0x00;
    ptext[3] = 0x00;
    ptext[4] = 0x00;
    ptext[5] = 0x00;
    ptext[6] = 0x00;
    ptext[7] = 0x00;
    
    in[0] = 0xf9;
    in[1] = 0x5b;
    in[2] = 0x91;
    in[3] = 0x53;
    in[4] = 0xcf;
    in[5] = 0xd3;
    in[6] = 0x5f;
    in[7] = 0x42;
    
    key[0] = 0xff;
    key[1] = 0xff;
    key[2] = 0xff;
    key[3] = 0xff;
    key[4] = 0xff;
    key[5] = 0xff;
    key[6] = 0xff;
    key[7] = 0xff;
    
    testDecryptionVerbose(in, key, ptext, 3);
    
    ptext[0] = 0x00;
    ptext[1] = 0x00;
    ptext[2] = 0x00;
    ptext[3] = 0x00;
    ptext[4] = 0x00;
    ptext[5] = 0x00;
    ptext[6] = 0x00;
    ptext[7] = 0x00;
    
    in[0] = 0x87;
    in[1] = 0x5a;
    in[2] = 0xc4;
    in[3] = 0xeb;
    in[4] = 0x37;
    in[5] = 0xb7;
    in[6] = 0x7b;
    in[7] = 0xfe;
    
    key[0] = 0x00;
    key[1] = 0x00;
    key[2] = 0x00;
    key[3] = 0x00;
    key[4] = 0x00;
    key[5] = 0x00;
    key[6] = 0x00;
    key[7] = 0x00;
    key[8] = 0xff;
    key[9] = 0xff;
    key[10] = 0xff;
    key[11] = 0xff;
    key[12] = 0xff;
    key[13] = 0xff;
    key[14] = 0xff;
    key[15] = 0xff;
    
    testDecryptionVerbose(in, key, ptext, 4);
    
    ptext[0] = 0x10;
    ptext[1] = 0x32;
    ptext[2] = 0x54;
    ptext[3] = 0x76;
    ptext[4] = 0x98;
    ptext[5] = 0xba;
    ptext[6] = 0xdc;
    ptext[7] = 0xfe;
    
    in[0] = 0xea;
    in[1] = 0x52;
    in[2] = 0xda;
    in[3] = 0xc3;
    in[4] = 0x8a;
    in[5] = 0xaf;
    in[6] = 0xc9;
    in[7] = 0xfc;
    
    key[0] = 0x00;
    key[1] = 0x00;
    key[2] = 0x00;
    key[3] = 0x00;
    key[4] = 0x00;
    key[5] = 0x00;
    key[6] = 0x00;
    key[7] = 0x00;
    key[8] = 0xef;
    key[9] = 0xcd;
    key[10] = 0xab;
    key[11] = 0x89;
    key[12] = 0x67;
    key[13] = 0x45;
    key[14] = 0x23;
    key[15] = 0x01;
    
    testDecryptionVerbose(in, key, ptext, 5);

}

// Checks each element in a given block to compare equality to the state
int blockCheck(uint8_t* state, uint8_t* text)
{
    for (int i = 0; i < 8; i++)
    {
        if (state[i] != text[i])
        {
            return 0;
        } // End if-statement
    } // End for-loop
    return 1;
} // End blockCheck()

/* Prints the contents of the state in Big-Endian order
 */
void printState(uint8_t* state)
{
    int8_t i;
    
    printf("0x");
    for (i = 0; i <8; i++) {
        printf("%x", state[i] & 0x0F);
        printf("%x", state[i] >> 4);
    } // End for-loop
} // End printState()
