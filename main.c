//
//  main.c
//  PRINCE-128
//
//  Created by Dare, Christopher E. (Assoc) on 6/1/16.
//  Copyright © 2016 Dare, Christopher E. (Assoc). All rights reserved.
//

#include "tests.h"
#include "prince.h"

int main(int argc, const char * argv[])
{
//    uint8_t in[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
//    uint8_t key[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
//    uint8_t subkey[8];
//
//    
//    printf("0x");
//    for (int8_t i = 7; i >=0; i--)
//    {
//        printf("%02x", in[i]);
//    }
//    printf("\n");
//    
//    keySchedule(key, subkey);
//
//    cipher(in, key, subkey);
//    printf("0x");
//    for (int8_t i = 7; i >=0; i--)
//    {
//        printf("%02x", in[i]);
//    }
//    printf("\n");
//    
//    decipher(in, key, subkey);
//    
//    printf("0x");
//    for (int8_t i = 7; i >=0; i--)
//    {
//        printf("%02x", in[i]);
//    }
//    printf("\n");

    testPRINCE128();
    return 0;
} // End main()
