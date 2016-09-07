//
//  tests.h
//  PRINCE-128
//
//  Created by Dare, Christopher E. (Assoc) on 6/9/16.
//  Copyright © 2016 Dare, Christopher E. (Assoc). All rights reserved.
//

#ifndef tests_h
#define tests_h

#include <stdint.h>
#include <stdio.h>

void testEncryptionVerbose(uint8_t* state, uint8_t* Key, uint8_t* ctext, uint8_t round);
void testDecryptionVerbose(uint8_t * state, uint8_t* Key, uint8_t* ptext, uint8_t round);
void testPRINCE128();
int blockCheck(uint8_t* state, uint8_t* text);
void printState(uint8_t* state);

#endif /* tests_h */
