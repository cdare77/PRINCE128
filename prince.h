//
//  prince.h
//  PRINCE-128
//
//  Created by Dare, Christopher E. (Assoc) on 6/9/16.
//  Copyright © 2016 Dare, Christopher E. (Assoc). All rights reserved.
//

#ifndef prince_h
#define prince_h

#include <stdint.h>

/*****************************************************************************/
/* Function Declarations:                                                    */
/*****************************************************************************/
void cipher(uint8_t* state, uint8_t* Key, uint8_t* subkey);
void decipher(uint8_t* state, uint8_t* Key, uint8_t* subkey);
void keySchedule(uint8_t* Key, uint8_t* subkey);

#endif /* prince_h */
