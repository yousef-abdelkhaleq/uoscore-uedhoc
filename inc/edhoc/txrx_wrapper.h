/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/
#ifndef EDHOC_TXRX_WRAPPER_H
#define EDHOC_TXRX_WRAPPER_H

#include "common/byte_array.h"

/**
 * @brief   The user should call inside this function its send function. 
 * @param   data pointer to the data to be send
 * @param   data_len length of the data
 */
extern enum err tx(uint8_t *data, uint32_t data_len);

/**
 * @brief   The user should call inside this function its receive function.  
 *          The length of the buffer pointed by data can be checked before 
 *          copying data into it by using *data_len. After copying the length 
 *          of the received data should be written in data_len.
 * @param   data pointer to a buffer where the edhoc message must be copied in
 * @param   data_len length of the received data
 */
extern enum err rx(uint8_t *data, uint32_t *data_len);

/**
 * @brief   IN this function the user performs application specific processing of ead items that can decide 
 *          on the protocol state (critical ead items), an example would be processing a staple after staple request in ead_1.
 * @param   data pointer to a buffer containing ead_2
 * @param   data_len length of the ead_2 cbor sequence
 */
extern enum err process_ead_2(uint8_t *ead_2, uint32_t *ead_2_len);

/**
 * @brief   In this function the user performs application specific processing of ead items that can decide 
 *          on the protocol state (critical ead items), an example would be checking for a staple request in ead_1.
 * @param   data pointer to a buffer containing ead_2
 * @param   data_len length of the ead_2 cbor sequence
 */
extern enum err process_ead_1(struct edhoc_responder_context *c, uint8_t *ead_1, uint32_t *ead_1_len);


#endif
