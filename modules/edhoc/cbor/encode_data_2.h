/*
 * Generated using cddl_gen version 0.2.99
 * https://github.com/NordicSemiconductor/cddl-gen
 * Generated with a default_max_qty of 3
 */

#ifndef ENCODE_DATA_2_H__
#define ENCODE_DATA_2_H__

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include "cbor_encode.h"
#include "types_encode_data_2.h"

#if DEFAULT_MAX_QTY != 3
#error "The type file was generated with a different default_max_qty than this file"
#endif


bool cbor_encode_data_2(
		uint8_t *payload, uint32_t payload_len,
		const struct data_2 *input,
		uint32_t *payload_len_out);


#endif /* ENCODE_DATA_2_H__ */
