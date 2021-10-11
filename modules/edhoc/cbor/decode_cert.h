/*
 * Generated using cddl_gen version 0.2.99
 * https://github.com/NordicSemiconductor/cddl-gen
 * Generated with a default_max_qty of 3
 */

#ifndef DECODE_CERT_H__
#define DECODE_CERT_H__

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include "cbor_decode.h"
#include "types_decode_cert.h"

#if DEFAULT_MAX_QTY != 3
#error "The type file was generated with a different default_max_qty than this file"
#endif


bool cbor_decode_cert(
		const uint8_t *payload, uint32_t payload_len,
		struct cert *result,
		uint32_t *payload_len_out);


#endif /* DECODE_CERT_H__ */
