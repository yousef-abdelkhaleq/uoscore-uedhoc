/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/
#include "../inc/retrieve_cred.h"

#include <string.h>

#include "../edhoc.h"
#include "../../common/inc/crypto_wrapper.h"
#include "../../common/inc/oscore_edhoc_error.h"
#include "../inc/print_util.h"
#include "../inc/memcpy_s.h"
#include "../cbor/decode_id_cred_x.h"
#include "../cbor/decode_cert.h"
/**
 * @brief   Verifies an certificate
 * @param   cert a native CBOR encoded certificate
 * @param   cer_len the length of the certificate
 * @param   cred_array an array containing credentials 
 * @param   cred_num number of elements in cred_array
 * @param   pk public key contained in the certificate
 * @param   pk_len the length pk
 * @param   verified true if verification successfull
 */
static enum err cert_verify(const uint8_t *cert, uint16_t cert_len,
			    const struct other_party_cred *cred_array,
			    uint16_t cred_num, uint8_t *pk, uint16_t *pk_len,
			    bool *verified)
{
	uint32_t decode_len = 0;
	struct cert c;

	TRY_EXPECT(cbor_decode_cert(cert, cert_len, &c, &decode_len), true);

	PRINT_MSG("CBOR certificate parsed.\n");
	PRINTF("Certificate type: %d\n", c._cert_type);
	PRINT_ARRAY("Serial number", c._cert_serial_number.value,
		    c._cert_serial_number.len);
	PRINT_ARRAY("issuer", c._cert_issuer.value, c._cert_issuer.len);
	PRINTF("validity_not_before: %d\n", c._cert_validity_not_before);
	PRINTF("validity_not_after: %d\n", c._cert_validity_not_after);
	PRINT_ARRAY("subject", c._cert_subject.value, c._cert_subject.len);
	PRINT_ARRAY("PK", c._cert_pk.value, c._cert_pk.len);
	PRINTF("extensions: %d\n", c._cert_extensions);
	PRINT_ARRAY("Signature", c._cert_signature.value,
		    c._cert_signature.len);

	/*get the CAs public key*/
	uint8_t *root_pk = NULL;
	uint8_t root_pk_len = 0;
	for (uint16_t i = 0; i < cred_num; i++) {
		if (memcmp(cred_array[i].ca.ptr, c._cert_issuer.value,
			   cred_array[i].ca.len)) {
			root_pk = cred_array[i].ca_pk.ptr;
			root_pk_len = cred_array[i].ca_pk.len;
			PRINT_ARRAY("Root PK of the CA", root_pk, root_pk_len);
			break;
		}
		return no_such_ca;
	}

	TRY(_memcpy_s(pk, *pk_len, c._cert_pk.value, c._cert_pk.len));
	*pk_len = c._cert_pk.len;

	return verify(EdDSA, root_pk, root_pk_len, cert,
		      cert_len - 2 - c._cert_signature.len,
		      c._cert_signature.value, c._cert_signature.len, verified);
}

enum err retrieve_cred(bool static_dh_auth, struct other_party_cred *cred_array,
		       uint16_t cred_num, uint8_t *id_cred, uint8_t id_cred_len,
		       uint8_t *cred, uint16_t *cred_len, uint8_t *pk,
		       uint16_t *pk_len, uint8_t *g, uint16_t *g_len)
{
	bool verified;
	uint32_t decode_len = 0;
	struct id_cred_x_map map;

	//TODO implement here retrieving of the public of the other party from CRED_x of the other party!!!

	/*check first if the credential is preestablished (RPK)*/
	for (uint16_t i = 0; i < cred_num; i++) {
		if (cred_array[i].id_cred.len == id_cred_len) {
			if (0 == memcmp(cred_array[i].id_cred.ptr, id_cred,
					id_cred_len)) {
				TRY(_memcpy_s(cred, *cred_len,
					      cred_array[i].cred.ptr,
					      cred_array[i].cred.len));
				*cred_len = cred_array[i].cred.len;
				if (static_dh_auth) {
					*pk_len = 0;
					TRY(_memcpy_s(g, *g_len,
						      cred_array[i].g.ptr,
						      cred_array[i].g.len));
					*g_len = cred_array[i].g.len;
				} else {
					*g_len = 0;
					TRY(_memcpy_s(pk, *pk_len,
						      cred_array[i].pk.ptr,
						      cred_array[i].pk.len));
					*pk_len = cred_array[i].pk.len;
				}
				return ok;
			}
		}
	}

	/* Check if ID_CRED_x contains a certificate*/
	TRY_EXPECT(cbor_decode_id_cred_x_map(id_cred, id_cred_len, &map,
					     &decode_len),
		   true);
	if (map._id_cred_x_map_x5chain_present != 0) {
		PRINT_ARRAY(
			"ID_CRED_x contains a certificate",
			map._id_cred_x_map_x5chain._id_cred_x_map_x5chain.value,
			map._id_cred_x_map_x5chain._id_cred_x_map_x5chain.len);
		TRY(_memcpy_s(
			cred, *cred_len,
			map._id_cred_x_map_x5chain._id_cred_x_map_x5chain.value,
			map._id_cred_x_map_x5chain._id_cred_x_map_x5chain.len));
		*cred_len =
			map._id_cred_x_map_x5chain._id_cred_x_map_x5chain.len;
		if (static_dh_auth) {
			*pk_len = 0;
			TRY(cert_verify(map._id_cred_x_map_x5chain
						._id_cred_x_map_x5chain.value,
					map._id_cred_x_map_x5chain
						._id_cred_x_map_x5chain.len,
					cred_array, cred_num, g, g_len,
					&verified));
		} else {
			*g_len = 0;
			TRY(cert_verify(map._id_cred_x_map_x5chain
						._id_cred_x_map_x5chain.value,
					map._id_cred_x_map_x5chain
						._id_cred_x_map_x5chain.len,
					cred_array, cred_num, pk, pk_len,
					&verified));
		}

		if (verified) {
			PRINT_MSG("Certificate verification successful!\n");
			return ok;
		} else {
			return aead_authentication_failed;
		}
	}

	return credential_not_found;
}
