/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

extern "C" {
#include "edhoc.h"
#include "sock.h"
#include "edhoc_test_vectors_p256_v15.h"
}
#include "cantcoap.h"

#define STAPLE_REQUEST_LABEL 0x21

#define USE_IPV4
// #define USE_IPV6
/*comment this out to use DH keys from the test vectors*/
//#define USE_RANDOM_EPHEMERAL_DH_KEY

/**
 * @brief	Initializes sockets for CoAP client.
 * @param
 * @retval	error code
 */
static int start_coap_client(int *sockfd)
{
	int err;
#ifdef USE_IPV4
	struct sockaddr_in servaddr;
	const char IPV4_SERVADDR[] = { "127.0.0.1" };
	//const char IPV4_SERVADDR[] = { "172.31.24.45" };
	err = sock_init(SOCK_CLIENT, IPV4_SERVADDR, IPv4, &servaddr,
			sizeof(servaddr), sockfd);
	if (err < 0) {
		printf("error during socket initialization (error code: %d)",
		       err);
		return -1;
	}
#endif
#ifdef USE_IPV6
	struct sockaddr_in6 servaddr;
	const char IPV6_SERVADDR[] = { "2001:db8::1" };
	err = sock_init(SOCK_CLIENT, IPV6_SERVADDR, IPv6, &servaddr,
			sizeof(servaddr), sockfd);
	if (err < 0) {
		printf("error during socket initialization (error code: %d)",
		       err);
		return -1;
	}
#endif
	return 0;
}

/**
 * @brief	Callback function called inside the frontend when data needs to 
 * 		be send over the network. We use here CoAP as transport 
 * @param	data pointer to the data that needs to be send
 * @param	data_len lenhgt of the data in bytes
 */
enum err tx(void *sock, uint8_t *data, uint32_t data_len)
{
	/*construct a CoAP packet*/
	static uint16_t mid = 0;
	static uint32_t token = 0;
	CoapPDU *pdu = new CoapPDU();
	pdu->reset();
	pdu->setVersion(1);
	pdu->setType(CoapPDU::COAP_CONFIRMABLE);
	pdu->setCode(CoapPDU::COAP_POST);
	pdu->setToken((uint8_t *)&(++token), sizeof(token));
	pdu->setMessageID(mid++);
	pdu->setURI((char *)".well-known/edhoc", 17);
	pdu->setPayload(data, data_len);

	send(*((int *)sock), pdu->getPDUPointer(), pdu->getPDULength(), 0);

	delete pdu;
	return ok;
}

/**
 * @brief	Callback function called inside the frontend when data needs to 
 * 		be received over the network. We use here CoAP as transport 
 * @param	data pointer to the data that needs to be received
 * @param	data_len length of the data in bytes
 */
enum err rx(void *sock, uint8_t *data, uint32_t *data_len)
{
	int n;
	char buffer[MAXLINE];
	CoapPDU *recvPDU;
	/* receive */
	n = recv(*((int *)sock), (char *)buffer, MAXLINE, MSG_WAITALL);
	if (n < 0) {
		printf("recv error");
	}

	recvPDU = new CoapPDU((uint8_t *)buffer, n);

	if (recvPDU->validate()) {
		recvPDU->printHuman();
	}

	uint32_t payload_len = recvPDU->getPayloadLength();
	printf("data_len: %d\n", *data_len);
	printf("payload_len: %d\n", payload_len);

	if (*data_len >= payload_len) {
		memcpy(data, recvPDU->getPayloadPointer(), payload_len);
		*data_len = payload_len;
	} else {
		printf("insufficient space in buffer");
		return buffer_to_small;
	}

	delete recvPDU;
	return ok;
}
enum err get_tinyOCSP_certStatus_(uint8_t *responseData)
{
	uint8_t *walk=responseData;
	uint32_t responseData_len= *walk;
	walk+=responseData_len; //we should now be right on certStatus
	if (*walk==1){
		printf("certStatus: Good Certificate\n");
		return ok;
	}
	else if (*walk==3){
		printf("certStatus: Revoked Certificate\n");
		return error_message_sent;
	}
	else{

		printf("certStatus: unknown\n");
		return error_message_sent;
	}

	return ok;
}

enum err parse_stapleRequest_ead_2_value(uint8_t **ead_value, uint8_t **responseData, uint8_t **signatureVal, uint8_t **sigAlg)
{
	uint8_t *walk=*ead_value;
	uint32_t signatureVal_len;
	uint32_t responseData_len;


	//we'll do a quick parser here
	if (*walk !=0x59) //2 byte representable byteString
	{
		printf("malformed staple.\n");
		return malformed_ead_value;
	}
	else 
	{
		walk+=3; //now at 0x58
		walk+=1;
		responseData_len = *walk;
		walk++;
		*responseData=walk-1; //go back to length part
		PRINT_ARRAY("tinyOCSP responseData:",*responseData+1,responseData_len); //+1 to skip length
		walk+=responseData_len; //should now be at signature
		if (*walk!=0x58) 
		{
		  	printf("malformed staple.\n");
			return malformed_ead_value;
		}
		else
		{
			walk++;
			signatureVal_len = *walk;
			walk++;
			*signatureVal=walk;
			PRINT_ARRAY("tinyOCSP signatureVal:",*signatureVal,signatureVal_len);
			//won't worry about parsing sigAlg now since it's known for this ead item
		}
	}
	//we can now perform all required verifications
	//verify signature
	//verify responderID
	//verify producedAt
	//verify nonce

	//Do not attempt to use this function in a production setting as most of the verification measures aren't implemented

	return ok;
}

enum err process_ead_2(uint8_t *ead_2, uint32_t *ead_2_len)
{
	printf("Now processing EAD_2!\n");
	PRINT_ARRAY("msg2 ead_2", ead_2, *ead_2_len);

	//we can act on EAD_2 from here and accordingly stop EDHOC for example in the case of an invalid OCSP staple
	uint8_t *walk=ead_2;
	if(*walk==STAPLE_REQUEST_LABEL) //only expecting staple request label in ead item now //generic parser is another task
	{
		walk++; //pointing at ead_value head now
		//create pointers for responseData, signatureVal and sigAlg
		uint8_t *responseData, *signatureVal, *sigAlg;
		printf("Received staple including signed tinyOCSP response.\n");
		//parse the staple inside ead_value
		TRY(parse_stapleRequest_ead_2_value(&walk, &responseData, &signatureVal, &sigAlg));
		TRY(get_tinyOCSP_certStatus_(responseData));

	}

	return ok;
}


int main()
{
	int sockfd;
	uint8_t prk_exporter[32];
	uint8_t oscore_master_secret[16];
	uint8_t oscore_master_salt[8];

	/* edhoc declarations */
	uint8_t PRK_out[PRK_DEFAULT_SIZE];
	uint8_t err_msg[ERR_MSG_DEFAULT_SIZE];
	uint32_t err_msg_len = sizeof(err_msg);
	uint8_t ad_2[AD_DEFAULT_SIZE+64];
	uint32_t ad_2_len = sizeof(ad_2);
	uint8_t ad_4[AD_DEFAULT_SIZE+64];
	uint32_t ad_4_len = sizeof(ad_2);

	/* test vector inputs */
	uint16_t cred_num = 1;
	struct other_party_cred cred_r;
	struct edhoc_initiator_context c_i;

	uint8_t TEST_VEC_NUM = 1;
	uint8_t vec_num_i = TEST_VEC_NUM - 1;

	// uint8_t ead1_test[]={0x01,0x02,0x03,0x04};
	uint8_t ead1_stapleRequest[]={0x21,0x42,0xF6,0xF5}; //staple request
																	// # CBOR sequence with 3 elements
																	// 21 # negative(1) //cbor -2 for staple request critical label
																	// F6 # primitive(22) //cbor Null for out of band agreed upon responderIdList
																	// F5 # primitive(21) //cbor True for requesting a nonce //can be optional



	c_i.msg4 = true;
	c_i.sock = &sockfd;
	c_i.c_i.len = test_vectors[vec_num_i].c_i_len;
	c_i.c_i.ptr = (uint8_t *)test_vectors[vec_num_i].c_i;
	c_i.method = (enum method_type) * test_vectors[vec_num_i].method;
	c_i.suites_i.len = test_vectors[vec_num_i].SUITES_I_len;
	c_i.suites_i.ptr = (uint8_t *)test_vectors[vec_num_i].SUITES_I;
	// c_i.ead_1.len = test_vectors[vec_num_i].ead_1_len;
	// c_i.ead_1.ptr = (uint8_t *)test_vectors[vec_num_i].ead_1;
	
	//just passing our own test
	c_i.ead_1.ptr = ead1_stapleRequest; 
	c_i.ead_1.len = sizeof(ead1_stapleRequest);
	
	c_i.ead_3.len = test_vectors[vec_num_i].ead_3_len;
	c_i.ead_3.ptr = (uint8_t *)test_vectors[vec_num_i].ead_3;
	c_i.id_cred_i.len = test_vectors[vec_num_i].id_cred_i_len;
	c_i.id_cred_i.ptr = (uint8_t *)test_vectors[vec_num_i].id_cred_i;
	c_i.cred_i.len = test_vectors[vec_num_i].cred_i_len;
	c_i.cred_i.ptr = (uint8_t *)test_vectors[vec_num_i].cred_i;
	c_i.g_x.len = test_vectors[vec_num_i].g_x_raw_len;
	c_i.g_x.ptr = (uint8_t *)test_vectors[vec_num_i].g_x_raw;
	c_i.x.len = test_vectors[vec_num_i].x_raw_len;
	c_i.x.ptr = (uint8_t *)test_vectors[vec_num_i].x_raw;
	c_i.g_i.len = test_vectors[vec_num_i].g_i_raw_len;
	c_i.g_i.ptr = (uint8_t *)test_vectors[vec_num_i].g_i_raw;
	c_i.i.len = test_vectors[vec_num_i].i_raw_len;
	c_i.i.ptr = (uint8_t *)test_vectors[vec_num_i].i_raw;
	c_i.sk_i.len = test_vectors[vec_num_i].sk_i_raw_len;
	c_i.sk_i.ptr = (uint8_t *)test_vectors[vec_num_i].sk_i_raw;
	c_i.pk_i.len = test_vectors[vec_num_i].pk_i_raw_len;
	c_i.pk_i.ptr = (uint8_t *)test_vectors[vec_num_i].pk_i_raw;

	cred_r.id_cred.len = test_vectors[vec_num_i].id_cred_r_len;
	cred_r.id_cred.ptr = (uint8_t *)test_vectors[vec_num_i].id_cred_r;
	cred_r.cred.len = test_vectors[vec_num_i].cred_r_len;
	cred_r.cred.ptr = (uint8_t *)test_vectors[vec_num_i].cred_r;
	cred_r.g.len = test_vectors[vec_num_i].g_r_raw_len;
	cred_r.g.ptr = (uint8_t *)test_vectors[vec_num_i].g_r_raw;
	cred_r.pk.len = test_vectors[vec_num_i].pk_r_raw_len;
	cred_r.pk.ptr = (uint8_t *)test_vectors[vec_num_i].pk_r_raw;
	cred_r.ca.len = test_vectors[vec_num_i].ca_r_len;
	cred_r.ca.ptr = (uint8_t *)test_vectors[vec_num_i].ca_r;
	cred_r.ca_pk.len = test_vectors[vec_num_i].ca_r_pk_len;
	cred_r.ca_pk.ptr = (uint8_t *)test_vectors[vec_num_i].ca_r_pk;

#ifdef USE_RANDOM_EPHEMERAL_DH_KEY
	uint32_t seed;
	uint8_t G_X_random[32];
	uint8_t X_random[32];
	uint32_t G_X_random_len = sizeof(G_X_random);

	/*create a random seed*/
	FILE *fp;
	fp = fopen("/dev/urandom", "r");
	uint64_t seed_len = fread((uint8_t *)&seed, 1, sizeof(seed), fp);
	fclose(fp);
	PRINT_ARRAY("seed", (uint8_t *)&seed, seed_len);

	/*create ephemeral DH keys from seed*/
	TRY(ephemeral_dh_key_gen(X25519, seed, X_random, G_X_random,
				 &G_X_random_len));
	c_i.g_x.ptr = G_X_random;
	c_i.g_x.len = sizeof(G_X_random);
	c_i.x.ptr = X_random;
	c_i.x.len = sizeof(X_random);
	PRINT_ARRAY("secret ephemeral DH key", c_i.g_x.ptr, c_i.g_x.len);
	PRINT_ARRAY("public ephemeral DH key", c_i.x.ptr, c_i.x.len);

#endif

	TRY_EXPECT(start_coap_client(&sockfd), 0);
	// TRY(edhoc_initiator_run(&c_i, &cred_r, cred_num, err_msg, &err_msg_len,
	// 			ad_2, &ad_2_len, ad_4, &ad_4_len, PRK_out,
	// 			sizeof(PRK_out), tx, rx));

	//use our extended function which also passes the process_ead_2 cb
	TRY(edhoc_initiator_run_extended_2(&c_i, &cred_r, cred_num, err_msg, &err_msg_len,
				ad_2, &ad_2_len, ad_4, &ad_4_len, PRK_out,
				sizeof(PRK_out), tx, rx, process_ead_2));
	

	PRINT_ARRAY("PRK_out", PRK_out, sizeof(PRK_out));

	TRY(prk_out2exporter(SHA_256, PRK_out, sizeof(PRK_out), prk_exporter));
	PRINT_ARRAY("prk_exporter", prk_exporter, sizeof(prk_exporter));

	TRY(edhoc_exporter(SHA_256, OSCORE_MASTER_SECRET, prk_exporter,
			   sizeof(prk_exporter), oscore_master_secret,
			   sizeof(oscore_master_secret)));
	PRINT_ARRAY("OSCORE Master Secret", oscore_master_secret,
		    sizeof(oscore_master_secret));

	TRY(edhoc_exporter(SHA_256, OSCORE_MASTER_SALT, prk_exporter,
			   sizeof(prk_exporter), oscore_master_salt,
			   sizeof(oscore_master_salt)));
	PRINT_ARRAY("OSCORE Master Salt", oscore_master_salt,
		    sizeof(oscore_master_salt));

	close(sockfd);
	return 0;
}
