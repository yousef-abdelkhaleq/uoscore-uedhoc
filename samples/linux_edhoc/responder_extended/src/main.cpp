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
#include <errno.h>
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
#include "tinyOcsp-req_2.h"
}
#include "cantcoap.h"

//variables used by the openssl library
char *default_config_file;
BIO *bio_in;
BIO *bio_out;
BIO *bio_err;

#define STAPLE_REQUEST_LABEL 0x21

// #define USE_IPV4
#define USE_IPV6

CoapPDU *txPDU = new CoapPDU();

char buffer[MAXLINE];
CoapPDU *rxPDU;

/*comment this out to use DH keys from the test vectors*/
//#define USE_RANDOM_EPHEMERAL_DH_KEY

#ifdef USE_IPV6
struct sockaddr_in6 client_addr;
#endif
#ifdef USE_IPV4
struct sockaddr_in client_addr;
#endif
socklen_t client_addr_len;

/**
 * @brief	Initializes socket for CoAP server.
 * @param	
 * @retval	error code
 */
static int start_coap_server(int *sockfd)
{
	int err;
#ifdef USE_IPV4
	struct sockaddr_in servaddr;
	//struct sockaddr_in client_addr;
	client_addr_len = sizeof(client_addr);
	memset(&client_addr, 0, sizeof(client_addr));
	const char IPV4_SERVADDR[] = { "127.0.0.1" };
	//const char IPV4_SERVADDR[] = { "192.168.43.63" };
	err = sock_init(SOCK_SERVER, IPV4_SERVADDR, IPv4, &servaddr,
			sizeof(servaddr), sockfd);
	if (err < 0) {
		printf("error during socket initialization (error code: %d)",
		       err);
		return -1;
	}
#endif
#ifdef USE_IPV6
	struct sockaddr_in6 servaddr;
	//struct sockaddr_in6 client_addr;
	client_addr_len = sizeof(client_addr);
	memset(&client_addr, 0, sizeof(client_addr));
	const char IPV6_SERVADDR[] = { "2001:db9::2" };
	err = sock_init(SOCK_SERVER, IPV6_SERVADDR, IPv6, &servaddr,
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
 * @brief	Sends CoAP packet over network.
 * @param	pdu pointer to CoAP packet
 * @retval	error code
 */
static int send_coap_reply(void *sock, CoapPDU *pdu)
{
	int r;

	r = sendto(*((int *)sock), pdu->getPDUPointer(), pdu->getPDULength(), 0,
		   (struct sockaddr *)&client_addr, client_addr_len);
	if (r < 0) {
		printf("Error: failed to send reply (Code: %d, ErrNo: %d)\n", r,
		       errno);
		return r;
	}

	printf("CoAP reply sent!\n");
	return 0;
}

enum err tx(void *sock, uint8_t *data, uint32_t data_len)
{
	txPDU->setCode(CoapPDU::COAP_CHANGED);
	txPDU->setPayload(data, data_len);
	send_coap_reply(sock, txPDU);
	return ok;
}

enum err rx(void *sock, uint8_t *data, uint32_t *data_len)
{
	int n;

	/* receive */
	client_addr_len = sizeof(client_addr);
	memset(&client_addr, 0, sizeof(client_addr));

	n = recvfrom(*((int *)sock), (char *)buffer, sizeof(buffer), 0,
		     (struct sockaddr *)&client_addr, &client_addr_len);
	if (n < 0) {
		printf("recv error");
	}

	rxPDU = new CoapPDU((uint8_t *)buffer, n);

	if (rxPDU->validate()) {
		rxPDU->printHuman();
	}

	PRINT_ARRAY("CoAP message", rxPDU->getPayloadPointer(),
		    rxPDU->getPayloadLength());

	uint32_t payload_len = rxPDU->getPayloadLength();
	if (*data_len >= payload_len) {
		memcpy(data, rxPDU->getPayloadPointer(), payload_len);
		*data_len = payload_len;
	} else {
		printf("insufficient space in buffer");
	}

	txPDU->reset();
	txPDU->setVersion(rxPDU->getVersion());
	txPDU->setMessageID(rxPDU->getMessageID());
	txPDU->setToken(rxPDU->getTokenPointer(), rxPDU->getTokenLength());

	if (rxPDU->getType() == CoapPDU::COAP_CONFIRMABLE) {
		txPDU->setType(CoapPDU::COAP_ACKNOWLEDGEMENT);
	} else {
		txPDU->setType(CoapPDU::COAP_NON_CONFIRMABLE);
	}

	delete rxPDU;
	return ok;
}

enum err parse_stapleRequest_ead_1_value(uint8_t **ead_value, uint8_t **responderIdList, uint8_t **nonce_option)
{
	uint8_t *walk=*ead_value;
	if (*walk !=0x42) //assumes null responderIDList
	{
		printf("malformed staple request.\n");
		return malformed_ead_value;
	}
	else 
	{
		walk++;
		*responderIdList = walk;
		walk++;
		if (*walk==0xf5) //true for nonce
		{
		  	*nonce_option = walk;
		}
		else
			*nonce_option=NULL;
	}
	return ok;
}


//Application can implement this function to process EAD_1 and act on the protocol state
enum err process_ead_1(struct edhoc_responder_context *c, uint8_t *ead_1, uint32_t *ead_1_len, uint8_t *g_x, uint32_t g_x_len )
{
	printf("processing ead 1!\n");
	PRINT_ARRAY("msg1 ead_1", ead_1, *ead_1_len);
	uint8_t *walk=ead_1;
	bool _nonce;


	//We won't implement a generic parser at this point
	if(*walk==STAPLE_REQUEST_LABEL)
	{	
		uint8_t *tinyOCSP_response_staple= (uint8_t*)malloc(AD_DEFAULT_SIZE+64);
		walk++; //pointing at ead_value head now
		//create pointers for responder ID list and optional nonce include
		uint8_t *responderIdList, *nonce_option;
		printf("Received tinyOCSP stapling request.\n");
		//parse staple request in EAD Value
		TRY(parse_stapleRequest_ead_1_value(&walk, &responderIdList, &nonce_option)); //update pointers here
		if (nonce_option!=NULL)
			{
				printf("{stapleRequestLabel:-2,ResponderIdList:NULL,Nonce:True}\n"); //skipping translation for now
				_nonce=true;
			}
		else
			printf("{stapleRequestLabel:-2,ResponderIdList:NULL}\n"); //skipping translation for now

	
		if (_nonce)
		{
			//create the request appending g_x as nonce
			PRINT_ARRAY("Performing tinyOCSP request with (g_x) as nonce:",g_x,g_x_len);
			if(generate_ocsp_request(&tinyOCSP_response_staple, g_x, g_x_len))
				printf("Received tinyOCSP response, can now construct staple for EAD_2\n");
			else
				return error_message_sent;
		}
		// else
		// {
		// 	if(generate_ocsp_request(&tinyOCSP_response_staple))
		// 		printf("Received tinyOCSP response, can now construct staple for EAD_2\n");
		// 	else
		// 		return error_message_sent;

		// }

		//encode the staple
		uint8_t *size_ptr=tinyOCSP_response_staple;
		uint32_t tinyOCSP_response_staple_len=size_ptr[0]+((size_ptr[1]&0xf0)*4096)+((size_ptr[1]&0x0f)*256)-2; //remove length
		printf("response staple len= %d\n",tinyOCSP_response_staple_len);
		//add length of ead_value byteString
		//add staple request label 0x21
		size_ptr=(uint8_t*)&tinyOCSP_response_staple_len;
		uint32_t ead_len_encoding=size_ptr[0]+((size_ptr[1]&0xf0)*4096)+((size_ptr[1]&0x0f)*256);
		size_ptr=(uint8_t*)&ead_len_encoding;
		uint8_t *temp=c->ead_2.ptr;
		memcpy(c->ead_2.ptr+7, tinyOCSP_response_staple+2, tinyOCSP_response_staple_len); //3 for EAD len encoding and 2 for label and ead value encoding
		*(temp+6) =size_ptr[0];
		*(temp+5) =size_ptr[1];
		*(temp+4) =0x59;
		*(temp+3) =0x21; 
		uint16_t ead_2_len=tinyOCSP_response_staple_len+4;
		size_ptr=(uint8_t*)&ead_2_len;
		*(temp+2) =size_ptr[0];
		*(temp+1) =size_ptr[1];
		*temp = 0x59;
		uint16_t ead_2_len_enc=ead_2_len+3;
		//[ead_len_encoding(3)][label(1)][staple_len_encoding(3)[staple]
		// memcpy(c->ead_2.ptr+4,&0x59,1); 
		// memcpy(c->ead_2.ptr+3,&0x21,1);
		//last memcpy to add total size of ead
		free(tinyOCSP_response_staple);
		c->ead_2.len=ead_2_len_enc;
		PRINT_ARRAY("EAD_2",c->ead_2.ptr,c->ead_2.len);


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
	uint8_t ad_1[AD_DEFAULT_SIZE+64];
	uint32_t ad_1_len = sizeof(ad_1);
	uint8_t ad_3[AD_DEFAULT_SIZE+64];
	uint32_t ad_3_len = sizeof(ad_1);

	/* test vector inputs */
	uint16_t cred_num = 1;
	struct other_party_cred cred_i;
	struct edhoc_responder_context c_r;

	uint8_t TEST_VEC_NUM = 1;
	uint8_t vec_num_i = TEST_VEC_NUM - 1;

	TRY_EXPECT(start_coap_server(&sockfd), 0);

#ifdef USE_RANDOM_EPHEMERAL_DH_KEY
	uint32_t seed;
	uint8_t G_Y_random[32];
	uint8_t Y_random[32];
	c_r.g_y.ptr = G_Y_random;
	c_r.g_y.len = sizeof(G_Y_random);
	c_r.y.ptr = Y_random;
	c_r.y.len = sizeof(Y_random);
#endif




	c_r.msg4 = true;
	c_r.sock = &sockfd;
	c_r.c_r.ptr = (uint8_t *)test_vectors[vec_num_i].c_r;
	c_r.c_r.len = test_vectors[vec_num_i].c_r_len;
	c_r.suites_r.len = test_vectors[vec_num_i].SUITES_R_len;
	c_r.suites_r.ptr = (uint8_t *)test_vectors[vec_num_i].SUITES_R;
	// c_r.ead_2.len = test_vectors[vec_num_i].ead_2_len;
	// c_r.ead_2.ptr = (uint8_t *)test_vectors[vec_num_i].ead_2;
	c_r.ead_2.ptr = (uint8_t*)malloc(AD_DEFAULT_SIZE+64); //assign memory for ead_2 //buf it up a bit
	c_r.ead_2.len = 0; //len is now 0
	c_r.ead_4.len = test_vectors[vec_num_i].ead_4_len;
	c_r.ead_4.ptr = (uint8_t *)test_vectors[vec_num_i].ead_4;
	c_r.id_cred_r.len = test_vectors[vec_num_i].id_cred_r_len;
	c_r.id_cred_r.ptr = (uint8_t *)test_vectors[vec_num_i].id_cred_r;
	c_r.cred_r.len = test_vectors[vec_num_i].cred_r_len;
	c_r.cred_r.ptr = (uint8_t *)test_vectors[vec_num_i].cred_r;
	c_r.g_y.len = test_vectors[vec_num_i].g_y_raw_len;
	c_r.g_y.ptr = (uint8_t *)test_vectors[vec_num_i].g_y_raw;
	c_r.y.len = test_vectors[vec_num_i].y_raw_len;
	c_r.y.ptr = (uint8_t *)test_vectors[vec_num_i].y_raw;
	c_r.g_r.len = test_vectors[vec_num_i].g_r_raw_len;
	c_r.g_r.ptr = (uint8_t *)test_vectors[vec_num_i].g_r_raw;
	c_r.r.len = test_vectors[vec_num_i].r_raw_len;
	c_r.r.ptr = (uint8_t *)test_vectors[vec_num_i].r_raw;
	c_r.sk_r.len = test_vectors[vec_num_i].sk_r_raw_len;
	c_r.sk_r.ptr = (uint8_t *)test_vectors[vec_num_i].sk_r_raw;
	c_r.pk_r.len = test_vectors[vec_num_i].pk_r_raw_len;
	c_r.pk_r.ptr = (uint8_t *)test_vectors[vec_num_i].pk_r_raw;

	cred_i.id_cred.len = test_vectors[vec_num_i].id_cred_i_len;
	cred_i.id_cred.ptr = (uint8_t *)test_vectors[vec_num_i].id_cred_i;
	cred_i.cred.len = test_vectors[vec_num_i].cred_i_len;
	cred_i.cred.ptr = (uint8_t *)test_vectors[vec_num_i].cred_i;
	cred_i.g.len = test_vectors[vec_num_i].g_i_raw_len;
	cred_i.g.ptr = (uint8_t *)test_vectors[vec_num_i].g_i_raw;
	cred_i.pk.len = test_vectors[vec_num_i].pk_i_raw_len;
	cred_i.pk.ptr = (uint8_t *)test_vectors[vec_num_i].pk_i_raw;
	cred_i.ca.len = test_vectors[vec_num_i].ca_i_len;
	cred_i.ca.ptr = (uint8_t *)test_vectors[vec_num_i].ca_i;
	cred_i.ca_pk.len = test_vectors[vec_num_i].ca_i_pk_len;
	cred_i.ca_pk.ptr = (uint8_t *)test_vectors[vec_num_i].ca_i_pk;

	while (1) {
#ifdef USE_RANDOM_EPHEMERAL_DH_KEY
		/*create ephemeral DH keys from seed*/
		/*create a random seed*/
		FILE *fp;
		fp = fopen("/dev/urandom", "r");
		uint32_t G_Y_random_len = sizeof(G_Y_random);
		uint64_t seed_len =
			fread((uint8_t *)&seed, 1, sizeof(seed), fp);
		fclose(fp);
		PRINT_ARRAY("seed", (uint8_t *)&seed, seed_len);

		TRY(ephemeral_dh_key_gen(X25519, seed, Y_random, G_Y_random,
					 &G_Y_random_len));
		PRINT_ARRAY("secret ephemeral DH key", c_r.g_y.ptr,
			    c_r.g_y.len);
		PRINT_ARRAY("public ephemeral DH key", c_r.y.ptr, c_r.y.len);
#endif
		// TRY(edhoc_responder_run(&c_r, &cred_i, cred_num, err_msg,
		// 			&err_msg_len, (uint8_t *)&ad_1,
		// 			&ad_1_len, (uint8_t *)&ad_3, &ad_3_len,
		// 			PRK_out, sizeof(PRK_out),
		// 			tx, rx));

		//use our extended function which also passes the process_ead_1 cb
		TRY(edhoc_responder_run_extended_ead_proc(&c_r, &cred_i, cred_num, err_msg,
					&err_msg_len, (uint8_t *)&ad_1,
					&ad_1_len, (uint8_t *)&ad_3, &ad_3_len,
					PRK_out, sizeof(PRK_out),
					tx, rx, process_ead_1));
		PRINT_ARRAY("PRK_out", PRK_out, sizeof(PRK_out));

		TRY(prk_out2exporter(SHA_256, PRK_out, sizeof(PRK_out),
				     prk_exporter));
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
	}

	close(sockfd);
	return 0;
}
