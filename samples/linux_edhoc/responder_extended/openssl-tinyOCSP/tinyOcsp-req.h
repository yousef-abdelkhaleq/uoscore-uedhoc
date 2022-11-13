#ifdef OPENSSL_SYS_VMS
  /* So fd_set and friends get properly defined on OpenVMS */
# define _XOPEN_SOURCE_EXTENDED

#endif


#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
// #include <openssl/ocsp.h>


#include "apps.h"
#include "http_server.h"
#include "progs.h"
#include "ocsp_local.h"
#include "internal/sockets.h"
#include <openssl/ocsp.h>
#include <openssl/e_os2.h>
#include <openssl/crypto.h>
#include <openssl/bio.h>
#include <openssl/http.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/x509v3.h>


#define TAG_ZERO   0xC0
#define TEXT_TAG   0x60
#define BS_SMALL   0x40
#define CBOR_ARRAY 0x80

#define noncesize 32
#define sn_size 2
#define sha_1_hsize 20

#define good_cert 1
#define revoked_cert 2

#define one_byte_n_bs 0x58
#define responseData_size 201

struct OCSP_CBOR_CERTID{

    uint8_t hashAlg;
    uint8_t issuer_h[sha_1_hsize+1]; //+2 for cbor encoding bytes
    uint8_t issuer_kh[sha_1_hsize+1];
    uint8_t sn[sn_size+1];

};

typedef struct OCSP_CBOR_CERTID OCSP_CBOR_CERTID;
struct OCSP_CBOR_RESPONSE{
    uint8_t responseType;
    uint8_t *responderID;
    uint8_t *producedat;
    uint8_t nonce[noncesize+2];
    OCSP_CBOR_CERTID certID;
    uint8_t certStatus;
    uint8_t signaturVal[64+2];
    uint8_t signatureAlg;
};
typedef struct OCSP_CBOR_RESPONSE OCSP_CBOR_RESPONSE;

OCSP_CBOR_RESPONSE* tiny_response_item();
void printByteArray(uint8_t *bytestring,size_t len);
void string2ByteArray(char* input, uint8_t* output);

bool generate_ocsp_request(uint8_t **signed_tinyResponse, uint8_t *nonce_g_x, uint32_t nonce_g_x_len);
int add_ocsp_cert(OCSP_REQUEST **req, X509 *cert,
                         const EVP_MD *cert_id_md, X509 *issuer,
                         STACK_OF(OCSP_CERTID) *ids);
unsigned char *OCSP_tiny_sendreq_bio(BIO *b, const char *path, OCSP_REQUEST *req);
OSSL_HTTP_REQ_CTX *OCSP_tiny_sendreq_new(BIO *io, const char *path,
                                    const OCSP_REQUEST *req, int buf_size);




