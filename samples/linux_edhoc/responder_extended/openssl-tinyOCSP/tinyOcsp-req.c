#include "tinyOcsp-req.h"

void string2ByteArray(char* input, uint8_t* output)
{
    int loop;
    int i;
    
    loop = 0;
    i = 0;
    
    while(input[loop] != '\0')
    {
        output[i++] = input[loop++];
    }
}

void printByteArray(uint8_t *bytestring,size_t len)
{
    int i=0;
    while (len)
    {
        printf("%02x ",bytestring[i]);
        len--;
        i++;
    }
    
}



OCSP_CBOR_RESPONSE* tiny_response_item()
{
   static const OCSP_CBOR_CERTID   client_id={
    0,
    "",
    "",
    ""};
    //initialise members
   static OCSP_CBOR_RESPONSE tiny_response_it={
      15,
      NULL,
      NULL,
      "",
      client_id,
      0,
      "",
      0
     };

    OCSP_CBOR_RESPONSE *ptr_to_resp;
    ptr_to_resp=&tiny_response_it;

    return ptr_to_resp;


}



//sendreq with tiny as content type
OSSL_HTTP_REQ_CTX *OCSP_tiny_sendreq_new(BIO *io, const char *path,
                                    const OCSP_REQUEST *req, int buf_size)
{
    OSSL_HTTP_REQ_CTX *rctx = OSSL_HTTP_REQ_CTX_new(io, io, buf_size);

    if (rctx == NULL)
        return NULL;
    /*-
     * by default:
     * no bio_update_fn (and consequently no arg)
     * no ssl
     * no proxy
     * no timeout (blocking indefinitely)
     * no expected content type
     * max_resp_len = 100 KiB
     */
    if (!OSSL_HTTP_REQ_CTX_set_request_line(rctx, 1 /* POST */,
                                            NULL, NULL, path))
        goto err;
   
    if (!OSSL_HTTP_REQ_CTX_set_expected(rctx,
                                        NULL /* content_type */, 0 /* asn1 */,
                                        0 /* timeout */, 0 /* keep_alive */))
        goto err;
    
    if (req != NULL
         && !OSSL_HTTP_REQ_CTX_set1_req(rctx, "application/ocsp-request-tiny",
                                       ASN1_ITEM_rptr(OCSP_REQUEST),
                                       (const ASN1_VALUE *)req))
        goto err;
    return rctx;

 err:
    OSSL_HTTP_REQ_CTX_free(rctx);
    return NULL;
}

unsigned char *OCSP_tiny_sendreq_bio(BIO *b, const char *path, OCSP_REQUEST *req)
{
    unsigned char *resp = NULL;
    OSSL_HTTP_REQ_CTX *ctx;
    BIO *mem;
    ctx = OCSP_tiny_sendreq_new(b, path, req, 0 /* default buf_size */);
    if (ctx == NULL)
        return NULL;
    mem = OSSL_HTTP_REQ_CTX_exchange(ctx); 

    resp = cbor_item_d2i_bio(mem);

    OSSL_HTTP_REQ_CTX_free(ctx);
    return resp;
}



int add_ocsp_cert(OCSP_REQUEST **req, X509 *cert,
                         const EVP_MD *cert_id_md, X509 *issuer,
                         STACK_OF(OCSP_CERTID) *ids)
{
    OCSP_CERTID *id;

    if (issuer == NULL) {
        BIO_printf(bio_err, "No issuer certificate specified\n");
        return 0;
    }
    if (*req == NULL)
        *req = OCSP_REQUEST_new();
    if (*req == NULL)
        goto err;
    id = OCSP_cert_to_id(cert_id_md, cert, issuer);
    if (id == NULL || !sk_OCSP_CERTID_push(ids, id))
        goto err;
    if (!OCSP_request_add0_id(*req, id))
        goto err;
    return 1;

 err:
    BIO_printf(bio_err, "Error Creating OCSP request\n");
    return 0;
}

bool generate_ocsp_request(uint8_t **signed_tinyResponse, uint8_t *nonce_g_x, uint32_t nonce_g_x_len) 
{   
    uint8_t g_x_nonce[nonce_g_x_len];
    OCSP_CBOR_CERTID cbor_client_id;
	EVP_MD *cert_id_md = NULL;
    
    BIO* out;
    BIO* file;
    
    OCSP_BASICRESP *bs = NULL;
    OCSP_REQUEST *req = NULL;

    uint8_t *resp = NULL;

    STACK_OF(OCSP_CERTID) *ids = NULL;

    STACK_OF(OPENSSL_STRING) *reqnames = NULL;
    
    STACK_OF(X509) *verify_other = NULL;
    STACK_OF(X509) *issuers = NULL;

    X509 *issuer = NULL, *cert = NULL;
    X509_STORE *store = NULL;

    const char *CAfile = NULL, *CApath = NULL, *CAstore = NULL;
    int noCAfile = 0, noCApath = 0, noCAstore = 0;

    char *verify_certfile = NULL;
    char* client_certfile = NULL;

    

    //Certificate paths
    CAfile="/usr/lib/ssl/demoCA/certs/ca.pem"; 
    // verify_certfile="/etc/pki/CA/certs/ocsp_ec.pem";
    client_certfile="/usr/lib/ssl/client.pem"; 
    
    char* outfile;

    out = bio_open_default(outfile, 'w', FORMAT_TEXT);
    if (out == NULL)
        goto end;


    store = setup_verify(CAfile, noCAfile, CApath, noCApath,
                             CAstore, noCAstore); //probably not required
    if(!store)
    {
        printf("Couldn't setup trust store");
        return false;
    }


    issuer = load_cert(CAfile, FORMAT_UNDEF, "issuer certificate");
    if (issuer == NULL)
        goto end;
    if (issuers == NULL) {
        if ((issuers = sk_X509_new_null()) == NULL)
            goto end;
    }
    //add issuer to issuers stack
    if (!sk_X509_push(issuers, issuer))
        goto end;
    
    //create ocsp request from EDHOC responder

    // setup OCSP request
    req = OCSP_REQUEST_new(); //get a new OCSP_REQUEST* req
    
    //make sure it was successful
    if(!req)  {
        printf("Failed to create new OCSP_REQUEST\n");
        return false;
    }

    //Get x509 form of client cert
    cert = load_cert(client_certfile, FORMAT_UNDEF, "certificate");
    if (cert == NULL)
        {
            printf("failed to load client cert\n");
            return false;
        }

    //set the message digest for the cert to be SHA1
    if (cert_id_md == NULL)
        cert_id_md = (EVP_MD *)EVP_sha1();
    
    //add the client cert to the create OCSP_REQUEST structure 
    if (!add_ocsp_cert(&req, cert, cert_id_md, issuer, ids))
        goto end;
    
    // add nonce and have it as part of the request
    memcpy(g_x_nonce,nonce_g_x,nonce_g_x_len); 
    //add g_X as nonce to request
    if (!OCSP_request_add1_nonce(req, g_x_nonce,sizeof(g_x_nonce))) 
        {
            printf("failed to add nonce to request structure\n");
            return false;
        }


    //print out request for debugging
    OCSP_REQUEST_print(out, req, 0);
    

    //prepare to send request
    const char* hostname="localhost";
    BIO* ocsp_responder=BIO_new_connect(hostname);
    const char* path="/";
    BIO_set_conn_port(ocsp_responder, "9999"); //responder is running on localhost:9999

 
    resp= OCSP_tiny_sendreq_bio(ocsp_responder, path, req); 
    if (resp==NULL)
    	 {
        printf("failed to reach OCSP Responder\n");
        return false;
    }

    size_t signed_tiny_len=resp[0]+((resp[1]&0xf0)*4096)+((resp[1]&0x0f)*256);
    printf("Tiny Response including ECDSA-p256 Signature:\n");
    printByteArray(resp+2,signed_tiny_len-2);
    printf("\n");

    memcpy(*signed_tinyResponse,resp,signed_tiny_len);

    

    return true;
end:
    printf("--SCRIPT FAILED AT END--\n");

    return false;
}




