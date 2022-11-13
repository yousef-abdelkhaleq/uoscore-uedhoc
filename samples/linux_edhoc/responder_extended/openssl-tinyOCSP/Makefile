LIB_OPENSSL_tinyOCSP_PATH=/home/trexozz/thesis_rise/openssl-tinyOCSP/openssl-3.0.5/
OPENSSL_INCLUDES += -I $(LIB_OPENSSL_tinyOCSP_PATH)crypto/ocsp/
OPENSSL_INCLUDES += -I $(LIB_OPENSSL_tinyOCSP_PATH)apps/include/
OPENSSL_INCLUDES += -I $(LIB_OPENSSL_tinyOCSP_PATH)
OPENSSL_INCLUDES += -I $(LIB_OPENSSL_tinyOCSP_PATH)include/
OPENSSL_INCLUDES += -I $(LIB_OPENSSL_tinyOCSP_PATH)apps/
OPENSSL_INCLUDES += -I /usr/local/ssl/include/

all: lib-tinyocsp
lib-tinyocsp:
	gcc -c tinyOcsp-req.c $(OPENSSL_INCLUDES) -L $(LIB_OPENSSL_tinyOCSP_PATH)apps/ -lapps --whole-file -L /usr/local/ssl/lib64/ -lssl -lcrypto
	