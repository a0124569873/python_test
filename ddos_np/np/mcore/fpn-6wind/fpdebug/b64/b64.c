#include <stdint.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

#include "b64.h"

char * b64_encode(const char *buffer, uint32_t length) {
    BIO *bmem = NULL;
    BIO *b64 = NULL;
    BUF_MEM *bptr;

    char* out_buff = NULL;

    b64 = BIO_new(BIO_f_base64());

    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_write(b64, buffer, length);
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bptr);
//    BIO_set_close(b64, BIO_NOCLOSE);

    out_buff = (char *)malloc(bptr->length + 1);
    memcpy(out_buff, bptr->data, bptr->length);
    out_buff[bptr->length] = 0;
    BIO_free_all(b64);

    return out_buff;
}

char * b64_decode(char *input, uint32_t length) {
    BIO *b64 = NULL;
    BIO *bmem = NULL;
    char *buffer = (char *)malloc(length);

    memset(buffer, 0, length);
    b64 = BIO_new(BIO_f_base64());

    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bmem = BIO_new_mem_buf(input, length);
    bmem = BIO_push(b64, bmem);
    BIO_read(bmem, buffer, length);
    BIO_free_all(bmem);

    return buffer;
}