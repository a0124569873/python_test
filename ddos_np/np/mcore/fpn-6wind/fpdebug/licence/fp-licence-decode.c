#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <stdio.h>
#include <unistd.h>

#include <fcntl.h>
#include <sys/stat.h>

#include <sys/mman.h>
#include <sys/ioctl.h>

#include "rsa_pub.h"
#include "fp-licence-header.h"

#define _INDEX(i) (((~i&0x1f)<<5) | ((~i&0x3e0)>>5))

RSA * createRSA(uint8_t * key, int32_t public);
int32_t public_encrypt(uint8_t * data, int32_t data_len, uint8_t * key, uint8_t *encrypted);
int32_t public_decrypt(uint8_t * enc_data, int32_t data_len, uint8_t * key, uint8_t *decrypted);
int32_t private_encrypt(uint8_t * data, int32_t data_len, uint8_t * key, uint8_t *encrypted);
int32_t private_decrypt(uint8_t * enc_data, int32_t data_len, uint8_t * key, uint8_t *decrypted);

void printLastError(char *buf);

uint32_t format_pub(const char* pub, char* buf, int32_t bsize);
uint32_t format_pri(const char* pub, char* buf, int32_t bsize);

int32_t format_raw_licence(raw_licence_t* raw_licence);
int32_t decode_licence(raw_licence_t* raw_licence, int32_t raw_size, void** new_licence, uint32_t *new_size, int32_t is_first);

uint32_t vade_licence_decode(raw_licence_t* licence, uint32_t raw_size, void** licence_buf, uint32_t* bsize, raw_licence_decode_info debug_info[10]);

uint8_t check_sum(uint8_t* bytes, uint32_t len) {
    uint16_t cksum = 0;
    uint32_t i = 0;

    for(; i < len; i ++) {
        cksum += bytes[i];
    }

    return (uint8_t)(~cksum);
}

RSA * createRSA(uint8_t * key, int32_t public) {

    RSA * rsa = NULL;
    BIO * keybio = BIO_new_mem_buf(key, -1);

    if (keybio == NULL) {
        return 0;
    }

    if(public) {
        rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
    } else {
        rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
    }

    BIO_free_all(keybio);
    return rsa;
}
 
int32_t public_encrypt(uint8_t * data, int32_t data_len, uint8_t * key, uint8_t *encrypted) {
    RSA * rsa = createRSA(key, 1);

    if (!rsa) {
        return -1;
    }
   
    return RSA_public_encrypt(data_len,data,encrypted,rsa,RSA_PKCS1_PADDING);
}

int32_t private_decrypt(uint8_t * enc_data, int32_t data_len, uint8_t * key, uint8_t *decrypted) {
    RSA * rsa = createRSA(key, 0);

    if (!rsa) {
        return -1;
    }

    return RSA_private_decrypt(data_len,enc_data,decrypted,rsa,RSA_PKCS1_PADDING);
}
 
 
int32_t private_encrypt(uint8_t * data, int32_t data_len, uint8_t * key, uint8_t *encrypted) {
    RSA * rsa = createRSA(key, 0);

    if (!rsa) {
        return -1;
    }

    return RSA_private_encrypt(data_len,data,encrypted,rsa, RSA_PKCS1_PADDING);
}

int32_t public_decrypt(uint8_t * enc_data, int32_t data_len, uint8_t * key, uint8_t *decrypted) {
    RSA * rsa = createRSA(key, 1);

    if (!rsa) {
        return -1;
    }
    
    return RSA_public_decrypt(data_len, enc_data, decrypted, rsa, RSA_PKCS1_PADDING);
}
 
void printLastError(char *buf) {
    ERR_load_crypto_strings();
    ERR_error_string(ERR_get_error(), buf);
}

uint32_t format_pub(const char* pub, char* buf, int32_t bsize) {
    const char* p = pub;
    char* p1 = buf;

    p1 += snprintf(p1, bsize, "%s\n", "-----BEGIN PUBLIC KEY-----");

    while(*p) {
        if (p1 - buf >= bsize) {
            return 0;
        }

        *p1 ++ = *p ++;

        if ((p - pub) % 64 ==  0) {
            *p1 ++ = '\n';
        }
    }

    if (*p1 != '\n') *p1 ++ = '\n';

    p1 += snprintf(p1, bsize - (p1 - buf), "%s\n", "-----END PUBLIC KEY-----");

    return 1;
}

uint32_t format_pri(const char* pub, char* buf, int32_t bsize) {
    const char* p = pub;
    char* p1 = buf;

    p1 += snprintf(p1, bsize, "%s\n", "-----BEGIN RSA PRIVATE KEY-----");

    while(*p) {
        if (p1 - buf >= bsize) {
            return 0;
        }

        *p1 ++ = *p ++;

        if ((p - pub) % 64 ==  0) {
            *p1 ++ = '\n';
        }
    }

    if (*p1 != '\n') *p1 ++ = '\n';

    snprintf(p1, bsize - (p1 - buf), "%s\n", "-----END RSA PRIVATE KEY-----");

    return 1;
}

uint32_t vade_licence_decode(raw_licence_t* raw_licence, uint32_t raw_size, void** licence_buf, uint32_t* bsize, raw_licence_decode_info debug_info[10]) {

    int32_t decode_continue = 1;

    char* decode_str = 0;
    uint32_t decode_size = 0;

    *licence_buf = NULL;
    *bsize = 0;

    if (format_raw_licence(raw_licence) < 0) {
        return 0;
    }

    uint32_t dep = 0;

    debug_info[dep].header = *(raw_licence_t*)raw_licence;
    debug_info[dep ++].data_len = raw_size;


    do {
        uint32_t new_size = 0;
        void *new_block = NULL;
        int32_t result = 0;

        result = decode_licence(raw_licence, raw_size, &new_block, &new_size, dep == 1);

        decode_continue = result == 1 && !!new_block && !!new_size;

        free(raw_licence);
        if (!new_block) {
            break;
        }
      
        if (decode_continue) {
            raw_size = new_size;
            raw_licence = (raw_licence_t*)new_block;
            debug_info[dep].header = *(raw_licence_t*)raw_licence;
            debug_info[dep ++].data_len = new_size;
        } else {
            decode_str = new_block;
            decode_size = new_size;
        }

    } while(decode_continue);

    if (decode_str) {
        *licence_buf = decode_str;
        *bsize = decode_size;
    }

    return dep;

}

void raw_licence_info(const raw_licence_t* raw_licence, char buf[1024]) {
    snprintf(buf, 1024, "magic=%c%c%c%c index=%d block_count=%x alive_time=%d tick_count=%d utc_timestamp=%d",
        raw_licence->magic[0],
        raw_licence->magic[1],
        raw_licence->magic[2],
        raw_licence->magic[3],
        raw_licence->index,
        raw_licence->block_count,
        raw_licence->alive_time,
        raw_licence->sys_tick_count,
        raw_licence->utc_timestamp
    );
}

//
// @return value
// 0: ok, -1: error
//
int32_t format_raw_licence(raw_licence_t* raw_licence) {

    if (
        raw_licence->magic[0] != 'V' ||
        raw_licence->magic[1] != 'E' ||
        raw_licence->magic[2] != 'D' ||
        raw_licence->magic[3] != 'A'
    ) {
        return -1;
    }

    if (
        (int32_t)_INDEX(raw_licence->index) < 0 ||
        _INDEX(raw_licence->index) >= sizeof(kLicenceData)/sizeof(*kLicenceData)
    ) {
        return -1;
    }

    raw_licence->index = _INDEX(raw_licence->index);

    return 0;
}

//
// @raw_licence 
// @return value:
// 0: finish, 1: unfinish, -1: error
//
int32_t decode_licence(raw_licence_t* raw_licence, int32_t raw_size, void** new_licence, uint32_t *new_size, int32_t is_first) {

    int32_t de_len = 0;
    uint8_t *data = is_first ? raw_licence->data : raw_licence->inner_data;

    int32_t block_bytes = (raw_size - (data - (uint8_t*)raw_licence))/raw_licence->block_count;
    
    *new_size = 0;
    *new_licence = malloc(raw_size);

    uint8_t pub_key[4096] = {0};

    format_pub(kLicenceData[raw_licence->index], (char*)pub_key, sizeof(pub_key));

    while(data < (uint8_t *)raw_licence + raw_size) {
        
        uint8_t de_buf[1024] = {0};

        de_len = public_decrypt(data, block_bytes, pub_key, de_buf);

        if(de_len == -1) {
            printLastError((char*)de_buf);
            free(*new_licence);
            *new_licence = 0;
            return -1;
        }

        memcpy(*new_licence + *new_size, de_buf, de_len);

        data += block_bytes;
        *new_size = *new_size + de_len;
    }

    ((uint8_t*)(*new_licence))[*new_size] = 0;

    return format_raw_licence((raw_licence_t*)*new_licence) == 0 ? 1 : 0;
}

int32_t get_licence_time(const char* file_name, int32_t *alive_time, int32_t *tick_count, int32_t *utc_timestamp, uint8_t *cksum) {
     raw_licence_t *p_raw_licence;
     const char* file = file_name && strlen(file_name) > 0 ? file_name : LICENCE_FILE_DEFAULT_PATH;
     int fd = open(file, O_RDWR);
     if(fd < 0) {
         return -1;
     }

     p_raw_licence = (raw_licence_t *)mmap(0, sizeof(raw_licence_t), PROT_READ, MAP_SHARED, fd, 0);
     if(p_raw_licence == MAP_FAILED) {
         close(fd);
         return -2;
     }
     
     *alive_time = p_raw_licence->alive_time;
     *tick_count = p_raw_licence->sys_tick_count;
     *utc_timestamp = p_raw_licence->utc_timestamp;
     *cksum = p_raw_licence->cksum;

     munmap(p_raw_licence, sizeof(raw_licence_t));
     close(fd);

     return 0;
}

int32_t set_licence_time(const char* file_name, int32_t alive_time, int32_t tick_count, int32_t utc_timestamp, uint8_t cksum) {
     raw_licence_t *p_raw_licence;
     const char* file = file_name && strlen(file_name) > 0 ? file_name : LICENCE_FILE_DEFAULT_PATH;
     int fd = open(file, O_RDWR);
     if(fd < 0) {
         return -1;
     }

     p_raw_licence = (raw_licence_t *)mmap(0, sizeof(raw_licence_t), PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
     if(p_raw_licence == MAP_FAILED) {
         close(fd);
         return -2;
     }
     
     p_raw_licence->alive_time = alive_time;
     p_raw_licence->sys_tick_count = tick_count;
     p_raw_licence->utc_timestamp = utc_timestamp;
     p_raw_licence->cksum = cksum;

     munmap(p_raw_licence, sizeof(raw_licence_t));
     close(fd);

     return 0;
}

//
// @return value
// -1: 内存分配错误; -2: 文件打开错误; -3: 文件读取错误
//
int32_t get_licence_content(const char* file_name, void** licence_str, uint32_t* size, char debug_info_str[4096]) {

    FILE* fd;
    struct stat licence_stat;
    const char* file = file_name && strlen(file_name) > 0 ? file_name : LICENCE_FILE_DEFAULT_PATH;
    raw_licence_decode_info debug_info[10];
    
    int dep;
    void *licence_buf = NULL;
    uint32_t buf_size = 0;
    void* raw_licence;

    *licence_str = NULL;
    *size = 0;

    if (stat(file, &licence_stat) < 0 || licence_stat.st_size == 0) {
        return -2;
    }

    raw_licence = malloc(licence_stat.st_size);

    if (!raw_licence) {
        return -1;
    }

    if(!(fd = fopen(file, "r"))) {
        return -2;
    }

    if (fread(raw_licence, 1, licence_stat.st_size , fd) != (size_t)licence_stat.st_size) {
        fclose(fd);
        free(raw_licence);
        return -3;
    }

    fclose(fd);

    dep = vade_licence_decode(raw_licence, licence_stat.st_size, &licence_buf, &buf_size, debug_info);

    if (debug_info_str) {
        int x = 0;

        for(; x < dep; x ++) {
            char buf[1024] = {0};
            raw_licence_info(&debug_info[x].header, buf);
            snprintf(debug_info_str + strlen(debug_info_str), 4096 - strlen(debug_info_str) - 1, 
                "------->>> Stage %i: len=%d %s \n", x, debug_info[x].data_len, buf);
        }
    }

    if (licence_buf) {
        *licence_str = (char*)licence_buf;
        *size = buf_size;
    }

    return 0;
}