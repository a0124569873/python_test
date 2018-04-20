#ifndef _FP_LICENCE_HEADER_H_
#define _FP_LICENCE_HEADER_H_

#define LICENCE_FILE_DEFAULT_PATH "/hard_disk/grub/licence"

typedef struct {
    char magic[4];                  // "VEDA"
    uint32_t index;                 // index of rsa pub
    uint32_t block_count;         // data block count

    union {
        struct {
            int32_t alive_time;            // licence total alive time
            int32_t sys_tick_count;             // sys tick count
            int32_t utc_timestamp;   // last chack time
            uint8_t cksum;
        } __attribute__((packed));

        uint8_t inner_data[0];                  // data block
    } ;
   
    uint8_t data[0];                  // data block
} __attribute__((packed)) raw_licence_t;

typedef struct {
    raw_licence_t header;
    uint32_t data_len;
} __attribute__((packed)) raw_licence_decode_info;

//
// @return value
// -1: 内存分配错误; -2: 文件打开错误; -3: 文件读取错误
//
int32_t get_licence_content(const char* file_name, void** licence_str, uint32_t* size, char debug_info_str[4096]);

uint8_t check_sum(uint8_t* bytes, uint32_t len);

uint32_t decode_json(char* json_str, uint32_t len);

//
// @return value:  0: success; -1: licence not exist; -2: mmap error
//
int32_t get_licence_time(const char* file_name, int32_t *alive_time, int32_t *tick_count, int32_t *utc_timestamp, uint8_t *cksum);
int32_t set_licence_time(const char* file_name, int32_t alive_time, int32_t tick_count, int32_t utc_timestamp, uint8_t cksum);

void raw_licence_info(const raw_licence_t* raw_licence, char buf[1024]);

#endif // _FP_LICENCE_HEADER_H_