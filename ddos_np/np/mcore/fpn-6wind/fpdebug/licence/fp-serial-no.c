#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include "../md5/md5.h"
#include <stdlib.h>
#include <ctype.h>

#include "fp.h"

#define _min(a, b) (a<b?a:b)

void serial_init(char info[1024]);

extern uint32_t get_sorted_macs(char* mac_buffer, uint32_t size, uint32_t (*f_mac_filter)(const char* name, const char* mac, uint32_t argc, void*  argv), uint32_t argc, void*  argv);
extern uint32_t choose_hd_serial(char* hd, uint32_t hsize, char* serial, uint32_t ssize);
extern uint32_t get_cpu_name(char* buffer, uint32_t size);
uint32_t get_mgr_nic(const char* config, char mgr_nic[1024]);

static uint32_t mac_filter(const char* name, const char* mac, uint32_t argc, void*  argv) {
	uint32_t i = 0;
	char* mgr_nic_name = (char*)argv;
	uint32_t mgr_count = argc;

    if (!strcmp("lo", name) || strlen(name) < 4 ||
            name[0] != 'e' || name[1] != 't' || name[2] != 'h' || isdigit(name[3]) == 0
        ) {
        return 0;
    }

    // 如果配置文件没有指定管理口，则取全部mac
    if (mgr_count == 0) {
    		return 1;
    }

    for (; i < mgr_count; i ++) {
    		if (strcmp(name, mgr_nic_name) == 0) {
    				return 1;
    		}

    		mgr_nic_name += strlen(mgr_nic_name) + 1;
    }

    return 0;
}

static void final_md5_16(md5_ctxt* ctx, char result[PRODUCT_SERIAL_CODE_LEN]) {
	uint8_t buffer[16] = {0};

	MD5Final(buffer, ctx);

	snprintf(result, PRODUCT_SERIAL_CODE_LEN,
		"%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x", 
		/*result[0], result[1], result[2], result[3], */
		buffer[4], buffer[5], buffer[6], buffer[7], 
		buffer[8], buffer[9], buffer[10], buffer[11]/*, 
		result[12], result[13], result[14], result[15] */
		);
}

// [cpu_model_name]|[macs]|[hardisk]
void serial_init(char info[1024]) {
	md5_ctxt ctx;

	MD5Init(&ctx);

	{
		// cpu
		char buffer[48 + 10] = {0};
		get_cpu_name(buffer, 49);
		strcat(buffer, "|");
		MD5Update(&ctx, (uint8_t*)buffer, strlen(buffer));

		if (info) {
			strncat(info, buffer, _min(1024 - strlen(info), strlen(buffer)));
		}
	}

	{
		// nic
		char macs[1024] = {0};
		uint32_t c = 0;

		char mgr_nic[1024];
		uint32_t mgr_count = 0;
	    	uint32_t i; 

		char* p = 0;

		mgr_count = get_mgr_nic("/hard_disk/boot/nic.config", mgr_nic);
		c = get_sorted_macs(macs, 1024, mac_filter, mgr_count, mgr_nic);
		p = macs;

		for(i = 0; i < c; i ++) {
		   
		    p += strlen(p);
		    *p = i + 1 != c ? ';' : 0;
		    p += 1;
		}

		strcat(macs, "|");
		MD5Update(&ctx, (uint8_t*)macs, strlen(macs));

		if (info) {
			strncat(info, macs, _min(1024 - strlen(info), strlen(macs)));
		}
	}

	{
		// hard disk
		char disk[100] = {0};
		char serial[100] = {0};

		choose_hd_serial(disk, sizeof(disk), serial, sizeof(serial));
		MD5Update(&ctx, (uint8_t*)serial, strlen(serial));

		if (info) {
			strncat(info, serial, _min(1024 - strlen(info), strlen(serial)));
		}
	}

	final_md5_16(&ctx, fp_shared->product_serial.data);
}

uint32_t get_mgr_nic(const char* config, char mgr_nic[1024]) {
    FILE* fp;
    uint32_t mgr_count = 0;
    char buf[255] = {0};
    char* pmgr = mgr_nic;

    if(!(fp = fopen(config, "r"))) {
        return 0;
    }

    while(fgets(buf, 255, (FILE*) fp)) {
        uint32_t len = strlen(buf);
        uint32_t blank_char = 0;
        char* p = buf;
        char nic_name[255] = {0};

        if (len < 3 || buf[0] != 'e' || buf[1] != 't' || buf[2] != 'h') {
            continue;
        }

        while(p - buf <= len && blank_char <= 2) {
            if (*p == ' ') {
                blank_char ++;

                if (blank_char == 1) {
                    memcpy(nic_name, buf, p - buf);
                }
            }

            if (blank_char == 2 && p + 1 - buf != len) {
                // find
                if (atoi(p + 1) == 0) {
                    memcpy(pmgr, nic_name, strlen(nic_name) + 1);
                    mgr_count ++;
                    pmgr += strlen(nic_name) + 1;
                }
                
                break;
            }

            p ++;
        }
    }

    fclose(fp);
    return mgr_count;
}