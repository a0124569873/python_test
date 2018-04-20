#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <stdlib.h>


#include "fp.h"
#include "fp-licence-header.h"
#include "../json/cJSON.h"

#include <fcntl.h>
#include <sys/stat.h>

#ifndef min
#define min(a, b) (a > b ? a : b)
#endif

uint32_t verify_licence(const char* file_name, char debug_info_str[4096], uint32_t for_test);
void serial_init(char info[1024]);
uint32_t decode_json(char* json_str, uint32_t len);

//
uint32_t verify_licence(const char* file_name, char debug_info_str[4096], uint32_t for_test) {
    char* licence_str;
    uint32_t size;
    cJSON *licence_obj, *obj;
    uint32_t status = LICENCE_UNINIT;

#define SET_STATUS(s) if(!for_test) { fp_shared->licence.status = s; status = s; } else { status = s; }
    serial_init(NULL);

    get_licence_content(file_name, (void**)&licence_str, &size, debug_info_str);

    if (!licence_str || size == 0) {
        SET_STATUS(LICENCE_MISSING)
        return status;
    }

    licence_obj = cJSON_Parse(licence_str);

    if (debug_info_str) snprintf(debug_info_str + strlen(debug_info_str), 4096 - strlen(debug_info_str) - 1, "%s", licence_str);

    free(licence_str);

    if (cJSON_IsInvalid(licence_obj)) {
        SET_STATUS(LICENCE_MALFORM)
        return status;
    }

    // id
    obj = cJSON_GetObjectItem(licence_obj, "id");
    if (!cJSON_IsString(obj)) {
        SET_STATUS(LICENCE_MALFORM)
        cJSON_Delete(licence_obj);
        return status;
    }

    if (
        fp_shared->licence.status == LICENCE_VALID &&
        strncmp(fp_shared->licence.id, obj->valuestring, min(sizeof(fp_shared->licence.id) - 1, strlen(obj->valuestring))) == 0) {
        SET_STATUS(LICENCE_VALID)
        return status;
    }

    if (!for_test) memcpy(fp_shared->licence.id, obj->valuestring, min(sizeof(fp_shared->licence.id) - 1, strlen(obj->valuestring)));

    // serial
    obj = cJSON_GetObjectItem(licence_obj, "device_id");
    if (!cJSON_IsString(obj)) {
        SET_STATUS(LICENCE_MALFORM)
        cJSON_Delete(licence_obj);
        return status;
    }

    if (strncmp(obj->valuestring, fp_shared->product_serial.data, 
        min(PRODUCT_SERIAL_CODE_LEN, strlen(obj->valuestring))) != 0) {
        SET_STATUS(LICENCE_DEVICE_NOT_MATCH)
        cJSON_Delete(licence_obj);
        return status;
    }

    // model
    obj = cJSON_GetObjectItem(licence_obj, "model");
    if (!cJSON_IsString(obj)) {
        SET_STATUS(LICENCE_MALFORM)
        cJSON_Delete(licence_obj);
        return status;
    }

    if (!for_test) memcpy(fp_shared->licence.model, obj->valuestring, min(sizeof(fp_shared->licence.model) - 1, strlen(obj->valuestring)));

    // type
    obj = cJSON_GetObjectItem(licence_obj, "type");
    if (!cJSON_IsString(obj)) {
        SET_STATUS(LICENCE_MALFORM)
        cJSON_Delete(licence_obj);
        return status;
    }

    if (strcmp(obj->valuestring, "official") == 0) {
        if (!for_test) fp_shared->licence.type = LICENCE_TYPE_OFFICIAL;
        SET_STATUS(LICENCE_TYPE_OFFICIAL)
    } else if (strcmp(obj->valuestring, "test") == 0) {
        if (!for_test) fp_shared->licence.type = LICENCE_TYPE_TEST;
    } else {
        SET_STATUS(LICENCE_TYPE_ERROR)
        cJSON_Delete(licence_obj);
        return status;
    }

    // create_time
    obj = cJSON_GetObjectItem(licence_obj, "create_time");
    if (!cJSON_IsNumber(obj)) {
        SET_STATUS(LICENCE_MALFORM)
        cJSON_Delete(licence_obj);
        return status;
    }

    if (!for_test) fp_shared->licence.create_time = (uint32_t)obj->valueint;

    // start_time
    obj = cJSON_GetObjectItem(licence_obj, "start_time");
    if (!cJSON_IsNumber(obj)) {
        SET_STATUS(LICENCE_MALFORM)
        cJSON_Delete(licence_obj);
        return status;
    }

    if (!for_test) fp_shared->licence.start_time = (uint32_t)obj->valueint;

    // end_time
    obj = cJSON_GetObjectItem(licence_obj, "end_time");
    if (!cJSON_IsNumber(obj)) {
        SET_STATUS(LICENCE_MALFORM)
        cJSON_Delete(licence_obj);
        return status;
    }

    if (!for_test) fp_shared->licence.end_time = (uint32_t)obj->valueint;

    // max_hosts
    obj = cJSON_GetObjectItem(licence_obj, "max_hosts");
    if (!cJSON_IsNumber(obj)) {
        SET_STATUS(LICENCE_MALFORM)
        cJSON_Delete(licence_obj);
        return status;
    }

    if (!for_test) fp_shared->licence.max_hosts = (uint32_t)obj->valueint;

    // max_flows
    obj = cJSON_GetObjectItem(licence_obj, "max_flows");
    if (!cJSON_IsNumber(obj)) {
        SET_STATUS(LICENCE_MALFORM)
        cJSON_Delete(licence_obj);
        return status;
    }

    if (!for_test) fp_shared->licence.max_flows = (uint32_t)obj->valueint;

    // desc
    obj = cJSON_GetObjectItem(licence_obj, "desc");
    if (!cJSON_IsString(obj)) {
        SET_STATUS(LICENCE_MALFORM)
        cJSON_Delete(licence_obj);
        return status;
    }

    if (!for_test) memcpy(fp_shared->licence.desc, obj->valuestring, min(sizeof(fp_shared->licence.desc) - 1, strlen(obj->valuestring)));

    // lang
    obj = cJSON_GetObjectItem(licence_obj, "lang");
    if (!cJSON_IsString(obj)) {
        SET_STATUS(LICENCE_MALFORM)
        cJSON_Delete(licence_obj);
        return status;
    }

    if (!for_test) memcpy(fp_shared->licence.lang, obj->valuestring, min(sizeof(fp_shared->licence.lang) - 1, strlen(obj->valuestring)));

    // user
    obj = cJSON_GetObjectItem(licence_obj, "user");
    if (!cJSON_IsString(obj)) {
        SET_STATUS(LICENCE_MALFORM)
        cJSON_Delete(licence_obj);
        return status;
    }

    if (!for_test) memcpy(fp_shared->licence.user, obj->valuestring, min(sizeof(fp_shared->licence.user) - 1, strlen(obj->valuestring)));

    // licence_owner
    obj = cJSON_GetObjectItem(licence_obj, "licence_owner");
    if (!cJSON_IsString(obj)) {
        SET_STATUS(LICENCE_MALFORM)
        cJSON_Delete(licence_obj);
        return status;
    }

    if (!for_test) memcpy(fp_shared->licence.licence_owner, obj->valuestring, min(sizeof(fp_shared->licence.licence_owner) - 1, strlen(obj->valuestring)));

    // copy_right
    obj = cJSON_GetObjectItem(licence_obj, "copy_right");
    if (!cJSON_IsString(obj)) {
        SET_STATUS(LICENCE_MALFORM)
        cJSON_Delete(licence_obj);
        return status;
    }

    if (!for_test) memcpy(fp_shared->licence.copy_right, obj->valuestring, min(sizeof(fp_shared->licence.copy_right) - 1, strlen(obj->valuestring)));

    // parse ok
    SET_STATUS(LICENCE_VALID)

    if (!for_test) {
        int32_t alive_time = 0;
        int32_t sys_tick_count = 0;
        int32_t utc_timestamp = 0;
        uint8_t cksum = 0;

        if (fp_shared->licence.status == LICENCE_VALID &&
            get_licence_time(file_name, &alive_time, &sys_tick_count, &utc_timestamp, &cksum) >= 0 ) {

            uint32_t ar[4] = {alive_time, sys_tick_count, utc_timestamp, cksum};

            if (check_sum((uint8_t*)ar, 13) != 0) {
                fp_shared->licence.status = LICENCE_MALFORM;
            } else {
                fp_shared->licence.licence_time.alive_time = alive_time;
                fp_shared->licence.licence_time.sys_tick_count = sys_tick_count;
                fp_shared->licence.licence_time.utc_timestamp = utc_timestamp;
            }
        } else {
            fp_shared->licence.licence_time.alive_time = 0;
            fp_shared->licence.licence_time.sys_tick_count = 0;
            fp_shared->licence.licence_time.utc_timestamp = 0;
        }
    }

    cJSON_Delete(licence_obj);
    return status;
#undef SET_STATUS
}