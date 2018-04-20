
#include <stdint.h>
#include <stdio.h>

#include <sys/ioctl.h>
#include <linux/hdreg.h>
#include <sys/fcntl.h>
#include <unistd.h>
#include <errno.h> 
#include <string.h> 

uint32_t get_hd_serial(const char* phd, char* serial, uint32_t bsize);
uint32_t choose_hd_serial(char* hd, uint32_t hsize, char* serial, uint32_t ssize);

// lsblk
uint32_t get_hd_serial(const char* phd, char* serial, uint32_t bsize) {
    struct hd_driveid id; 
    int fd = open(phd, O_RDONLY|O_NONBLOCK);

    if (fd < 0) {
        snprintf(serial, bsize, "open: %s %s, error", phd, strerror(errno));
        return 1;
    }

    if(ioctl(fd, HDIO_GET_IDENTITY, &id)) {
        snprintf(serial, bsize, "get: %s %s, error", phd, strerror(errno));
        close(fd);
        return 1;
     }

     {
        uint32_t len = bsize > sizeof(id.serial_no) ? sizeof(id.serial_no) : bsize;

        memcpy(serial, id.serial_no, len);
     }

     close(fd);

     return 0;
}

uint32_t choose_hd_serial(char* hd, uint32_t hsize, char* serial, uint32_t ssize) {
    char disk[] = "/dev/sda";
    uint32_t i = 0;
    char buffer[100] = {0};

    *hd = 0;
    *serial = 0;

    while(i < 25) {
        if (!get_hd_serial(disk, buffer, sizeof(buffer)/sizeof(buffer[0]))) {
            snprintf(serial, ssize, "%s", buffer);
            snprintf(hd, hsize, "%s", disk);
            break;
        }

        disk[strlen(disk) - 1] += 1;
        i ++;
    }

    return *serial != 0 && *hd != 0;
}