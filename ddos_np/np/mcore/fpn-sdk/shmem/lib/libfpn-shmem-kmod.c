/*
 * Copyright (c) 2012 6WIND
 */

#ifndef _LARGEFILE64_SOURCE
#define _LARGEFILE64_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <syslog.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "shmem/fpn-shmem.h"

#define LIBFP_SHM_DEBUG 0

#if LIBFP_SHM_DEBUG == 1
#define TRACE(fmt, args...) syslog(LOG_DEBUG, "libfpn_shmem: " fmt, ##args)
#else
#define TRACE(fmt, args...) do {} while(0)
#endif

#define SHM_PERROR(str) syslog(LOG_ERR, "libfpn_shmem: " str ": %s", strerror(errno))

/* Shared mem between kernel and userland */
void *fpn_shmem_mmap(const char *shm_name, void *map_addr, size_t mapsize)
{
	int memfd, procfd, n;
	struct stat stats;
	void *shmp;
	char buf[BUFSIZ];
	char *string;
	uint64_t shm_size;
	char name[32];
	uint32_t minor;
	uint32_t major;
	int create = 0;
	uint64_t pagemask;
	int mapping;

	/*
	 * Get shared memory virtual address:
	 *  dump /proc/mcore/fp_shared
	 */
	procfd = open("/proc/sys/fpn_shmem/list_shm", O_RDONLY);
	if(procfd < 0) {
		SHM_PERROR("open procfs");
		return(NULL);
	}
	n = read(procfd, buf, sizeof(buf)-1);
	if(n < 0) {
		SHM_PERROR("read procfs");
		return(NULL);
	}
	buf[n] = '\0';
	close(procfd);

	/* parse procfs */
	string = buf;
	while (string) {
		n = sscanf(string, "%31s 0x%"PRIX64" %u %u\n", name, &shm_size, &major, &minor);
		if (n == 4) {
			if (strcmp(name, shm_name) == 0)
				break;
		}
		string = strchr(string, '\n');
		if (!string)
			return NULL;
		string ++;
	}

	if (major == 0) {
		syslog(LOG_ERR, "libfpn_shmem: Could not extract major number\n");
		return(NULL);
	}

	TRACE("Got shared memory infos from /proc: %s, major=[%u], minor=[%u] size=[0x%zx]\n",
			shm_name, major, minor, shm_size);

	pagemask = getpagesize() - 1;
	mapsize = (mapsize + pagemask) & ~pagemask;
	if (mapsize > shm_size) {
		syslog(LOG_ERR, "libfpn_shmem: map size is too large\n");
		return NULL;
	}
	/*
	 * open or create char device
	 */
	snprintf(buf, sizeof(buf), "/dev/%s", name);
	if (stat(buf, &stats) < 0) {
		TRACE("No char device for %s: create it", shm_name);
		create = 1;
	} else {
		if (!S_ISCHR(stats.st_mode)) {
			TRACE("Got wrong file mode (%u) for %s: recreate it", stats.st_mode, shm_name);
			unlink(buf);
			create = 1;
		}
	}
	if (create) {
		if (mknod(buf, S_IFCHR | 0666, (major << 8) | minor) < 0) {
			SHM_PERROR("Could not create node device");
			return NULL;
		}
	}

	memfd = open(buf, O_RDWR|O_SYNC);
	if(memfd == -1) {
		SHM_PERROR("can't open shared memory device");
		return NULL;
	}
	/*
	 * map shared memory.
	 */
	mapping = MAP_SHARED;
	if (map_addr != NULL)
		mapping |= MAP_FIXED;

	shmp = mmap(map_addr, mapsize,
		    PROT_READ|PROT_WRITE, mapping, memfd, 0);
	close(memfd);
	if (shmp == MAP_FAILED) {
		SHM_PERROR("mmap");
		return NULL; 
	}
	TRACE("Shared memory <%s> mapped (virt=[0x%p], size [0x%zx] bytes)\n",
			shm_name, shmp, mapsize);

	return shmp;
	/* "/dev/mem" will be (automatically) closed when the process will exit */
}

int fpn_shmem_add(const char *shm_name, size_t shm_size)
{
	int procfd, n;
	char buf[BUFSIZ];
	uint64_t pagemask = getpagesize() - 1;

	shm_size = (shm_size + pagemask) & ~pagemask;
	procfd = open("/proc/sys/fpn_shmem/add_shm", O_WRONLY);
	if(procfd < 0) {
		SHM_PERROR("open procfs");
		return -1;
	}

	snprintf(buf, BUFSIZ, "%s shm_size=%zu\n", shm_name, shm_size);
	n = write(procfd, buf, strlen(buf));
	close(procfd);
	if (n < 0) {
		SHM_PERROR("write procfs");
		return  -1;
	}
	return 0;
}

int fpn_shmem_del(const char *shm_name)
{
	int procfd, n;
	char buf[BUFSIZ];

	/* Delete char device */
	snprintf(buf, BUFSIZ, "/dev/%s\n", shm_name);
	unlink(buf);

	/* Delete shared memory */
	procfd = open("/proc/sys/fpn_shmem/del_shm", O_WRONLY);
	if(procfd < 0) {
		SHM_PERROR("open procfs");
		return -1;
	}

	snprintf(buf, BUFSIZ, "%s\n", shm_name);
	n = write(procfd, buf, strlen(buf));
	close(procfd);
	if (n < 0) {
		SHM_PERROR("write procfs");
		return -1;
	}
	return 0;
}
