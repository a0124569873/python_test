
#ifndef _READ_FP_SHARED_H_
#define _READ_FP_SHARED_H_

#if defined(__LinuxKernelVNB__)

#include <fp.h>
#include <shmem/fpn-shmem.h>

//share memory
shared_mem_t *fp_shared;

#endif

#endif