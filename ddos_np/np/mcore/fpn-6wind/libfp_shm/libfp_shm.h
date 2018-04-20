/*
 * Copyright (c) 2008 6WIND
 */

#ifndef _LIBFP_SHM_H_
#define _LIBFP_SHM_H_

/* Shared mem between fast-path and linux  */
/* return shared_mem_t pointer. per architecture implementation */
void *get_fp_shared(void);

#endif /* _LIBFP_SHM_H_ */
