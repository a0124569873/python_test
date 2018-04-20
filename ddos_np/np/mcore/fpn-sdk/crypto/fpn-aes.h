/*
 * Copyright(c) 2012 6WIND, All rights reserved.
 */
#ifndef _FPN_AES_H_
#define _FPN_AES_H_

#define fpn_aes_cbc_encrypt(m, o, l, i, K, k) \
	fpn_aes_cbc(m, o, l, i, K, k, AES_ENCRYPT)
#define fpn_aes_cbc_decrypt(m, o, l, i, K, k) \
	fpn_aes_cbc(m, o, l, i, K, k, AES_DECRYPT)
#define fpn_aes_xcbc_mac(a, k, m, o, l) \
	fpn_generic_aes_xcbc_mac(a, k, m, o, l)

#endif /* _FPN_AES_H_ */

