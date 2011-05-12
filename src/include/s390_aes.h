/* This program is released under the Common Public License V1.0
 *
 * You should have received a copy of Common Public License V1.0 along with
 * with this program.
 */

/**
 * Authors: Felix Beck <felix.beck@de.ibm.com>
 *	    Christian Maaser <cmaaser@de.ibm.com>
 *	    Holger Dengler <hd@linux.vnet.ibm.com>
 *
 * Copyright IBM Corp. 2009, 2010, 2011
 */

#ifndef S390_AES_H
#define S390_AES_H
#include <openssl/aes.h>

#define AES_BLOCK_SIZE 16

int s390_aes_ecb(unsigned int fc, unsigned long data_length,
		 const unsigned char *in_data, const unsigned char *key,
		 unsigned char *out_data);
int s390_aes_cbc(unsigned int fc, unsigned long data_length,
		 const unsigned char *in_data, unsigned char *iv,
		 const unsigned char *key, unsigned char *out_data);
int s390_aes_cfb(unsigned int fc, unsigned long data_length,
		 const unsigned char *in_data, unsigned char *iv,
		 const unsigned char *key, unsigned char *out_data,
		 unsigned int lcfb);
int s390_aes_ofb(unsigned int fc, unsigned long data_length,
		 const unsigned char *in_data, unsigned char *iv,
		 const unsigned char *key, unsigned char *out_data);
int s390_aes_ctr(unsigned int fc, const unsigned char *in_data,
		 unsigned char *out_data, unsigned long data_length,
		 const unsigned char *key, unsigned char *ctr,
		 unsigned int ctr_width);
int s390_aes_ctrlist(unsigned int fc, unsigned long data_length,
		     const unsigned char *in_data, const unsigned char *ctrlist,
		     const unsigned char *keys, unsigned char *out_data);
int s390_aes_xts(unsigned int fc, unsigned long data_length,
		 const unsigned char *in_data, unsigned char *iv,
		 const unsigned char *key1, const unsigned char *key2,
		 unsigned int key_length, unsigned char *out_data);
#endif
