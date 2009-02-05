/* This program is released under the Common Public License V1.0
 *
 * You should have received a copy of Common Public License V1.0 along with
 * with this program.
 */

/**
 * Authors: Felix Beck <felix.beck@de.ibm.com>
 *	    Christian Maaser <cmaaser@de.ibm.com>
 *
 * Copyright IBM Corp. 2009
 */

#ifndef S390_AES_H
#define S390_AES_H
#include <openssl/aes.h>

int s390_aes_ecb(unsigned int fc, unsigned int input_length,
                 unsigned char *input_data, unsigned char *keys,
		 unsigned char *output_data);
int s390_aes_cbc(unsigned int fc, unsigned int input_length,
                 unsigned char *input_data, ica_aes_vector_t *iv,
                 unsigned char *keys, unsigned char *output_data);

#endif

