/* This program is released under the Common Public License V1.0
 *
 * You should have received a copy of Common Public License V1.0 along with
 * with this program.
 */

/**
 * Authors: Holger Dengler <hd@linux.vnet.ibm.com>
 *
 * Copyright IBM Corp. 2011
 */

#ifndef S390_CBCCS_H
#define S390_CBCCS_H

int s390_des_cbccs(unsigned int fc, const unsigned char *in_data,
		   unsigned char *out_data, unsigned long data_length,
		   const unsigned char *key,
		   unsigned char *iv, unsigned int variant);
int s390_aes_cbccs(unsigned int fc, const unsigned char *in_data,
		   unsigned char *out_data, unsigned long data_length,
		   const unsigned char *key, unsigned int key_length,
		   unsigned char *iv, unsigned int variant);
#endif
