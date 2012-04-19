/* This program is released under the Common Public License V1.0
 *
 * You should have received a copy of Common Public License V1.0 along with
 * with this program.
 */

/**
 * Authors: Felix Beck <felix.beck@de.ibm.com>
 * 	    Holger Dengler <hd@linux.vnet.ibm.com>
 *
 * Copyright IBM Corp. 2010, 2011
 */

#ifndef S390_GCM_H
#define S390_GCM_H

#define S390_GCM_MAX_TEXT_LENGTH (0x0000000fffffffe0ul) /* (2^31)-32 */
#define S390_GCM_MAX_AAD_LENGTH  (0x2000000000000000ul) /* (2^61)    */
#define S390_GCM_MAX_IV_LENGTH   (0x2000000000000000ul) /* (2^61)    */

int s390_gcm(unsigned int function_code,
	     unsigned char *plaintext, unsigned long text_length,
	     unsigned char *ciphertext,
	     const unsigned char *iv, unsigned long iv_length,
	     const unsigned char *aad, unsigned long aad_length,
	     unsigned char *tag, unsigned long tag_length,
	     const unsigned char *key);
inline int s390_ghash(const unsigned char *in_data, unsigned long data_length,
		      const unsigned char *key, unsigned char *iv);
#endif
