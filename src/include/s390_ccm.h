/* This program is released under the Common Public License V1.0
 *
 * You should have received a copy of Common Public License V1.0 along with
 * with this program.
 */

/**
 * Authors: Ruben Straus <rstraus@de.ibm.com>
 * 	    Holger Dengler <hd@linux.vnet.ibm.com>
 *
 * Copyright IBM Corp. 2010
 */

#ifndef S390_CCM
#define S390_CCM_H

#define S390_CCM_MAX_NONCE_LENGTH 13
#define S390_CCM_MIN_NONCE_LENGTH  7
#define S390_CCM_MAX_MAC_LENGTH   16
#define S390_CCM_MIN_MAC_LENGTH    4

unsigned int s390_ccm(unsigned int function_code,
		      unsigned char *payload, unsigned long payload_length,
		      unsigned char *ciphertext,
		      const unsigned char *assoc_data, unsigned long assoc_data_length,
		      const unsigned char *nonce, unsigned long nonce_length,
		      unsigned char *mac, unsigned long mac_length,
		      const unsigned char *key);
/*
int s390_ccm(unsigned long fc, unsigned long payload_length,
	unsigned char *payload, unsigned long assoc_data_length,
	unsigned char *assoc_data, unsigned int nonce_length,
	unsigned char *nonce, unsigned int cbc_mac_length,
	unsigned int key_length, unsigned char *key,
	unsigned long cipther_text_length, unsigned char *cipher_text);
*/
#endif

