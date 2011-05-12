/* This program is released under the Common Public License V1.0
 *
 * You should have received a copy of Common Public License V1.0 along with
 * with this program.
 */

/**
 * Authors: Ruben Straus <rstraus@de.ibm.com>
 * 	    Holger Dengler <hd@linux.vnet.ibm.com>
 *
 * Copyright IBM Corp. 2010, 2011
 */

#include <string.h>
#include <errno.h>
#include <openssl/aes.h>

#include "ica_api.h"
#include "icastats.h"
#include "init.h"
#include "s390_crypto.h"
#include "s390_aes.h"
#include "s390_cmac.h"

#define block_size 16

static int s390_cmac_hw(unsigned long fc,
			const unsigned char *message,
			unsigned long message_length,
			unsigned int  key_size, const unsigned char *key,
			unsigned int cmac_length, unsigned char *cmac)
{
	struct {
		unsigned int ml :8;   /* 8 bit unsigned message length */
		unsigned char reserved[7];
		unsigned char message[AES_BLOCK_SIZE];
		ica_aes_vector_t iv;
		ica_aes_key_len_256_t keys;
	} __attribute__((packed)) aes_parm_block;
	unsigned int length_tail;
	unsigned long length_head;
	int rc;

	/* CMAC uses encrypt function code for generate and verify. */
	fc &= S390_CRYPTO_FUNCTION_MASK;
	memset(&aes_parm_block, 0, sizeof(aes_parm_block));
	memcpy(&(aes_parm_block.keys), key, key_size);

	if (message_length) {
		length_tail = message_length % AES_BLOCK_SIZE;
		if (length_tail)
			length_head = message_length - length_tail;
		else {
			length_head = message_length - AES_BLOCK_SIZE;
			length_tail = AES_BLOCK_SIZE;
		}

		if (length_head) {
			rc = s390_kmac(fc, &(aes_parm_block.iv),
				       message, length_head);
			if (rc < 0)
				return EIO;
		}

		aes_parm_block.ml = length_tail * 8;	/* message length in bits */
		memcpy(&(aes_parm_block.message), message + length_head, length_tail);
	}

	rc = s390_pcc(fc, &aes_parm_block);
	if (rc < 0)
		return EIO;

	memcpy(cmac, &(aes_parm_block.iv), cmac_length);
	return 0;
}

inline int s390_cmac(unsigned long fc,
		     const unsigned char *message,
		     unsigned long message_length,
		     unsigned int  key_length, const unsigned char *key,
		     unsigned int  mac_length, unsigned char *mac)
{
	int hardware = 1;
	int rc;

	if (*s390_msa4_functions[fc].enabled)
		rc = s390_cmac_hw(s390_msa4_functions[fc].hw_fc,
				  message, message_length,
				  key_length, key,
				  mac_length, mac);
	else {
		hardware = 0;
		return EPERM;
	}

	if (rc)
		return rc;

	stats_increment((s390_msa4_functions[fc].hw_fc &
			S390_CRYPTO_DIRECTION_MASK) == 0 ?
			ICA_STATS_CMAC_GENERATE : ICA_STATS_CMAC_VERIFY,
			hardware);

	return rc;
}
