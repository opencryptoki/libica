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
#include "s390_des.h"
#include "s390_cmac.h"

#define PARM_BLOCK_SIZE 72

/*
struct cmac_des_parm_block{
	uint8_t ml;
	unsigned char reserved[7];
	unsigned char message[DES_BLOCK_SIZE];
	ica_des_vector_t iv;
	unsigned char keys[3*DES_BLOCK_SIZE];
} __attribute__((packed));

struct cmac_aes_parm_block {
	uint8_t ml;
	unsigned char reserved[7];
	unsigned char message[AES_BLOCK_SIZE];
	ica_aes_vector_t iv;
	ica_aes_key_len_256_t keys;
} __attribute__((packed));

static inline void parm_block_lookup_init2(struct parm_block_lookup *lookup,
					   unsigned char *base,
					   unsigned int block_size)
{
	lookup->block_size = block_size;
	lookup->base = base;

	switch (block_size) {
	case DES_BLOCK_SIZE: {
		struct cmac_des_parm_block *tmp = (struct cmac_des_parm_block *)&base;
		lookup->ml      = &(tmp->ml);
		lookup->message = tmp->message;
		lookup->iv      = tmp->iv;
		lookup->keys    = (unsigned char *)tmp->keys;
		break; }
	case AES_BLOCK_SIZE:
	default: {
		struct cmac_aes_parm_block *tmp = (struct cmac_aes_parm_block *)&base;
		lookup->ml      = &(tmp->ml);
		lookup->message = tmp->message;
		lookup->iv      = tmp->iv;
		lookup->keys    = tmp->keys;
		break; }
	}
}
*/

typedef unsigned char parm_block_t[PARM_BLOCK_SIZE];

struct parm_block_lookup {
	unsigned int block_size;
	unsigned char *base;
	uint8_t       *ml;
	unsigned char *message;
	unsigned char *iv;
	unsigned char *keys;
};

static inline void parm_block_lookup_init(struct parm_block_lookup *lookup,
					  parm_block_t base,
					  unsigned int block_size)
{
	lookup->block_size = block_size;
	lookup->base       = base;
	lookup->ml         = (uint8_t *)base;
	lookup->message    = (unsigned char *)(base + 8);
	lookup->iv         = (unsigned char *)(lookup->message + block_size);
	lookup->keys       = (unsigned char *)(lookup->iv + block_size);
}

static unsigned int fc_block_size(unsigned int fc)
{
	unsigned int rc;

	switch(fc) {
	case S390_CRYPTO_DEA_ENCRYPT:
	case S390_CRYPTO_TDEA_128_ENCRYPT:
	case S390_CRYPTO_TDEA_192_ENCRYPT:
		rc = DES_BLOCK_SIZE;
		break;
	case S390_CRYPTO_AES_128_ENCRYPT:
	case S390_CRYPTO_AES_192_ENCRYPT:
	case S390_CRYPTO_AES_256_ENCRYPT:
	default:
		rc = AES_BLOCK_SIZE;
		break;
	}

	return rc;
}

static int s390_cmac_hw(unsigned long fc,
			const unsigned char *message,
			unsigned long message_length,
			unsigned int  key_size, const unsigned char *key,
			unsigned int cmac_length, unsigned char *cmac,
			unsigned char *iv)
{
	parm_block_t parm_block;
	struct parm_block_lookup pb_lookup;
	unsigned int length_tail;
	unsigned long length_head;
	int rc;

	/* CMAC uses encrypt function code for generate and verify. */
	fc &= S390_CRYPTO_FUNCTION_MASK;
	memset(parm_block, 0, sizeof(parm_block));

	parm_block_lookup_init(&pb_lookup, parm_block, fc_block_size(fc));
	memcpy(pb_lookup.keys, key, key_size);

	/* copy iv into param block, if available (intermediate) */
	if (iv != NULL)
		memcpy(pb_lookup.iv, iv, pb_lookup.block_size);


	if (cmac == NULL) {
		/* intermediate */
		rc = s390_kmac(fc, pb_lookup.iv, message, message_length);
		if (rc < 0)
			return rc;

		/* rescue iv for chained calls (intermediate) */
		memcpy(iv, pb_lookup.iv, pb_lookup.block_size);
	} else {
		if (message_length) {
			length_tail = message_length % pb_lookup.block_size;
			if (length_tail)
				length_head = message_length - length_tail;
			else {
				length_head = message_length - pb_lookup.block_size;
				length_tail = pb_lookup.block_size;
			}

			if (length_head) {
				rc = s390_kmac(fc, pb_lookup.iv,
					       message, length_head);
				if (rc < 0)
					return EIO;
			}

			*pb_lookup.ml = length_tail * 8;	/* message length in bits */
			memcpy(pb_lookup.message, message + length_head, length_tail);
		}
		/* calculate final block (last/full) */
		rc = s390_pcc(fc, pb_lookup.base);
		if (rc < 0)
			return EIO;

		memcpy(cmac, pb_lookup.iv, cmac_length);
	}

	return 0;
}

inline int s390_cmac(unsigned long fc,
		     const unsigned char *message,
		     unsigned long message_length,
		     unsigned int  key_length, const unsigned char *key,
		     unsigned int  mac_length, unsigned char *mac,
		     unsigned char *iv)
{
	int hardware = 1;
	int rc;

	if (*s390_msa4_functions[fc].enabled)
		rc = s390_cmac_hw(s390_msa4_functions[fc].hw_fc,
				  message, message_length,
				  key_length, key,
				  mac_length, mac,
				  iv);
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
