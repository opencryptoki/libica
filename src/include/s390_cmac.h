/* This program is released under the Common Public License V1.0
 *
 * You should have received a copy of Common Public License V1.0 along with
 * with this program.
 */

/**
 * Authors: Ruben Straus <rstraus@de.ibm.com>
 *	    Holger Dengler <hd@linux.vnet.ibm.com>
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

#ifndef S390_CMAC
#define S390_CMAC_H

#define PARM_BLOCK_SIZE 72

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

static inline unsigned int fc_block_size(unsigned int fc)
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

static inline void _stats_increment(unsigned int fc, int hw, int direction)
{
	switch(fc) {
		case 1:
		case 9:
			stats_increment(ICA_STATS_DES_CMAC, hw, direction);
			break;
		case 2:
		case 3:
		case 10:
		case 11:
			stats_increment(ICA_STATS_3DES_CMAC, hw, direction);
			break;
		case 18:
		case 19:
		case 20:
		case 26:
		case 27:
		case 28:
			stats_increment(ICA_STATS_AES_CMAC, hw, direction);
			break;
		default:
			break;
	}
}

static inline int s390_cmac_hw(unsigned long fc,
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
		memset(pb_lookup.keys, 0, key_size);
		if (rc < 0)
			return rc;

		_stats_increment(fc, ALGO_HW, ENCRYPT);

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
				if (rc < 0) {
					memset(pb_lookup.keys, 0, key_size);
					return EIO;
				}
				_stats_increment(fc, ALGO_HW, ENCRYPT);
			}

			*pb_lookup.ml = length_tail * 8;	/* message length in bits */
			memcpy(pb_lookup.message, message + length_head, length_tail);
		}
		/* calculate final block (last/full) */
		rc = s390_pcc(fc, pb_lookup.base);
		memset(pb_lookup.keys, 0, key_size);
		if (rc < 0)
			return EIO;

		_stats_increment(fc, ALGO_HW, ENCRYPT);
		memcpy(cmac, pb_lookup.iv, cmac_length);
	}

	return 0;
}

static inline int s390_cmac(unsigned long fc,
		     const unsigned char *message,
		     unsigned long message_length,
		     unsigned int  key_length, const unsigned char *key,
		     unsigned int  mac_length, unsigned char *mac,
		     unsigned char *iv)
{
	int rc = ENODEV;

	if (*s390_msa4_functions[fc].enabled)
		rc = s390_cmac_hw(s390_msa4_functions[fc].hw_fc,
				  message, message_length,
				  key_length, key,
				  mac_length, mac,
				  iv);

	return rc;
}
#endif
