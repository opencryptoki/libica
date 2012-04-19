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

#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

#include "ica_api.h"
#include "icastats.h"
#include "init.h"
#include "s390_crypto.h"
#include "s390_aes.h"
#include "s390_des.h"
#include "s390_aux.h"
#include "s390_common.h"

/* get next multiple of blocksize (bs) of n */
#define NEXT_BS(n, bs) ((n + (bs - 1)) & (~(bs - 1)))

#define LARGE_MSG_CHUNK 4096	/* page size */

inline int s390_ctr_hw(unsigned int function_code, unsigned long data_length,
                       const unsigned char *in_data, const unsigned char *key,
                       unsigned char *out_data, const unsigned char *ctrlist)
{
        int rc = -1;
	rc = s390_kmctr(function_code, key, out_data, in_data,
			data_length, ctrlist);
	if (rc >= 0)
		return 0;
	else
		return EIO;
}

static inline int __s390_des_ctrlist(unsigned int fc, unsigned long data_length,
				     const unsigned char *in_data,
				     const unsigned char *ctrlist,
				     const unsigned char *key,
				     unsigned char *out_data)
{
	int rc = EPERM;
	int hardware = 1;

	if (*s390_msa4_functions[fc].enabled)
		rc = s390_ctr_hw(s390_msa4_functions[fc].hw_fc,
				 data_length, in_data, key,
				 out_data, ctrlist);
	if (rc) {
		hardware = 0;
		return rc;
	}
	switch (s390_msa4_functions[fc].hw_fc & S390_CRYPTO_FUNCTION_MASK) {
	case S390_CRYPTO_DEA_ENCRYPT:
		stats_increment((s390_msa4_functions[fc].hw_fc &
				S390_CRYPTO_DIRECTION_MASK) ==
				0 ? ICA_STATS_DES_ENCRYPT :
				ICA_STATS_DES_DECRYPT, hardware);
		break;
	case S390_CRYPTO_TDEA_128_ENCRYPT:
	case S390_CRYPTO_TDEA_192_ENCRYPT:
		stats_increment((s390_msa4_functions[fc].hw_fc &
				S390_CRYPTO_DIRECTION_MASK) ==
				0 ? ICA_STATS_3DES_ENCRYPT :
				ICA_STATS_3DES_DECRYPT, hardware);
		break;
	}
	return rc;
}

static inline int __s390_aes_ctrlist(unsigned int fc, unsigned long data_length,
				     const unsigned char *in_data,
				     const unsigned char *ctrlist,
				     const unsigned char *key,
				     unsigned char *out_data)
{
	int rc = EPERM;
	int hardware = 1;

	if (*s390_msa4_functions[fc].enabled)
		rc = s390_ctr_hw(s390_msa4_functions[fc].hw_fc,
				 data_length, in_data, key,
				 out_data, ctrlist);
	if (rc) {
		hardware = 0;
		return rc;
	}
	stats_increment((s390_msa4_functions[fc].hw_fc &
			 S390_CRYPTO_DIRECTION_MASK) == 0 ?
			 ICA_STATS_AES_ENCRYPT : ICA_STATS_AES_DECRYPT,
			hardware);
	return rc;
}

inline int s390_des_ctrlist(unsigned int fc, unsigned long data_length,
			    const unsigned char *in_data,
			    const unsigned char *ctrlist,
			    const unsigned char *key, unsigned char *out_data)
{
	int rc = 0;
	unsigned char rest_in_data[DES_BLOCK_SIZE];
	unsigned char rest_out_data[DES_BLOCK_SIZE];
	unsigned long rest_data_length;
	unsigned long tmp_data_length;

	rest_data_length = data_length % DES_BLOCK_SIZE;
	tmp_data_length = data_length - rest_data_length;

	if (tmp_data_length) {
		rc = __s390_des_ctrlist(fc, tmp_data_length, in_data,
					ctrlist, key, out_data);
		if (rc)
			return rc;
	}

	if (rest_data_length) {
		memcpy(rest_in_data, in_data + tmp_data_length,
		       rest_data_length);

		rc = __s390_des_ctrlist(fc, DES_BLOCK_SIZE,
					rest_in_data,
					ctrlist + tmp_data_length,
					key, rest_out_data);
		if (rc)
			return rc;

		memcpy(out_data + tmp_data_length,
		       rest_out_data, rest_data_length);
	}

	return rc;
}

inline int s390_aes_ctrlist(unsigned int fc, unsigned long data_length,
			    const unsigned char *in_data,
			    const unsigned char *ctrlist,
			    const unsigned char *key, unsigned char *out_data)
{
	int rc = 0;
	unsigned char rest_in_data[AES_BLOCK_SIZE];
	unsigned char rest_out_data[AES_BLOCK_SIZE];
	unsigned long rest_data_length;
	unsigned long tmp_data_length;

	rest_data_length = data_length % AES_BLOCK_SIZE;
	tmp_data_length = data_length - rest_data_length;

	if (tmp_data_length) {
		rc = __s390_aes_ctrlist(fc, tmp_data_length, in_data,
					ctrlist, key, out_data);
		if (rc)
			return rc;
	}

	if (rest_data_length) {
		memcpy(rest_in_data, in_data + tmp_data_length,
		       rest_data_length);

		rc = __s390_aes_ctrlist(fc, AES_BLOCK_SIZE,
					rest_in_data,
					ctrlist + tmp_data_length,
					key, rest_out_data);
		if (rc)
			return rc;

		memcpy(out_data + tmp_data_length,
		       rest_out_data, rest_data_length);
	}

	return rc;
}

inline int s390_des_ctr(unsigned int fc, const unsigned char *in_data,
			unsigned char *out_data, unsigned long data_length,
			const unsigned char *key, unsigned char *ctr,
			unsigned int ctr_width)
{
	const unsigned char *src;
	unsigned char *tmp_ctrlist = NULL;
	unsigned long chunk_length;
	unsigned long rest_length;
	unsigned long tmp_length;

	int rc = 0;

	if (data_length <= DES_BLOCK_SIZE) {
		/* short message handling */
		rc = s390_des_ctrlist(fc, data_length, in_data, ctr,
				      key, out_data);
		if (rc)
			goto free_out;

		ctr_inc_single(ctr, DES_BLOCK_SIZE, ctr_width);
		return rc;
	}

	/* find largest possible message chunk */
	/* get next multiple of blocksize of data_length */
	chunk_length = NEXT_BS(data_length, DES_BLOCK_SIZE);
	tmp_ctrlist = malloc(chunk_length);

	/* page size chunk fall back */
	if ((!tmp_ctrlist) && (data_length > LARGE_MSG_CHUNK)) {
		chunk_length = LARGE_MSG_CHUNK;
		tmp_ctrlist = malloc(chunk_length);
	}

	/* single block chunk fall back */
	if (!tmp_ctrlist)
		chunk_length = DES_BLOCK_SIZE;

	for (src = in_data, rest_length = data_length;
	     src < (in_data + data_length);
	     src += chunk_length, out_data += chunk_length,
	     rest_length -= chunk_length) {
		tmp_length = (rest_length < chunk_length) ?
			      rest_length : chunk_length;
		if (tmp_ctrlist) {
			ctr_inc_block(ctr, DES_BLOCK_SIZE, ctr_width,
				      tmp_ctrlist,
				      NEXT_BS(tmp_length, DES_BLOCK_SIZE));

			rc = s390_des_ctrlist(fc, tmp_length, src,
					      tmp_ctrlist, key, out_data);
			if (rc)
				goto free_out;
		} else {
			rc = s390_des_ctrlist(fc, tmp_length, src,
					      ctr, key, out_data);
			if (rc)
				goto free_out;

			ctr_inc_single(ctr, DES_BLOCK_SIZE, ctr_width);
		}
	}

free_out:
	if (tmp_ctrlist)
		free(tmp_ctrlist);

	return rc;
}

inline int s390_aes_ctr(unsigned int fc, const unsigned char *in_data,
			unsigned char *out_data, unsigned long data_length,
			const unsigned char *key, unsigned char *ctr,
			unsigned int ctr_width)
{
	const unsigned char *src;
	unsigned char *tmp_ctrlist = NULL;
	unsigned long chunk_length;
	unsigned long rest_length;
	unsigned long tmp_length;

	int rc = 0;

	if (data_length <= AES_BLOCK_SIZE) {
		/* short message handling */
		rc = s390_aes_ctrlist(fc, data_length, in_data, ctr,
				      key, out_data);
		if (rc)
			goto free_out;

		ctr_inc_single(ctr, AES_BLOCK_SIZE, ctr_width);
		return rc;
	}

	/* find largest possible message chunk */
	chunk_length = NEXT_BS(data_length, AES_BLOCK_SIZE);
	tmp_ctrlist = malloc(chunk_length);

	/* page size chunk fall back */
	if ((!tmp_ctrlist) && (data_length > LARGE_MSG_CHUNK)) {
		chunk_length = LARGE_MSG_CHUNK;
		tmp_ctrlist = malloc(chunk_length);
	}

	/* single block chunk fall back */
	if (!tmp_ctrlist)
		chunk_length = AES_BLOCK_SIZE;

	for (src = in_data, rest_length = data_length;
	     src < (in_data + data_length);
	     src += chunk_length, out_data += chunk_length,
	     rest_length -= chunk_length) {
		tmp_length = (rest_length < chunk_length) ?
			      rest_length : chunk_length;
		if (tmp_ctrlist) {
			ctr_inc_block(ctr, AES_BLOCK_SIZE, ctr_width,
				      tmp_ctrlist,
				      NEXT_BS(tmp_length, AES_BLOCK_SIZE));

			rc = s390_aes_ctrlist(fc, tmp_length, src,
					      tmp_ctrlist, key, out_data);
			if (rc)
				goto free_out;
		} else {
			/* single block fall back */
			rc = s390_aes_ctrlist(fc, tmp_length, src,
					      ctr, key, out_data);
			if (rc)
				goto free_out;

			ctr_inc_single(ctr, AES_BLOCK_SIZE, ctr_width);
		}
	}

free_out:
	if (tmp_ctrlist)
		free(tmp_ctrlist);

	return rc;
}
