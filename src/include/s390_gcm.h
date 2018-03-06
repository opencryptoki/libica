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

#include "s390_ctr.h"

#define S390_GCM_MAX_TEXT_LENGTH (0x0000000fffffffe0ul) /* (2^31)-32 */
#define S390_GCM_MAX_AAD_LENGTH  (0x2000000000000000ul) /* (2^61)    */
#define S390_GCM_MAX_IV_LENGTH   (0x2000000000000000ul) /* (2^61)    */

/* the recommended iv length for GCM is 96 bit or 12 byte */
#define GCM_RECOMMENDED_IV_LENGTH 12

/* ctr with for GCM is specified with 32 bit */
#define GCM_CTR_WIDTH 32

/* Helper struct containing last uncomplete ciphertext block
 * with padding, aad_length and ciphertext_length. */
unsigned char zero_block[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static unsigned char partial_j[] = {
	0x00, 0x00, 0x00, 0x01,
};

struct pad_meta {
	unsigned char pad[AES_BLOCK_SIZE];
	uint64_t length_a;
	uint64_t length_b;
} __attribute__((packed));

/**
 * GCM context struct
 */
struct kma_ctx_t {
	unsigned char reserved[12];
	uint32_t cv;
	ica_aes_vector_t tag;
	ica_aes_vector_t subkey_h;
	uint64_t total_aad_length;
	uint64_t total_input_length;
	ica_aes_vector_t j0;
	ica_aes_key_len_256_t key;
	// Above this line: KMA parmblock, never change!
	uint32_t version; /* 0x00 */
	uint32_t direction;
	uint32_t key_length;
	uint32_t subkey_provided;
	// Below this line: KMA simulation via MSA 4
	unsigned char* iv;
	uint32_t iv_length;
	ica_aes_vector_t ucb;
	uint32_t done;
	uint32_t intermediate;
	uint32_t first_time;
} __attribute__((packed));

static inline int s390_ghash_hw(unsigned int fc,
				const unsigned char *in_data,
				unsigned long data_length,
				unsigned char *iv,
				const unsigned char *subkey)
{
	struct {
		unsigned char iv[AES_BLOCK_SIZE];
		unsigned char hash_subkey[AES_BLOCK_SIZE];
	} __attribute__((packed)) parmblock;
	int rc = 0;
	int hardware = ALGO_HW;

	memcpy(parmblock.iv, iv, AES_BLOCK_SIZE);
	memcpy(parmblock.hash_subkey, subkey, AES_BLOCK_SIZE);

	rc = s390_kimd(fc, &parmblock, in_data, data_length);
	if((unsigned long)rc == data_length) {
		/* All data has been processed */
		memcpy(iv, parmblock.iv, AES_BLOCK_SIZE);
		stats_increment(ICA_STATS_GHASH, hardware, ENCRYPT);
		return 0;
	}

	return EIO;
}

static inline int s390_ghash(const unsigned char *in_data, unsigned long data_length,
		      const unsigned char *key, unsigned char *iv)
{
	if (!s390_kimd_functions[GHASH].enabled)
		return ENODEV;

	return s390_ghash_hw(s390_kimd_functions[GHASH].hw_fc,
			     in_data, data_length,
			     iv, key);
}

static inline unsigned int __compute_j0(const unsigned char *iv,
					unsigned int iv_length,
					const unsigned char *subkey_h,
					unsigned char *j0)
{
	int rc;
	struct pad_meta iv_pad_meta;
	unsigned long head_length;
	unsigned long tail_length;

	/* iv_length of 12 bytes is recommended */
	if (iv_length == GCM_RECOMMENDED_IV_LENGTH) {
		memcpy(j0, iv, iv_length);
		memcpy(j0 + iv_length, partial_j, sizeof(partial_j));
		return 0;
	}

	memset(j0, 0x00, AES_BLOCK_SIZE);

	memset(iv_pad_meta.pad, 0x00, sizeof(iv_pad_meta.pad));
	iv_pad_meta.length_a = (uint64_t)0ul;	/* unused for j0 */
	iv_pad_meta.length_b = (uint64_t)(iv_length * 8ul);

	tail_length = iv_length % AES_BLOCK_SIZE;
	head_length = iv_length - tail_length;

	if (head_length) {
		rc = s390_ghash(iv, head_length, subkey_h, j0);
		if (rc)
			return rc;
	}

	if (tail_length) {
		memcpy(iv_pad_meta.pad, iv + head_length, tail_length);
		rc = s390_ghash((unsigned char *)&iv_pad_meta,
				sizeof(iv_pad_meta),
				subkey_h, j0);
		if (rc)
			return rc;
	} else {
		/* no padding necessary, only ghash meta information */
		rc = s390_ghash((unsigned char *)&iv_pad_meta.length_a,
				AES_BLOCK_SIZE,
				subkey_h, j0);
		if (rc)
			return rc;
	}

	return 0;
}

static inline unsigned int s390_gcm_authenticate(const unsigned char *ciphertext, unsigned long text_length,
					  const unsigned char *aad, unsigned long aad_length,
					  const unsigned char *subkey_h, unsigned char *iv)
{
	unsigned int rc;
	unsigned char aad_pad[AES_BLOCK_SIZE];
	unsigned long head_length;
	unsigned long tail_length;
	struct pad_meta c_pad_meta;

	memset(iv, 0x00, AES_BLOCK_SIZE);

	memset(c_pad_meta.pad, 0x00, sizeof(c_pad_meta.pad));
	c_pad_meta.length_a = (uint64_t)(aad_length * 8ul);
	c_pad_meta.length_b = (uint64_t)(text_length * 8ul);

	if (aad_length) {
		tail_length = aad_length % AES_BLOCK_SIZE;
		head_length = aad_length - tail_length;

		/* ghash aad head */
		if (head_length) {
			rc = s390_ghash(aad, head_length, subkey_h, iv);
			if (rc)
				return rc;
		}

		/* ghash aad tail */
		if (tail_length) {
			memset(aad_pad, 0x00, AES_BLOCK_SIZE);
			memcpy(aad_pad, aad + head_length, tail_length);

			rc = s390_ghash(aad_pad, AES_BLOCK_SIZE, subkey_h, iv);
			if (rc)
				return rc;
		}
	}

	if (text_length) {
		tail_length = text_length % AES_BLOCK_SIZE;
		head_length = text_length - tail_length;

		/* ghash ciphertext head */
		if (head_length) {
			rc = s390_ghash(ciphertext, head_length, subkey_h, iv);
			if (rc)
				return rc;
		}

		/* ghash ciphertext tail and meta data */
		if (tail_length) {
			memcpy(c_pad_meta.pad, ciphertext + head_length, tail_length);

			rc = s390_ghash((unsigned char *)&c_pad_meta,
					sizeof(c_pad_meta), subkey_h, iv);
			if (rc)
				return rc;
		} else {
			rc = s390_ghash((unsigned char *)&c_pad_meta.length_a,
					AES_BLOCK_SIZE, subkey_h, iv);
			if (rc)
				return rc;
		}
	} else {
		/* ghash meta data only */
		rc = s390_ghash((unsigned char *)&c_pad_meta.length_a,
				AES_BLOCK_SIZE,
				subkey_h, iv);
		if (rc)
			return rc;
	}

	return 0;
}

static inline unsigned int s390_gcm_authenticate_intermediate(
		const unsigned char *ciphertext, unsigned long text_length,
		unsigned char *aad, unsigned long aad_length,
		const unsigned char *subkey_h, unsigned char *iv)
{
	unsigned int rc;
	unsigned char aad_pad[AES_BLOCK_SIZE];
	unsigned long head_length;
	unsigned long tail_length;
	struct pad_meta c_pad_meta;

	memset(c_pad_meta.pad, 0x00, sizeof(c_pad_meta.pad));

	if (aad_length) {
		tail_length = aad_length % AES_BLOCK_SIZE;
		head_length = aad_length - tail_length;

		/* ghash aad head */
		if (head_length) {
			rc = s390_ghash(aad, head_length, subkey_h, iv);
			if (rc)
				return rc;
		}

		/* ghash aad tail */
		if (tail_length) {
			memset(aad_pad, 0x00, AES_BLOCK_SIZE);
			memcpy(aad_pad, aad + head_length, tail_length);

			rc = s390_ghash(aad_pad, AES_BLOCK_SIZE, subkey_h, iv);
			if (rc)
				return rc;
		}
	}

	if (text_length) {
		tail_length = text_length % AES_BLOCK_SIZE;
		head_length = text_length - tail_length;

		/* ghash ciphertext head */
		if (head_length) {
			rc = s390_ghash(ciphertext, head_length, subkey_h, iv);
			if (rc)
				return rc;
		}

		/* ghash ciphertext tail and meta data */
		if (tail_length) {

			memcpy(c_pad_meta.pad, ciphertext + head_length, tail_length);

			rc = s390_ghash((unsigned char *)&c_pad_meta,
					AES_BLOCK_SIZE, subkey_h, iv);
			if (rc)
				return rc;

		}
	}
	return 0;
}

static inline unsigned int s390_gcm_authenticate_last(
		unsigned long aad_length, unsigned long ciph_length,
		const unsigned char *subkey_h, unsigned char *iv)
{
	unsigned int rc;
	struct pad_meta c_pad_meta;

	memset(c_pad_meta.pad, 0x00, sizeof(c_pad_meta.pad));
	c_pad_meta.length_a = (uint64_t)(aad_length * 8ul);
	c_pad_meta.length_b = (uint64_t)(ciph_length * 8ul);

	/* ghash meta data only */
	rc = s390_ghash((unsigned char *)&c_pad_meta.length_a,
			AES_BLOCK_SIZE,
			subkey_h, iv);
	if (rc)
		return rc;

	return 0;
}

static inline int s390_gcm(unsigned int function_code,
	     unsigned char *plaintext, unsigned long text_length,
	     unsigned char *ciphertext,
	     const unsigned char *iv, unsigned long iv_length,
	     const unsigned char *aad, unsigned long aad_length,
	     unsigned char *tag, unsigned long tag_length,
	     unsigned char *key)
{
	unsigned char subkey_h[AES_BLOCK_SIZE];
	unsigned char j0[AES_BLOCK_SIZE];
	unsigned char tmp_ctr[AES_BLOCK_SIZE];
	/* temporary tag must be of size cipher block size */
	unsigned char tmp_tag[AES_BLOCK_SIZE];
	unsigned int rc;

	if (!msa4_switch)
		return ENODEV;

	/* calculate subkey H */
	rc = s390_aes_ecb(UNDIRECTED_FC(function_code),
			  AES_BLOCK_SIZE, zero_block,
			  key, subkey_h);
	if (rc)
		return rc;

	/* calculate initial counter, based on iv */
	__compute_j0(iv, iv_length, subkey_h, j0);

	/* prepate initial counter for cipher */
	memcpy(tmp_ctr, j0, AES_BLOCK_SIZE);

	if (!msa8_switch) {

		/**
		 * simulate aes-gcm with aes-ctr and ghash.
		 */

		__inc_aes_ctr((struct uint128 *)tmp_ctr, GCM_CTR_WIDTH);

		if (function_code % 2) {
			/* mac */
			rc = s390_gcm_authenticate(ciphertext, text_length,
						   aad, aad_length,
						   subkey_h, tmp_tag);
			if (rc)
				return rc;

			/* decrypt */
			rc = s390_aes_ctr(UNDIRECTED_FC(function_code),
					  ciphertext, plaintext, text_length,
					  key, tmp_ctr, GCM_CTR_WIDTH);
			if (rc)
				return rc;
		} else {
			/* encrypt */
			rc = s390_aes_ctr(UNDIRECTED_FC(function_code),
					  plaintext, ciphertext, text_length,
					  key, tmp_ctr, GCM_CTR_WIDTH);
			if (rc)
				return rc;

			/* mac */
			rc = s390_gcm_authenticate(ciphertext, text_length,
						   aad, aad_length,
						   subkey_h, tmp_tag);
			if (rc)
				return rc;
		}

		/* encrypt tag */
		return s390_aes_ctr(UNDIRECTED_FC(function_code),
					tmp_tag, tag, tag_length,
					key, j0, GCM_CTR_WIDTH);

	} else {

		/**
		 * use the aes-gcm support via CPACF.
		 */

		if (function_code % 2) {
			/* decrypt */
			rc = s390_aes_gcm(function_code, ciphertext, plaintext,
					  text_length, key, j0, tmp_ctr, aad,
					  aad_length, subkey_h, tag, 1, 1);
		} else {
			/* encrypt */
			memset(tmp_tag, 0, AES_BLOCK_SIZE);
			rc = s390_aes_gcm(function_code, plaintext, ciphertext,
					  text_length, key, j0, tmp_ctr, aad,
					  aad_length, subkey_h, tmp_tag, 1, 1);
			memcpy(tag, tmp_tag, tag_length);
		}

		return rc;
	}
}

static inline int s390_gcm_initialize(unsigned int function_code,
				      const unsigned char *iv,
				      unsigned long iv_length,
				      unsigned char *key,
				      unsigned char *icb,
				      unsigned char *ucb,
				      unsigned char *subkey)
{
	int rc;

	if (!icb || !ucb)
		return -EINVAL;

	/* calculate subkey H */
	rc = s390_aes_ecb(UNDIRECTED_FC(function_code),
					  AES_BLOCK_SIZE, zero_block, key, subkey);
	if (rc)
		return rc;

	/* calculate initial counter, based on iv */
	__compute_j0(iv, iv_length, subkey, icb);

	/* prepare usage counter for cipher */
	memcpy(ucb, icb, AES_BLOCK_SIZE);

	if (!msa8_switch) // KMA increases the ctr internally
		__inc_aes_ctr((struct uint128 *)ucb, GCM_CTR_WIDTH);

	return 0;
}

static inline void inc_ctr(unsigned char* ctr)
{
    unsigned int* cv;

	cv = (unsigned int*)&ctr[12];
	*cv = *cv + 1;
}

/**
 * processes the last partial plaintext/ciphertext (< 16 bytes) and calculates
 * the last intermediate tag using the old code path. This is not possible with
 * KMA, because KMA cannot process partial blocks before s390_gcm_last.
 */
static inline int s390_gcm_last_intermediate(unsigned int function_code,
				unsigned char *plaintext, unsigned long text_length,
				unsigned char *ciphertext,
				unsigned char *ctr,
				unsigned char *aad, unsigned long aad_length,
				unsigned char *tag, unsigned char *key,
				unsigned char *subkey)
{
	unsigned int rc;
	unsigned char tmp_ctr[16];

	/*
	 * The old code needs ctr +1.
	 * We copy ctr, to not destroy the original ctr.
	 */
	memcpy(tmp_ctr, ctr, sizeof(tmp_ctr));
	inc_ctr(tmp_ctr);

	if (function_code % 2) {
		/* mac */
		rc = s390_gcm_authenticate_intermediate(ciphertext, text_length, aad,
			aad_length, subkey, tag);
		if (rc)
			return rc;
		/* decrypt */
		rc = s390_aes_ctr(UNDIRECTED_FC(function_code), ciphertext, plaintext,
						  text_length, key, tmp_ctr, GCM_CTR_WIDTH);
		if (rc)
			return rc;
	} else {
		/* encrypt */
		rc = s390_aes_ctr(UNDIRECTED_FC(function_code), plaintext, ciphertext,
						  text_length, key, tmp_ctr, GCM_CTR_WIDTH);
		if (rc)
			return rc;
		/* mac */
		rc = s390_gcm_authenticate_intermediate(ciphertext, text_length, aad,
			aad_length, subkey, tag);
		if (rc)
			return rc;
	}

	return 0;
}

static inline int s390_gcm_intermediate(unsigned int function_code,
				unsigned char *plaintext, unsigned long text_length,
				unsigned char *ciphertext,
				unsigned char *ctr,
				unsigned char *aad, unsigned long aad_length,
				unsigned char *tag, unsigned char *key,
				unsigned char *subkey)
{
	unsigned long bulk;
	unsigned int rc, laad;
	unsigned char *in, *out;

	if (!msa4_switch)
		return ENODEV;

	if (!msa8_switch) {
		if (function_code % 2) {
			/* mac */
			rc = s390_gcm_authenticate_intermediate(ciphertext, text_length, aad,
				aad_length, subkey, tag);
			if (rc)
				return rc;

			/* decrypt */
			rc = s390_aes_ctr(UNDIRECTED_FC(function_code), ciphertext, plaintext,
							  text_length, key, ctr, GCM_CTR_WIDTH);
			if (rc)
				return rc;
		} else {
			/* encrypt */
			rc = s390_aes_ctr(UNDIRECTED_FC(function_code), plaintext, ciphertext,
							  text_length, key, ctr, GCM_CTR_WIDTH);
			if (rc)
				return rc;

			/* mac */
			rc = s390_gcm_authenticate_intermediate(ciphertext, text_length, aad,
				aad_length, subkey, tag);
			if (rc)
				return rc;
		}
	} else {
		if ((text_length > 0) || (aad_length % AES_BLOCK_SIZE))
			laad = 1;
		else
			laad = 0;

		bulk = (text_length / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
		text_length %= AES_BLOCK_SIZE;

		if (bulk || aad_length) {
			in = (function_code % 2) ? ciphertext : plaintext;
			out = (function_code % 2) ? plaintext : ciphertext;

			rc = s390_aes_gcm(function_code, in, out, bulk, key,
					  NULL, ctr, aad, aad_length, subkey,
					  tag, laad, 0);
			if (rc)
				return rc;
		}
		if (text_length) {
			rc = s390_gcm_last_intermediate(function_code,
					plaintext + bulk, text_length,
					ciphertext + bulk, ctr, NULL,
					0, tag, key, subkey);
			if (rc)
				return rc;
		}
	}

	return 0;
}

static inline int s390_gcm_last(unsigned int function_code, unsigned char *icb,
				unsigned long aad_length, unsigned long ciph_length,
				unsigned char *tag, unsigned long tag_length,
				unsigned char *key, unsigned char *subkey)
{
	unsigned char tmp_tag[AES_BLOCK_SIZE];
	unsigned char tmp_icb[AES_BLOCK_SIZE];
	int rc;

	/* dont modify icb buffer */
	memcpy(tmp_icb, icb, sizeof(tmp_icb));

	if (!msa8_switch) {

		/* generate authentication tag */
		memcpy(tmp_tag, tag, tag_length);
		rc = s390_gcm_authenticate_last(aad_length, ciph_length, subkey, tmp_tag);
		if (rc)
			return rc;

		/* encrypt tag */
		return s390_aes_ctr(UNDIRECTED_FC(function_code), tmp_tag, tag, tag_length,
							key, tmp_icb, GCM_CTR_WIDTH);

	} else {
		return s390_aes_gcm(function_code, NULL, NULL, ciph_length,
				    key, tmp_icb, NULL, NULL, aad_length,
				    subkey, tag, 1, 1);
	}
}

static inline int is_valid_aes_key_length(unsigned int key_length)
{
	switch (key_length) {
	case 16:
	case 24:
	case 32:
		return 1;
	default:
		return 0;
	}
}

static inline int is_valid_direction(unsigned int direction)
{
	switch (direction) {
	case ICA_ENCRYPT:
	case ICA_DECRYPT:
		return 1;
	default:
		return 0;
	}
}

static inline int is_valid_tag_length(unsigned int tag_length)
{
	switch (tag_length) {
	case 4:
	case 8:
	case 12:
	case 13:
	case 14:
	case 15:
	case 16:
		return 1;
	default:
		return 0;
	}
}

static inline int s390_aes_gcm_simulate_kma_intermediate(const unsigned char *in_data,
		unsigned char *out_data, unsigned long data_length,
		const unsigned char *aad, unsigned long aad_length,
		kma_ctx* ctx)
{
	int rc;
	unsigned int function_code = aes_directed_fc(ctx->key_length, ctx->direction);

	/* Add one to first counter value for MSA 4 code path. */
	if (!ctx->first_time) {
		memcpy(&(ctx->ucb), ctx->j0, AES_BLOCK_SIZE);
		inc_ctr(ctx->ucb);
		ctx->first_time = 1;
	}

	if (ctx->direction == ICA_ENCRYPT) {
		rc = s390_gcm_intermediate(function_code,
					   (unsigned char*)in_data,
					   data_length, out_data,
					   (unsigned char*)&(ctx->ucb),
					   (unsigned char*)aad, aad_length,
					   ctx->tag, (unsigned char*)ctx->key,
					   (unsigned char*)ctx->subkey_h);
	} else {
		rc = s390_gcm_intermediate(function_code, out_data,
					   data_length, (unsigned char*)in_data,
					   (unsigned char*)&(ctx->ucb),
					   (unsigned char*)aad, aad_length,
					   ctx->tag, (unsigned char*)ctx->key,
					   (unsigned char*)ctx->subkey_h);
	}

	if (rc)
		return rc;

	ctx->total_aad_length += aad_length;
	ctx->total_input_length += data_length;

	return 0;
}

static inline int s390_aes_gcm_simulate_kma_full(const unsigned char *in_data,
		unsigned char *out_data, unsigned long data_length,
		const unsigned char *aad, unsigned long aad_length,
		kma_ctx* ctx)
{
	unsigned int function_code = aes_directed_fc(ctx->key_length, ctx->direction);

	if (ctx->direction == ICA_ENCRYPT) {
		return s390_gcm(function_code, (unsigned char*)in_data, data_length, out_data,
			      ctx->iv, ctx->iv_length, aad, aad_length,
			      ctx->tag, AES_BLOCK_SIZE, ctx->key);
	} else {
		return s390_gcm(function_code, out_data, data_length, (unsigned char*)in_data,
			      ctx->iv, ctx->iv_length, aad, aad_length,
			      ctx->tag, AES_BLOCK_SIZE, ctx->key);
	}
}

static inline int s390_aes_gcm_kma(const unsigned char *in_data,
		unsigned char *out_data, unsigned long data_length,
		const unsigned char *aad, unsigned long aad_length,
		unsigned int end_of_aad, unsigned int end_of_data,
		kma_ctx* ctx)
{
	unsigned int function_code = aes_directed_fc(ctx->key_length, ctx->direction);
	unsigned int hw_fc = 0;
	int rc;

	/* Set hardware function code */
	if (*s390_kma_functions[function_code].enabled) {
		hw_fc = s390_kma_functions[function_code].hw_fc;
		if (ctx->subkey_provided)
			hw_fc = hw_fc | HS_FLAG;
		if (end_of_aad)
			hw_fc = hw_fc | LAAD_FLAG;
		if (end_of_data)
			hw_fc = hw_fc | LPC_FLAG;
	} else {
		return ENODEV;
	}

	if (!aad)
		aad_length = 0;

	if (!in_data || !out_data)
		data_length = 0;

	/* Actual lengths needed by KMA */
	ctx->total_aad_length += aad_length*8;
	ctx->total_input_length += data_length*8;

	/* Call KMA */
	rc = s390_kma(hw_fc, ctx,
			out_data, in_data, data_length,
			aad, aad_length);

	if (rc >= 0) {
		ctx->subkey_provided = 1;
		if (ctx->direction)
			stats_increment(ICA_STATS_AES_GCM, ALGO_HW, ENCRYPT);
		else
			stats_increment(ICA_STATS_AES_GCM, ALGO_HW, DECRYPT);
		return 0;
	} else
		return EIO;
}
#endif
