/* This program is released under the Common Public License V1.0
 *
 * You should have received a copy of Common Public License V1.0 along with
 * with this program.
 */

/**
 * Authors: Joerg Schmidbauer <jschmidb@de.ibm.com>
 *
 * Copyright IBM Corp. 2017
 */

#ifndef S390_ECDH_H
#define S390_ECDH_H

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <asm/zcrypt.h>
#include "ica_api.h"

#define MAX_ECC_PRIV_SIZE	66 /* 521 bits */
#define MAX_ECDSA_SIG_SIZE	132

struct ec_key_t {
	uint32_t nid;
	unsigned char* X;
	unsigned char* Y;
	unsigned char* D;
}; /* ICA_EC_KEY */


/* ICA_X25519_CTX */
struct ica_x25519_ctx {
	unsigned char priv[32];
	unsigned char pub[32];

	int priv_init;
	int pub_init;
};

/* ICA_X448_CTX */
struct ica_x448_ctx {
	unsigned char priv[56];
	unsigned char pub[56];

	int priv_init;
	int pub_init;
};

/* ICA_ED25519_CTX */
struct ica_ed25519_ctx {
	struct {
		unsigned char sig[64];
		unsigned char priv[32];
		unsigned char buf[4096 - 64 - 32];
	} sign_param;

	struct {
		unsigned char sig[64];
		unsigned char pub[32];
		unsigned char buf[4096 - 64 - 32];
	} verify_param;

	int priv_init;
	int pub_init;
};

/* ICA_ED448_CTX */
struct ica_ed448_ctx {
	struct {
		unsigned char sig[128];
		unsigned char priv[64];
		unsigned char buf[4096 - 128 - 64];
	} sign_param;

	struct {
		unsigned char sig[128];
		unsigned char pub[64];
		unsigned char buf[4096 - 128 - 64];
	} verify_param;

	int priv_init;
	int pub_init;
};

int x25519_derive_pub(unsigned char pub[32],
		      const unsigned char priv[32]);
int x448_derive_pub(unsigned char pub[56],
		    const unsigned char priv[56]);
int ed25519_derive_pub(unsigned char pub[32],
		       const unsigned char sha512_priv[32]);
int ed448_derive_pub(unsigned char pub[57],
		     const unsigned char buf[57]);

int scalar_mulx_cpacf(unsigned char *res_u,
		      const unsigned char *scalar,
		      const unsigned char *u,
		      int curve_nid);

/**
 * Refer to z/OS ICSF Application Programmer's Guide,
 * Appendix A. ICSF and cryptographic coprocessor return and reason codes
 */
#define RS_SIGNATURE_INVALID	429

/**
 * Refer to z/OS ICSF Application Programmer's Guide,
 * Appendix B. Key Token Formats
 */

#define CURVE_TYPE_PRIME		0x00
#define CURVE_TYPE_BRAINPOOL	0x01

/**
 * CCA token header.
 */
typedef struct {
	uint8_t tkn_hdr_id;
	uint8_t tkn_hdr_version;
	uint16_t tkn_length;
	uint8_t reserved[4];
} __attribute__((packed)) CCA_TOKEN_HDR;

/**
 * ECC private key section
 */
typedef struct {
	uint8_t section_id; /* 0x20 = ecc private key */
	uint8_t version;
	uint16_t section_len;
	uint8_t wrapping_method;
	uint8_t hash_used_for_wrapping;
	uint8_t reserved1[2];
	uint8_t key_usage;
	uint8_t curve_type; /* 0x00 = prime, 0x01 = brainpool */
	uint8_t key_format;
	uint8_t reserved2;
	uint16_t priv_p_bitlen; /* length of prime p in bits */
	uint16_t ibm_associated_data_len;
	uint8_t kvp[8];
	uint8_t obj_protection_key[48];
	uint16_t associated_data_len;
	uint16_t formatted_data_len;
} __attribute__((packed)) ECC_PRIVATE_KEY_SECTION;

/**
 * ECC associated data.
 */
typedef struct {
	uint8_t version;
	uint8_t key_label;
	uint16_t ibm_data_len;
	uint16_t ibm_ext_ad_len;
	uint8_t user_def_ad_len;
	uint8_t curve_type;
	uint16_t p_bitlen;
	uint8_t usage_flag;
	uint8_t format_and_sec_flag;
	uint8_t reserved[4];
} __attribute__((packed)) ECC_ASSOCIATED_DATA;

/**
 * ECC public key section.
 */
typedef struct {
	uint8_t section_id; /* 0x21 = ecc public key */
	uint8_t version;
	uint16_t section_len;
	uint8_t reserved1[4];
	uint8_t curve_type;
	uint8_t reserved2;
	uint16_t pub_p_bitlen;
	uint16_t pub_q_bytelen;
} __attribute__((packed)) ECC_PUBLIC_KEY_SECTION;

/**
 * ECC private key token
 */
typedef struct {
	uint16_t key_len;
	uint16_t reserved;
	CCA_TOKEN_HDR tknhdr;
	ECC_PRIVATE_KEY_SECTION privsec;
	ECC_ASSOCIATED_DATA adata;
	unsigned char privkey[0];
	/* here comes the variable length private key (D) */
} __attribute__((packed)) ECC_PRIVATE_KEY_TOKEN;

/**
 *  ECC public key token
 */
typedef struct {
	ECC_PUBLIC_KEY_SECTION pubsec;
	uint8_t compress_flag;
	unsigned char pubkey[0];
	/* here comes the variable length public key (X,Y) */
} __attribute__((packed)) ECC_PUBLIC_KEY_TOKEN;

/**
 * ECC keyblock, just the length field.
 */
typedef struct {
	uint16_t keyblock_len;
} __attribute__((packed)) ECC_KEYBLOCK_LENGTH;

/**
 * A null key token.
 */
typedef struct {
	uint8_t nullkey_len[2];
	uint8_t nkey[66];
} ECDH_NULLKEY;

/**
 * An ecc nullkey block.
 */
typedef struct {
	uint16_t len;
	uint16_t flags;
	uint8_t nulltoken;
} __attribute__((packed)) ECC_NULL_TOKEN;

/**
 * ECDH parmblock.
 */
typedef struct {
	uint16_t subfunc_code;
	struct {
		uint16_t rule_array_len;
		uint8_t rule_array_cmd[8];
	} rule_array;
	struct {
		uint16_t vud_len;
		uint8_t vud1[4];
		uint8_t vud2[6];
		uint8_t vud3[4];
		uint8_t vud4[4];
	} vud_data;
} __attribute__((packed)) ECDH_PARMBLOCK;

/**
 * ECDH reply
 */
typedef struct {
	uint8_t reply_cprbx[sizeof(struct CPRBX)];
	uint8_t subfunc_code[2];
	uint16_t rule_len;
	uint8_t vud[14];
	uint16_t key_block_len;
	uint16_t key_len; /* keylen-4 is the z-value length */
	uint16_t key_tag;
	uint8_t raw_z_value[MAX_ECC_PRIV_SIZE];
} __attribute__((packed)) ECDH_REPLY;

unsigned int ecdh_hw(ica_adapter_handle_t adapter_handle,
		const ICA_EC_KEY *privkey_A, const ICA_EC_KEY *pubkey_B,
		unsigned char *z);

unsigned int ecdh_sw(const ICA_EC_KEY *privkey_A,
		const ICA_EC_KEY *pubkey_B, unsigned char *z);

/**
 * ECDSA parmblock.
 */
typedef struct {
	uint16_t subfunc_code;
	struct {
		uint16_t rule_array_len;
		uint8_t rule_array_cmd[8];
	} rule_array;
	struct {
		uint16_t vud_len;
		uint16_t vud1_len;
		uint8_t vud1[0];
		/* Here comes the variable length data to sign/verify */
	} vud_data;
} __attribute__((packed)) ECDSA_PARMBLOCK_PART1;

typedef struct {
	struct {
		uint16_t vud2_len;
		uint16_t vud2_data[0];
		/* Here comes the variable length signature to verify */
	} vud_data;
} __attribute__((packed)) ECDSA_PARMBLOCK_PART2;

/**
 * ECDSA verify public key block
 */
typedef struct {
	uint16_t key_len;
	uint8_t reserved[2];
	CCA_TOKEN_HDR tknhdr;
	ECC_PUBLIC_KEY_SECTION pubsec;
	uint8_t compress_flag;
	unsigned char pubkey[0];
	/* here comes the variable length public key (X,Y) */
} __attribute__((packed)) ECDSA_PUBLIC_KEY_BLOCK;

/**
 * ECDSA sign reply
 */
typedef struct {
	uint8_t reply_cprbx[sizeof(struct CPRBX)];
	uint8_t subfunc_code[2];
	uint16_t rule_len;
	uint16_t vud_len;
	uint8_t vud1[6];
	uint8_t signature[MAX_ECDSA_SIG_SIZE]; /* siglen = vud_len - 6 - 2 */
} __attribute__((packed)) ECDSA_SIGN_REPLY;

/**
 * ECDSA verify reply
 */
typedef struct {
	uint8_t reply_cprbx[sizeof(struct CPRBX)];
	uint8_t subfunc_code[2];
	uint16_t rule_len;
	uint16_t vud_len;
	uint16_t keylen;
} __attribute__((packed)) ECDSA_VERIFY_REPLY;

unsigned int ecdsa_sign_hw(ica_adapter_handle_t adapter_handle,
		const ICA_EC_KEY *privkey, const unsigned char *hash, unsigned int hash_length,
		unsigned char *signature);

unsigned int ecdsa_sign_sw(const ICA_EC_KEY *privkey,
		const unsigned char *hash, unsigned int hash_length,
		unsigned char *signature);

unsigned int ecdsa_verify_hw(ica_adapter_handle_t adapter_handle,
		const ICA_EC_KEY *pubkey, const unsigned char *hash, unsigned int hash_length,
		const unsigned char *signature);

unsigned int ecdsa_verify_sw(const ICA_EC_KEY *pubkey,
		const unsigned char *hash, unsigned int hash_length,
		const unsigned char *signature);

/**
 * ECKeyGen parmblock.
 */
typedef struct {
	uint16_t subfunc_code;
	struct {
		uint16_t rule_array_len;
		uint8_t rule_array_cmd[8];
	} rule_array;
	uint16_t vud_len; /* no data, only len field */
} __attribute__((packed)) ECKEYGEN_PARMBLOCK;

/**
 * ECKeyGen private key struct
 */
typedef struct {
	uint16_t key_len;
	uint16_t reserved1;
	CCA_TOKEN_HDR tknhdr;
	ECC_PRIVATE_KEY_SECTION privsec;
	ECC_ASSOCIATED_DATA adata;
	ECC_PUBLIC_KEY_SECTION pubsec;
} __attribute__((packed)) ECKEYGEN_KEY_TOKEN;

/**
 * ECKeyGen reply
 */
typedef struct {
	uint8_t reply_cprbx[sizeof(struct CPRBX)];
	uint8_t subfunc_code[2];
	uint16_t rule_len;
	uint16_t vud_len;
	uint16_t keyblock_len;
	ECC_PRIVATE_KEY_TOKEN eckey;
} __attribute__((packed)) ECKEYGEN_REPLY;

unsigned int eckeygen_hw(ica_adapter_handle_t adapter_handle, ICA_EC_KEY *key);

unsigned int eckeygen_sw(ICA_EC_KEY *key);

int ec_key_check(ICA_EC_KEY *ica_key);

/**
 * returns 1 if the given data length is valid for Crypto Express, 0 otherwise.
 */
static inline int hash_length_valid(unsigned int length)
{
	switch (length) {
	case 20:
	case 28:
	case 32:
	case 48:
	case 64:
		return 1;
	default:
		return 0;
	}
}

extern unsigned int msa9_switch, ecc_via_online_card;

/**
 * returns 1 if the curve specified by nid is supported by CCA cards,
 * and there is a CCA card online, 0 otherwise.
 */
static inline int curve_supported_via_online_card(unsigned int nid)
{
	if (!ecc_via_online_card)
		return 0;

	switch (nid) {
	case NID_X9_62_prime192v1:
	case NID_secp224r1:
	case NID_X9_62_prime256v1:
	case NID_secp384r1:
	case NID_secp521r1:
#if OPENSSL_VERSION_NUMBER >= 0x010002000
	case NID_brainpoolP160r1:
	case NID_brainpoolP192r1:
	case NID_brainpoolP224r1:
	case NID_brainpoolP256r1:
	case NID_brainpoolP320r1:
	case NID_brainpoolP384r1:
	case NID_brainpoolP512r1:
#endif
		return 1;
	default:
		return 0;
	}
}

/**
 * returns 1 if the curve specified by nid is supported by CPACF within the
 * EC API, 0 otherwise.
 *
 * Note: ED25519, ED448, X25519, and X448 must be used via the related ica_ed
 * and ica_x API functions. CPACF support within the ica_ec API is just a
 * performance improvement over CCA cards, but does not suppport curves
 * that are not supported via CCA cards.
 */
static inline int curve_supported_via_cpacf(unsigned int nid)
{
#ifdef NO_CPACF
	(void)(nid);
	return 0;
#else
	if (!msa9_switch)
		return 0;

	switch (nid) {
	case NID_X9_62_prime256v1:
	case NID_secp384r1:
	case NID_secp521r1:
		return 1;
	default:
		return 0;
	}
#endif
}

/**
 * returns 1 if the curve specified by nid is supported by openssl, 0 otherwise.
 */
static inline int curve_supported_via_openssl(unsigned int nid)
{
	EC_GROUP *ptr = EC_GROUP_new_by_curve_name(nid);
	if (ptr)
		EC_GROUP_free(ptr);
	return ptr ? 1 : 0;
}

/**
 * returns the curve type (prime or brainpool) for the given nid.
 * returns -1 for any unknown nid.
 */
static inline short curve_type_from_nid(unsigned int nid)
{
	switch (nid) {
	case NID_X9_62_prime192v1:
	case NID_secp224r1:
	case NID_X9_62_prime256v1:
	case NID_secp384r1:
	case NID_secp521r1:
		return CURVE_TYPE_PRIME;
#if OPENSSL_VERSION_NUMBER >= 0x010002000
	case NID_brainpoolP160r1:
	case NID_brainpoolP192r1:
	case NID_brainpoolP224r1:
	case NID_brainpoolP256r1:
	case NID_brainpoolP320r1:
	case NID_brainpoolP384r1:
	case NID_brainpoolP512r1:
		return CURVE_TYPE_BRAINPOOL;
#endif
	default:
		return -1;
	}
}

/**
 * returns the length in bytes of the EC private key D-value
 * for the given nid.
 * returns -1 for any unknown nid.
 */
static inline int privlen_from_nid(unsigned int nid)
{
	switch (nid) {
#if OPENSSL_VERSION_NUMBER >= 0x010002000
	case NID_brainpoolP160r1:
		return 20;
#endif
	case NID_X9_62_prime192v1:
#if OPENSSL_VERSION_NUMBER >= 0x010002000
	case NID_brainpoolP192r1:
		return 24;
#endif
	case NID_secp224r1:
#if OPENSSL_VERSION_NUMBER >= 0x010002000
	case NID_brainpoolP224r1:
		return 28;
#endif
	case NID_ED25519:
	case NID_X25519:
	case NID_X9_62_prime256v1:
#if OPENSSL_VERSION_NUMBER >= 0x010002000
	case NID_brainpoolP256r1:
		return 32;
	case NID_brainpoolP320r1:
		return 40;
#endif
	case NID_secp384r1:
#if OPENSSL_VERSION_NUMBER >= 0x010002000
	case NID_brainpoolP384r1:
#endif
		return 48;
	case NID_X448:
		return 56;
	case NID_ED448:
		return 57;
#if OPENSSL_VERSION_NUMBER >= 0x010002000
	case NID_brainpoolP512r1:
		return 64;
#endif
	case NID_secp521r1:
		return 66;
	default:
		return -1;
	}
}

static inline unsigned int getenv_icapath()
{
	char* s = getenv("ICAPATH");
	int icapath=0; /* hw with sw fallback (default) */
	int env_icapath;

	if (s) {
		if (sscanf(s, "%d", &env_icapath) == 1) {
			switch (env_icapath) {
				case 1:	return 1; /* sw only */
				case 2: return 2; /* hw only */
				default:   break; /* default */
			}
		}
	}

	return icapath;
}

#endif
