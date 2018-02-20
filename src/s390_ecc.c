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

#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/ecdsa.h>
#include <openssl/opensslconf.h>
#ifdef OPENSSL_FIPS
#include <openssl/fips.h>
#endif /* OPENSSL_FIPS */

#include "fips.h"
#include "s390_ecc.h"

#define CPRBXSIZE (sizeof(struct CPRBX))
#define PARMBSIZE (2048)

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#define ECDSA_SIG_get0(sig,pr,ps) \
do { \
*(pr)=(sig)->r; \
*(ps)=(sig)->s; \
} while (0)
#define ECDSA_SIG_set0(sig,pr,ps) \
do { \
(sig)->r=pr; \
(sig)->s=ps; \
} while (0)
#endif

/**
 * makes a private EC_KEY.
 */
EC_KEY *make_eckey(int nid, const unsigned char *p, size_t plen)
{
    int ok = 0;
    EC_KEY *k = NULL;
    BIGNUM *priv = NULL;
    EC_POINT *pub = NULL;
    const EC_GROUP *grp;

    if ((k = EC_KEY_new_by_curve_name(nid)) == NULL) {
        goto err;
    }

	if ((priv = BN_bin2bn(p, plen, NULL)) == NULL) {
		goto err;
	}

	if (!EC_KEY_set_private_key(k, priv)) {
		goto err;
	}

    grp = EC_KEY_get0_group(k);
    if ((pub = EC_POINT_new(grp)) == NULL) {
        goto err;
    }

    if (!EC_POINT_mul(grp, pub, priv, NULL, NULL, NULL)) {
        goto err;
    }
    if (!EC_KEY_set_public_key(k, pub)) {
        goto err;
    }
    ok = 1;

 err:
    if (priv)
        BN_clear_free(priv);
    if (pub)
        EC_POINT_free(pub);

    if (ok)
        return k;
    else if (k)
        EC_KEY_free(k);

    return NULL;
}

/**
 * makes a public EC_KEY.
 */
EC_KEY *make_public_eckey(int nid, BIGNUM *x, BIGNUM *y, size_t plen)
{
    int ok = 0;
    EC_KEY *k = NULL;
    EC_POINT *pub = NULL;
    const EC_GROUP *grp;

    k = EC_KEY_new_by_curve_name(nid);
    if (!k)
        goto err;

    grp = EC_KEY_get0_group(k);
    pub = EC_POINT_new(grp);
    if (!pub)
        goto err;

    if (x && y) {
		BN_CTX* ctx = BN_CTX_new();
		EC_POINT_set_affine_coordinates_GFp(grp, pub, x, y, ctx);
    }

    if (!EC_KEY_set_public_key(k, pub))
        goto err;
    ok = 1;

 err:
    if (pub)
        EC_POINT_free(pub);

    if (ok)
        return k;
    else if (k)
        EC_KEY_free(k);

    return NULL;
}

/**
 * makes a keyblock length field at given struct and returns its length.
 */
unsigned int make_keyblock_length(ECC_KEYBLOCK_LENGTH *kb, unsigned int len)
{
	kb->keyblock_len = len;

	return sizeof(ECC_KEYBLOCK_LENGTH);
}

/**
 * makes a nullkey token at given struct and returns its length.
 */
unsigned int make_nullkey(ECDH_NULLKEY* nkey)
{
	nkey->nullkey_len = 0x0044;

	return sizeof(ECDH_NULLKEY);
}

/**
 * makes an ecc null token at given struct.
 */
unsigned int make_ecc_null_token(ECC_NULL_TOKEN *kb)
{
	kb->len = 0x0005;
	kb->flags = 0x0010;
	kb->nulltoken = 0x00;

	return sizeof(ECC_NULL_TOKEN);
}

/**
 * makes a T2 CPRBX at given struct and returns its length.
 */
unsigned int make_cprbx(struct CPRBX* cprbx, unsigned int parmlen,
		struct CPRBX *preqcblk, struct CPRBX *prepcblk)
{
    cprbx->cprb_len = CPRBXSIZE;
    cprbx->cprb_ver_id = 0x02;
    memcpy(&(cprbx->func_id), "T2", 2);
    cprbx->req_parml = parmlen;
    cprbx->domain = -1; /* use any domain */

    cprbx->rpl_msgbl = CPRBXSIZE + PARMBSIZE;
    cprbx->req_parmb = ((uint8_t *) preqcblk) + CPRBXSIZE;
    cprbx->rpl_parmb = ((uint8_t *) prepcblk) + CPRBXSIZE;

	return CPRBXSIZE;
}

/**
 * makes an ECDH parmblock at given struct and returns its length.
 */
unsigned int make_ecdh_parmblock(ECDH_PARMBLOCK *pb)
{
	typedef struct {
		uint16_t vud_len;
		uint8_t vud1[4];
		uint8_t vud2[6];
		uint8_t vud3[4];
		uint8_t vud4[4];
	} vud_data;

	vud_data static_vud = {
		0x0014,
		{0x00,0x04,0x00,0x91},
		{0x00,0x06,0x00,0x93,0x00,0x00},
		{0x00,0x04,0x00,0x90},
		{0x00,0x04,0x00,0x92}
	};

	pb->subfunc_code = 0x4448; /* 'DH' in ASCII */
	pb->rule_array.rule_array_len = 0x000A;
	memcpy(&(pb->rule_array.rule_array_cmd), "PASSTHRU", 8);
	memcpy(&(pb->vud_data), (char*)&static_vud, sizeof(vud_data));

	return sizeof(ECDH_PARMBLOCK);
}

/**
 * makes an ECDH key structure at given struct and returns its length.
 */
unsigned int make_ecdh_key_token(unsigned char *kb, unsigned int keyblock_length,
		const ICA_EC_KEY  *privkey_A, const ICA_EC_KEY *pubkey_B,
		uint8_t curve_type)
{
	ECC_PRIVATE_KEY_TOKEN* kp1;
	ECC_PUBLIC_KEY_TOKEN* kp2;
	unsigned int privlen = privlen_from_nid(privkey_A->nid);

	unsigned int this_length = sizeof(ECC_PRIVATE_KEY_TOKEN) + privlen
			+ sizeof(ECC_PUBLIC_KEY_TOKEN) + 2*privlen;

	unsigned int ecdhkey_length = 2 + 2 + sizeof(CCA_TOKEN_HDR)
			+ sizeof(ECC_PRIVATE_KEY_SECTION)
			+ sizeof(ECC_ASSOCIATED_DATA) + privlen
			+ sizeof(ECC_PUBLIC_KEY_TOKEN) + 2*privlen;

	unsigned int priv_bitlen = privlen*8;
	if (privkey_A->nid == NID_secp521r1) {
		priv_bitlen = 521;
	}

	kp1 = (ECC_PRIVATE_KEY_TOKEN*)kb;
	kp2 = (ECC_PUBLIC_KEY_TOKEN*)(kb + sizeof(ECC_PRIVATE_KEY_TOKEN) + privlen);

	kp1->key_len = ecdhkey_length;
	kp1->tknhdr.tkn_hdr_id = 0x1E;
	kp1->tknhdr.tkn_length = ecdhkey_length - 2 - 2; /* 2x len field */

	kp1->privsec.section_id = 0x20;
	kp1->privsec.version = 0x00;
	kp1->privsec.section_len =  sizeof(ECC_PRIVATE_KEY_SECTION) + sizeof(ECC_ASSOCIATED_DATA) + privlen;
	kp1->privsec.key_usage = 0xC0;
	kp1->privsec.curve_type = curve_type;
	kp1->privsec.key_format = 0x40; /* unencrypted key */
	kp1->privsec.priv_p_bitlen = priv_bitlen;
	kp1->privsec.associated_data_len = sizeof(ECC_ASSOCIATED_DATA);
	kp1->privsec.ibm_associated_data_len = sizeof(ECC_ASSOCIATED_DATA);
	kp1->privsec.formatted_data_len = privlen;

	kp1->adata.ibm_data_len = sizeof(ECC_ASSOCIATED_DATA);
	kp1->adata.curve_type = curve_type;
	kp1->adata.p_bitlen = priv_bitlen;
	kp1->adata.usage_flag = 0xC0;
	kp1->adata.format_and_sec_flag = 0x40;

	memcpy(&kp1->privkey[0], privkey_A->D, privlen);

	kp2->pubsec.section_id = 0x21;
	kp2->pubsec.section_len = sizeof(ECC_PUBLIC_KEY_TOKEN) + 2*privlen;
	kp2->pubsec.curve_type = curve_type;
	kp2->pubsec.pub_p_bitlen = priv_bitlen;
	kp2->pubsec.pub_q_bytelen = 2*privlen + 1; /* pub bytelen + compress flag */

	kp2->compress_flag = 0x04; /* uncompressed key */
	memcpy(&kp2->pubkey[0], pubkey_B->X, privlen);
	memcpy(&kp2->pubkey[privlen+0], pubkey_B->Y, privlen);

	return this_length;
}

/**
 * finalizes an ica_xcRB struct that is sent to the card.
 */
void finalize_xcrb(struct ica_xcRB* xcrb, struct CPRBX *preqcblk, struct CPRBX *prepcblk)
{
    memset(xcrb, 0, sizeof(struct ica_xcRB));
    xcrb->agent_ID = 0x4341;
	xcrb->user_defined = 0xffffffff; /* use any card number */
    xcrb->request_control_blk_length = preqcblk->cprb_len + preqcblk->req_parml;
    xcrb->request_control_blk_addr = (void *) preqcblk;
    xcrb->reply_control_blk_length = preqcblk->rpl_msgbl;
    xcrb->reply_control_blk_addr = (void *) prepcblk;
}

/**
 * creates an ECDH xcrb request message for zcrypt.
 *
 * returns a pointer to the control block where the card
 * provides its reply.
 */
ECDH_REPLY* make_ecdh_request(const ICA_EC_KEY *privkey_A, const ICA_EC_KEY *pubkey_B,
		struct ica_xcRB* xcrb)
{
    uint8_t *cbrbmem = NULL;
    struct CPRBX *preqcblk, *prepcblk;
    unsigned int privlen = privlen_from_nid(privkey_A->nid);

	unsigned int ecdh_key_token_len = 2 + 2 + sizeof(CCA_TOKEN_HDR)
		+ sizeof(ECC_PRIVATE_KEY_SECTION)
		+ sizeof(ECC_ASSOCIATED_DATA) + privlen
		+ sizeof(ECC_PUBLIC_KEY_TOKEN) + 2*privlen;

	unsigned int keyblock_len = 2 + 2*ecdh_key_token_len + 4*sizeof(ECDH_NULLKEY);
	unsigned int parmblock_len = sizeof(ECDH_PARMBLOCK) + keyblock_len;

	unsigned int curve_type = curve_type_from_nid(privkey_A->nid);
	if (curve_type < 0)
		return NULL;

    /* allocate buffer space for req cprb, req parm, rep cprb, rep parm */
    cbrbmem = malloc(2 * (CPRBXSIZE + PARMBSIZE));
    if (!cbrbmem)
		return NULL;

    memset(cbrbmem, 0, 2 * (CPRBXSIZE + PARMBSIZE));
    preqcblk = (struct CPRBX *) cbrbmem;
    prepcblk = (struct CPRBX *) (cbrbmem + CPRBXSIZE + PARMBSIZE);

    /* make ECDH request */
	unsigned int offset = 0;
	offset = make_cprbx((struct CPRBX *)cbrbmem, parmblock_len, preqcblk, prepcblk);
	offset += make_ecdh_parmblock((ECDH_PARMBLOCK*)(cbrbmem+offset));
	offset += make_keyblock_length((ECC_KEYBLOCK_LENGTH*)(cbrbmem+offset), keyblock_len);
	offset += make_ecdh_key_token(cbrbmem+offset, ecdh_key_token_len, privkey_A, pubkey_B, curve_type);
	offset += make_nullkey((ECDH_NULLKEY*)(cbrbmem+offset));
	offset += make_ecdh_key_token(cbrbmem+offset, ecdh_key_token_len, privkey_A, pubkey_B, curve_type);
	offset += make_nullkey((ECDH_NULLKEY*)(cbrbmem+offset));
	offset += make_nullkey((ECDH_NULLKEY*)(cbrbmem+offset));
	offset += make_nullkey((ECDH_NULLKEY*)(cbrbmem+offset));
	finalize_xcrb(xcrb, preqcblk, prepcblk);

    return (ECDH_REPLY*)prepcblk;
}

/**
 * Perform an ECDH shared secret calculation with given EC private key A (D)
 * and EC public key B (X,Y) via Crypto Express CCA coprocessor.
 *
 * Returns 0 if successful
 */
unsigned int ecdh_hw(ica_adapter_handle_t adapter_handle,
		const ICA_EC_KEY *privkey_A, const ICA_EC_KEY *pubkey_B,
		unsigned char *z)
{
	int rc;
	struct ica_xcRB xcrb;
	ECDH_REPLY* reply_p;
	unsigned int privlen = privlen_from_nid(privkey_A->nid);

	if (adapter_handle == DRIVER_NOT_LOADED)
		return EFAULT;

	reply_p = make_ecdh_request(privkey_A, pubkey_B, &xcrb);
	if (!reply_p)
		return EFAULT;

	rc = ioctl(adapter_handle, ZSECSENDCPRB, xcrb);
	if (rc != 0)
		return EFAULT;

	if (reply_p->key_len-4 != privlen)
		return EFAULT;

	memcpy(z, reply_p->raw_z_value, privlen);

	return 0;
}

/**
 * Perform an ECDH shared secret calculation with given EC private key A (D)
 * and EC public key B (X,Y) in software.
 *
 * Returns 0 if successful
 */
unsigned int ecdh_sw(const ICA_EC_KEY *privkey_A, const ICA_EC_KEY *pubkey_B,
		unsigned char *z)
{
	int rc = 1;
    EC_KEY *a = NULL; EC_KEY *b = NULL;
    BIGNUM* xb=NULL; BIGNUM* yb=NULL;
    unsigned int ztmplen;
    unsigned int privlen = privlen_from_nid(privkey_A->nid);

#ifdef ICA_FIPS
	if ((fips & ICA_FIPS_MODE) && (!FIPS_mode()))
		return EACCES;
#endif /* ICA_FIPS */

	a = make_eckey(privkey_A->nid, privkey_A->D, privlen);
	xb = BN_bin2bn(pubkey_B->X, privlen, xb);
	yb = BN_bin2bn(pubkey_B->Y, privlen, yb);
	b = make_public_eckey(privkey_A->nid, xb, yb, privlen);
    if (!a || !b)
        goto err;

    ztmplen = (EC_GROUP_get_degree(EC_KEY_get0_group(a)) + 7) / 8;
    if (ztmplen != privlen)
        goto err;

    rc = ECDH_compute_key(z, privlen, EC_KEY_get0_public_key(b), a, NULL);
    if (rc == 0)
	goto err;

    rc = 0;

err:
	BN_clear_free(xb);
	BN_clear_free(yb);
	EC_KEY_free(a);
	EC_KEY_free(b);

	return rc;
}

/**
 * makes an ECDSA sign parmblock at given struct and returns its length.
 */
unsigned int make_ecdsa_sign_parmblock(ECDSA_PARMBLOCK_PART1 *pb,
		const unsigned char *hash, unsigned int hash_length)
{
	pb->subfunc_code = 0x5347; /* 'SG' */
	pb->rule_array.rule_array_len = 0x000A;
	memcpy(&(pb->rule_array.rule_array_cmd), "ECDSA   ", 8);
	pb->vud_data.vud_len = hash_length+4;
	pb->vud_data.vud1_len = hash_length+2;
	memcpy(&(pb->vud_data.vud1), hash, hash_length);

	return sizeof(ECDSA_PARMBLOCK_PART1) + hash_length;
}

/**
 * makes an ECDSA verify parmblock at given struct and returns its length.
 */
unsigned int make_ecdsa_verify_parmblock(char *pb,
		const unsigned char *hash, unsigned int hash_length,
		const unsigned char *signature, unsigned int signature_len)
{
	ECDSA_PARMBLOCK_PART1* pb1;
	ECDSA_PARMBLOCK_PART2* pb2;

	pb1 = (ECDSA_PARMBLOCK_PART1*)pb;
	pb2 = (ECDSA_PARMBLOCK_PART2*)(pb + sizeof(ECDSA_PARMBLOCK_PART1) + hash_length);

	pb1->subfunc_code = 0x5356; /* 'SV' */
	pb1->rule_array.rule_array_len = 0x000A;
	memcpy(&(pb1->rule_array.rule_array_cmd), "ECDSA   ", 8);
	pb1->vud_data.vud_len = 2 + (2+hash_length) + (2+signature_len);
	pb1->vud_data.vud1_len = 2+hash_length;
	memcpy(&(pb1->vud_data.vud1), hash, hash_length);

	pb2->vud_data.vud2_len = 2+signature_len;
	memcpy(&(pb2->vud_data.vud2_data), signature, signature_len);

	return sizeof(ECDSA_PARMBLOCK_PART1)
			+ hash_length
			+ sizeof(ECDSA_PARMBLOCK_PART2)
			+ signature_len;
}

/**
 * makes an ECDSA key structure at given struct and returns its length.
 */
unsigned int make_ecdsa_private_key_token(unsigned char *kb,
		const ICA_EC_KEY *privkey, unsigned char *X, unsigned char *Y,
		uint8_t curve_type)
{
	ECC_PRIVATE_KEY_TOKEN* kp1;
	ECC_PUBLIC_KEY_TOKEN* kp2;
	unsigned int privlen = privlen_from_nid(privkey->nid);

	unsigned int ecdsakey_length = 2 + 2 + sizeof(CCA_TOKEN_HDR)
			+ sizeof(ECC_PRIVATE_KEY_SECTION)
			+ sizeof(ECC_ASSOCIATED_DATA) + privlen
			+ sizeof(ECC_PUBLIC_KEY_TOKEN) + 2*privlen;

	unsigned int priv_bitlen = privlen*8;
	if (privkey->nid == NID_secp521r1) {
		priv_bitlen = 521;
	}

	kp1 = (ECC_PRIVATE_KEY_TOKEN*)kb;
	kp2 = (ECC_PUBLIC_KEY_TOKEN*)(kb + sizeof(ECC_PRIVATE_KEY_TOKEN) + privlen);

	kp1->key_len = ecdsakey_length;
	kp1->reserved = 0x0020;
	kp1->tknhdr.tkn_hdr_id = 0x1E;
	kp1->tknhdr.tkn_length = ecdsakey_length - 2 - 2; /* 2x len field */

	kp1->privsec.section_id = 0x20;
	kp1->privsec.version = 0x00;
	kp1->privsec.section_len =  sizeof(ECC_PRIVATE_KEY_SECTION) + sizeof(ECC_ASSOCIATED_DATA) + privlen;
	kp1->privsec.key_usage = 0x80;
	kp1->privsec.curve_type = curve_type;
	kp1->privsec.key_format = 0x40; /* unencrypted key */
	kp1->privsec.priv_p_bitlen = priv_bitlen;
	kp1->privsec.associated_data_len = sizeof(ECC_ASSOCIATED_DATA);
	kp1->privsec.ibm_associated_data_len = sizeof(ECC_ASSOCIATED_DATA);
	kp1->privsec.formatted_data_len = privlen;

	kp1->adata.ibm_data_len = sizeof(ECC_ASSOCIATED_DATA);
	kp1->adata.curve_type = curve_type;
	kp1->adata.p_bitlen = priv_bitlen;
	kp1->adata.usage_flag = 0x80;
	kp1->adata.format_and_sec_flag = 0x40;

	memcpy(&kp1->privkey[0], privkey->D, privlen);

	kp2->pubsec.section_id = 0x21;
	kp2->pubsec.section_len = sizeof(ECC_PUBLIC_KEY_TOKEN) + 2*privlen;
	kp2->pubsec.curve_type = curve_type;
	kp2->pubsec.pub_p_bitlen = priv_bitlen;
	kp2->pubsec.pub_q_bytelen = 2*privlen + 1; /* bytelen + compress flag */

	kp2->compress_flag = 0x04; /* uncompressed key */
	memcpy(&kp2->pubkey[0], X, privlen);
	memcpy(&kp2->pubkey[privlen+0], Y, privlen);

	return sizeof(ECC_PRIVATE_KEY_TOKEN)
			+ privlen
			+ sizeof(ECC_PUBLIC_KEY_TOKEN)
			+ 2*privlen;
}

/**
 * makes an ECDSA verify key structure at given struct and returns its length.
 */
unsigned int make_ecdsa_public_key_token(ECDSA_PUBLIC_KEY_BLOCK *kb,
		const ICA_EC_KEY *pubkey, uint8_t curve_type)
{
	unsigned int privlen = privlen_from_nid(pubkey->nid);
	unsigned int this_length = sizeof(ECDSA_PUBLIC_KEY_BLOCK) + 2*privlen;

	unsigned int priv_bitlen = privlen*8;
	if (pubkey->nid == NID_secp521r1) {
		priv_bitlen = 521;
	}

	kb->key_len = this_length;
	kb->tknhdr.tkn_hdr_id = 0x1E;
	kb->tknhdr.tkn_length = this_length - 2 - 2; /* 2x len field */

	kb->pubsec.section_id = 0x21;
	kb->pubsec.section_len = sizeof(ECC_PUBLIC_KEY_TOKEN) + 2*privlen;
	kb->pubsec.curve_type = curve_type;
	kb->pubsec.pub_p_bitlen = priv_bitlen;
	kb->pubsec.pub_q_bytelen = 2*privlen + 1; /* bytelen + compress flag */

	kb->compress_flag = 0x04; /* uncompressed key */
	memcpy(&kb->pubkey[0], pubkey->X, privlen);
	memcpy(&kb->pubkey[privlen+0], pubkey->Y, privlen);

	return this_length;
}

/**
 * creates an ECDSA sign request message for zcrypt. The given private key does usually
 * not contain a public key (X,Y), but the card requires (X,Y) to be present. The
 * calling function makes sure that (X,Y) are correctly set.
 *
 * returns a pointer to the control block where the card
 * provides its reply.
 */
ECDSA_SIGN_REPLY* make_ecdsa_sign_request(const ICA_EC_KEY *privkey,
		unsigned char *X, unsigned char *Y,
		const unsigned char *hash, unsigned int hash_length,
		struct ica_xcRB* xcrb)
{
    uint8_t *cbrbmem = NULL;
    struct CPRBX *preqcblk, *prepcblk;
    unsigned int privlen = privlen_from_nid(privkey->nid);

	unsigned int ecdsa_key_token_len = 2 + 2 + sizeof(CCA_TOKEN_HDR)
		+ sizeof(ECC_PRIVATE_KEY_SECTION)
		+ sizeof(ECC_ASSOCIATED_DATA) + privlen
		+ sizeof(ECC_PUBLIC_KEY_TOKEN) + 2*privlen;

	unsigned int keyblock_len = 2 + ecdsa_key_token_len;
	unsigned int parmblock_len = sizeof(ECDSA_PARMBLOCK_PART1) + hash_length + keyblock_len;

	unsigned int curve_type = curve_type_from_nid(privkey->nid);
	if (curve_type < 0)
		return NULL;

    /* allocate buffer space for req cprb, req parm, rep cprb, rep parm */
    cbrbmem = malloc(2 * (CPRBXSIZE + PARMBSIZE));
    if (!cbrbmem)
		return NULL;

    memset(cbrbmem, 0, 2 * (CPRBXSIZE + PARMBSIZE));
    preqcblk = (struct CPRBX *) cbrbmem;
    prepcblk = (struct CPRBX *) (cbrbmem + CPRBXSIZE + PARMBSIZE);

    /* make ECDSA sign request */
	unsigned int offset = 0;
	offset = make_cprbx((struct CPRBX *)cbrbmem, parmblock_len, preqcblk, prepcblk);
	offset += make_ecdsa_sign_parmblock((ECDSA_PARMBLOCK_PART1*)(cbrbmem+offset), hash, hash_length);
	offset += make_keyblock_length((ECC_KEYBLOCK_LENGTH*)(cbrbmem+offset), keyblock_len);
	offset += make_ecdsa_private_key_token(cbrbmem+offset, privkey, X, Y, curve_type);
	finalize_xcrb(xcrb, preqcblk, prepcblk);

    return (ECDSA_SIGN_REPLY*)prepcblk;
}

/**
 * calculate the public (X,Y) values for the given private key, if necessary.
 */
unsigned int provide_pubkey(const ICA_EC_KEY *privkey, unsigned char *X, unsigned char *Y)
{
	EC_KEY *eckey = NULL;
	EC_POINT *pub_key = NULL;
	const EC_GROUP *group = NULL;
	BIGNUM *bn_d = NULL, *bn_x = NULL, *bn_y = NULL;
	char* x_str = NULL;
	char* y_str = NULL;
	int privlen = -1;
	unsigned int i, n, rc;

	if (privkey == NULL || X == NULL || Y == NULL) {
		return EFAULT;
	}

	privlen = privlen_from_nid(privkey->nid);
	if (privlen < 0) {
		return EFAULT;
	}

	/* Check if (X,Y) already available */
	if (privkey->X != NULL && privkey->Y != NULL) {
		memcpy(X, privkey->X, privlen);
		memcpy(Y, privkey->Y, privlen);
		return 0;
	}

	/* Get (D) as BIGNUM */
	if ((bn_d = BN_bin2bn(privkey->D, privlen, NULL)) == NULL) {
		return EFAULT;
	}

	/* Calculate public (X,Y) values */
	eckey = EC_KEY_new_by_curve_name(privkey->nid);
	EC_KEY_set_private_key(eckey, bn_d);
	group = EC_KEY_get0_group(eckey);
	pub_key = EC_POINT_new(group);
	if (!EC_POINT_mul(group, pub_key, bn_d, NULL, NULL, NULL)) {
		rc = EFAULT;
		goto end;
	}

	/* Get (X,Y) as BIGNUMs */
	bn_x = BN_new();
	bn_y = BN_new();
	if (!EC_POINT_get_affine_coordinates_GFp(group, pub_key, bn_x, bn_y, NULL)) {
		rc = EFAULT;
		goto end;
	}

	/* Format (X) as char array, with leading zeros if necessary */
	x_str = BN_bn2hex(bn_x);
	n = privlen - strlen(x_str) / 2;
	for (i = 0; i < n; i++)
		X[i] = 0x00;
	BN_bn2bin(bn_x, &(X[n]));

	/* Format (Y) as char array, with leading zeros if necessary */
	y_str = BN_bn2hex(bn_y);
	n = privlen - strlen(y_str) / 2;
	for (i = 0; i < n; i++)
		Y[i] = 0x00;
	BN_bn2bin(bn_y, &(Y[n]));

	rc = 0;

end:

	if (pub_key)
		EC_POINT_free(pub_key);
	if (eckey)
		EC_KEY_free(eckey);
	BN_clear_free(bn_x);
	BN_clear_free(bn_y);
	BN_clear_free(bn_d);
	OPENSSL_free(x_str);
	OPENSSL_free(y_str);

	return rc;
}

/**
 * creates an ECDSA signature via Crypto Express CCA coprocessor.
 * Returns 0 if successful, 1 otherwise.
 */
unsigned int ecdsa_sign_hw(ica_adapter_handle_t adapter_handle,
		const ICA_EC_KEY *privkey, const unsigned char *hash, unsigned int hash_length,
		unsigned char *signature)
{
	int rc;
	struct ica_xcRB xcrb;
	ECDSA_SIGN_REPLY* reply_p;
	unsigned int privlen = privlen_from_nid(privkey->nid);
	unsigned char X[MAX_ECC_PRIV_SIZE];
	unsigned char Y[MAX_ECC_PRIV_SIZE];

	if (adapter_handle == DRIVER_NOT_LOADED)
		return EFAULT;

	rc = provide_pubkey(privkey, (unsigned char*)&X, (unsigned char*)&Y);
	if (rc != 0)
		return EFAULT;

	reply_p = make_ecdsa_sign_request((const ICA_EC_KEY*)privkey,
			(unsigned char*)&X, (unsigned char*)&Y,
			hash, hash_length, &xcrb);
	if (!reply_p)
		return EFAULT;

	rc = ioctl(adapter_handle, ZSECSENDCPRB, xcrb);
	if (rc != 0)
		return EFAULT;

	if (reply_p->vud_len-8 != 2*privlen)
		return EFAULT;

	memcpy(signature, reply_p->signature, reply_p->vud_len-8);

	return 0;
}

/**
 * creates an ECDSA signature in software using OpenSSL.
 * Returns 0 if successful, 1 otherwise.
 */
unsigned int ecdsa_sign_sw(const ICA_EC_KEY *privkey,
		const unsigned char *hash, unsigned int hash_length,
		unsigned char *signature)
{
	int rc = 1;
    EC_KEY *a = NULL;
    BIGNUM* r=NULL; BIGNUM* s=NULL;
    ECDSA_SIG* sig = NULL;
    unsigned int privlen = privlen_from_nid(privkey->nid);
    unsigned int i,n;

#ifdef ICA_FIPS
	if ((fips & ICA_FIPS_MODE) && (!FIPS_mode()))
		return EACCES;
#endif /* ICA_FIPS */

    if ((a = EC_KEY_new_by_curve_name(privkey->nid)) == NULL) {
        goto err;
    }

    a = make_eckey(privkey->nid, privkey->D, privlen);
    if (!a)
        goto err;

    if (!EC_KEY_check_key(a))
        goto err;

    sig = ECDSA_do_sign(hash, hash_length, a);
    if (!sig)
	goto err;

    ECDSA_SIG_get0(sig, (const BIGNUM**)&r, (const BIGNUM **)&s);

    /* Insert leading 0x00's if r or s shorter than privlen */
    n = privlen - BN_num_bytes(r);
	for (i=0;i<n;i++)
		signature[i] = 0x00;
	BN_bn2bin(r, &(signature[n]));

	n = privlen - BN_num_bytes(s);
	for (i=0;i<n;i++)
	signature[privlen+i] = 0x00;
    BN_bn2bin(s, &(signature[privlen+n]));

    rc = 0;

err:
	ECDSA_SIG_free(sig); /* also frees r and s */
	EC_KEY_free(a);

	return (rc);
}

/**
 * verifies an ECDSA signature via Crypto Express CCA coprocessor.
 * Returns 0 if successful, 1 otherwise.
 */
unsigned int ecdsa_verify_hw(ica_adapter_handle_t adapter_handle,
		const ICA_EC_KEY *pubkey, const unsigned char *hash, unsigned int hash_length,
		const unsigned char *signature)
{
	int rc;
	struct ica_xcRB xcrb;
	ECDSA_VERIFY_REPLY* reply_p;

	if (adapter_handle == DRIVER_NOT_LOADED)
		return EFAULT;

	reply_p = make_ecdsa_verify_request(pubkey,	hash, hash_length, signature, &xcrb);
	if (!reply_p)
		return EFAULT;

	rc = ioctl(adapter_handle, ZSECSENDCPRB, xcrb);
	if (rc != 0)
		return EFAULT;

	if (((struct CPRBX*)reply_p)->ccp_rtcode != 0 || ((struct CPRBX*)reply_p)->ccp_rscode != 0)
		return EFAULT;

	return 0;
}

/**
 * verifies an ECDSA signature in software using OpenSSL.
 * Returns 0 if successful, 1 otherwise.
 */
unsigned int ecdsa_verify_sw(const ICA_EC_KEY *pubkey,
		const unsigned char *hash, unsigned int hash_length,
		const unsigned char *signature)
{
	int rc = 1;
    EC_KEY *a = NULL;
    BIGNUM* r=NULL; BIGNUM* s=NULL;
    BIGNUM* xa=NULL; BIGNUM* ya=NULL;
    ECDSA_SIG* sig=NULL;
    unsigned int privlen = privlen_from_nid(pubkey->nid);

#ifdef ICA_FIPS
	if ((fips & ICA_FIPS_MODE) && (!FIPS_mode()))
		return EACCES;
#endif /* ICA_FIPS */

    if ((a = EC_KEY_new_by_curve_name(pubkey->nid)) == NULL) {
        goto err;
    }

    /* create public key with given (x,y) */
	xa = BN_bin2bn(pubkey->X, privlen, xa);
	ya = BN_bin2bn(pubkey->Y, privlen, ya);
    a = make_public_eckey(pubkey->nid, xa, ya, privlen);
    if (!a) {
        goto err;
    }

    /* create ECDSA_SIG instance */
    sig = ECDSA_SIG_new();
    r = BN_bin2bn(signature, privlen, r);
    s = BN_bin2bn(signature+privlen, privlen, s);
    ECDSA_SIG_set0(sig, r, s);

    /* create DER form from ECDSA_SIG and verify it */
    rc = ECDSA_do_verify(hash, hash_length, sig, a);
    if (rc != 1) {
	rc = 1;
	goto err;
    }

    rc = 0;

err:
	BN_clear_free(xa);
	BN_clear_free(ya);
	ECDSA_SIG_free(sig);
    EC_KEY_free(a);

	return rc;
}

/**
 * creates an ECDSA xcrb request message for zcrypt.
 *
 * returns a pointer to the control block where the card
 * provides its reply.
 */
ECDSA_VERIFY_REPLY* make_ecdsa_verify_request(const ICA_EC_KEY *pubkey,
		const unsigned char *hash, unsigned int hash_length,
		const unsigned char *signature, struct ica_xcRB* xcrb)
{
    uint8_t *cbrbmem = NULL;
    struct CPRBX *preqcblk, *prepcblk;
    unsigned int privlen = privlen_from_nid(pubkey->nid);

	unsigned int ecdsa_key_token_len = 2 + 2 + sizeof(CCA_TOKEN_HDR)
		+ sizeof(ECC_PUBLIC_KEY_TOKEN) + 2*privlen;

	unsigned int keyblock_len = 2 + ecdsa_key_token_len;
	unsigned int parmblock_len = sizeof(ECDSA_PARMBLOCK_PART1) + hash_length
		+ sizeof(ECDSA_PARMBLOCK_PART2) + 2*privlen + keyblock_len;

    /* allocate buffer space for req cprb, req parm, rep cprb, rep parm */
    cbrbmem = malloc(2 * (CPRBXSIZE + PARMBSIZE));
    if (!cbrbmem)
		return NULL;

	unsigned int curve_type = curve_type_from_nid(pubkey->nid);
	if (curve_type < 0)
		return NULL;

    memset(cbrbmem, 0, 2 * (CPRBXSIZE + PARMBSIZE));
    preqcblk = (struct CPRBX *) cbrbmem;
    prepcblk = (struct CPRBX *) (cbrbmem + CPRBXSIZE + PARMBSIZE);

    /* make ECDSA verify request */
	unsigned int offset = 0;
	offset = make_cprbx((struct CPRBX *)cbrbmem, parmblock_len, preqcblk, prepcblk);
	offset += make_ecdsa_verify_parmblock((char*)(cbrbmem+offset), hash, hash_length, signature, 2*privlen);
	offset += make_keyblock_length((ECC_KEYBLOCK_LENGTH*)(cbrbmem+offset), keyblock_len);
	offset += make_ecdsa_public_key_token((ECDSA_PUBLIC_KEY_BLOCK*)(cbrbmem+offset), pubkey, curve_type);
	finalize_xcrb(xcrb, preqcblk, prepcblk);

    return (ECDSA_VERIFY_REPLY*)prepcblk;
}

/**
 * makes an ECKeyGen parmblock at given struct and returns its length.
 */
unsigned int make_eckeygen_parmblock(ECKEYGEN_PARMBLOCK *pb)
{
	pb->subfunc_code = 0x5047; /* 'PG' */
	pb->rule_array.rule_array_len = 0x000A;
	memcpy(&(pb->rule_array.rule_array_cmd), "CLEAR   ", 8);
	pb->vud_len = 0x0002;

	return sizeof(ECKEYGEN_PARMBLOCK);
}

/**
 * makes an ECKeyGen private key structure at given struct and returns its length.
 */
unsigned int make_eckeygen_private_key_token(ECKEYGEN_KEY_TOKEN* kb,
		unsigned int nid, uint8_t curve_type)
{
	unsigned int privlen = privlen_from_nid(nid);

	unsigned int priv_bitlen = privlen*8;
	if (nid == NID_secp521r1) {
		priv_bitlen = 521;
	}

	kb->key_len = sizeof(ECKEYGEN_KEY_TOKEN);
	kb->reserved1 = 0x0020;
	kb->tknhdr.tkn_hdr_id = 0x1E;
	kb->tknhdr.tkn_length = sizeof(ECKEYGEN_KEY_TOKEN) - 2 - 2; /* 2x len field */

	kb->privsec.section_id = 0x20;
	kb->privsec.version = 0x00;
	kb->privsec.section_len =  sizeof(ECC_PRIVATE_KEY_SECTION) + sizeof(ECC_ASSOCIATED_DATA);
	kb->privsec.key_usage = 0x80;
	kb->privsec.curve_type = curve_type;
	kb->privsec.key_format = 0x40; /* unencrypted key */
	kb->privsec.priv_p_bitlen = priv_bitlen;
	kb->privsec.associated_data_len = sizeof(ECC_ASSOCIATED_DATA);
	kb->privsec.ibm_associated_data_len = sizeof(ECC_ASSOCIATED_DATA);
	kb->privsec.formatted_data_len = 0; /* no key */

	kb->adata.ibm_data_len = sizeof(ECC_ASSOCIATED_DATA);
	kb->adata.curve_type = curve_type;
	kb->adata.p_bitlen = priv_bitlen;
	kb->adata.usage_flag = 0x80;
	kb->adata.format_and_sec_flag = 0x40;

	kb->pubsec.section_id = 0x21;
	kb->pubsec.section_len = sizeof(ECC_PUBLIC_KEY_SECTION);
	kb->pubsec.curve_type = curve_type;
	kb->pubsec.pub_p_bitlen = priv_bitlen;
	kb->pubsec.pub_q_bytelen = 0; /* no keys */

	return sizeof(ECKEYGEN_KEY_TOKEN);
}

/**
 * creates an ECKeyGen xcrb request message for zcrypt.
 *
 * returns a pointer to the control block where the card
 * provides its reply.
 */
ECKEYGEN_REPLY* make_eckeygen_request(ICA_EC_KEY *key, struct ica_xcRB* xcrb)
{
    uint8_t *cbrbmem = NULL;
    struct CPRBX *preqcblk, *prepcblk;

	unsigned int keyblock_len = 2 + sizeof(ECKEYGEN_KEY_TOKEN)
			+ sizeof(ECC_NULL_TOKEN);
	unsigned int parmblock_len = sizeof(ECKEYGEN_PARMBLOCK) + keyblock_len;

	unsigned int curve_type = curve_type_from_nid(key->nid);
	if (curve_type < 0)
		return NULL;

    /* allocate buffer space for req cprb, req parm, rep cprb, rep parm */
    cbrbmem = malloc(2 * (CPRBXSIZE + PARMBSIZE));
    if (!cbrbmem)
		return NULL;

    memset(cbrbmem, 0, 2 * (CPRBXSIZE + PARMBSIZE));
    preqcblk = (struct CPRBX *) cbrbmem;
    prepcblk = (struct CPRBX *) (cbrbmem + CPRBXSIZE + PARMBSIZE);

    /* make ECKeyGen request */
	unsigned int offset = 0;
	offset = make_cprbx((struct CPRBX *)cbrbmem, parmblock_len, preqcblk, prepcblk);
	offset += make_eckeygen_parmblock((ECKEYGEN_PARMBLOCK*)(cbrbmem+offset));
	offset += make_keyblock_length((ECC_KEYBLOCK_LENGTH*)(cbrbmem+offset), keyblock_len);
	offset += make_eckeygen_private_key_token((ECKEYGEN_KEY_TOKEN*)(cbrbmem+offset), key->nid, curve_type);
	offset += make_ecc_null_token((ECC_NULL_TOKEN*)(cbrbmem+offset));
	finalize_xcrb(xcrb, preqcblk, prepcblk);

    return (ECKEYGEN_REPLY*)prepcblk;
}

/**
 * generates an EC key via Crypto Express CCA coprocessor.
 * Returns 0 if successful, 1 otherwise.
 */
unsigned int eckeygen_hw(ica_adapter_handle_t adapter_handle, ICA_EC_KEY *key)
{
	int rc;
	struct ica_xcRB xcrb;
	ECKEYGEN_REPLY *reply_p;
	unsigned int privlen = privlen_from_nid(key->nid);
	ECC_PUBLIC_KEY_TOKEN* pub_p;
	unsigned char* p;

	reply_p = make_eckeygen_request(key, &xcrb);
	if (!reply_p)
		return EFAULT;

	rc = ioctl(adapter_handle, ZSECSENDCPRB, xcrb);
	if (rc != 0)
		return EFAULT;

	if (reply_p->eckey.privsec.formatted_data_len != privlen)
		return EFAULT;

	memcpy(key->D, reply_p->eckey.privkey, privlen);

	p = (unsigned char*)&(reply_p->eckey.privsec) + reply_p->eckey.privsec.section_len;
	pub_p = (ECC_PUBLIC_KEY_TOKEN*)p;
	if (pub_p->compress_flag != 0x04)
		return EFAULT;

	memcpy(key->X, (char*)pub_p->pubkey, 2*privlen);

	return 0;
}

/**
 * generates an EC key in software using OpenSSL.
 * Returns 0 if successful, 1 otherwise.
 */
unsigned int eckeygen_sw(ICA_EC_KEY *key)
{
	int rc = 1;
    EC_KEY *a = NULL;
    BIGNUM* d=NULL; BIGNUM *x=NULL; BIGNUM *y=NULL;
    const EC_POINT* q=NULL;
    const EC_GROUP *group=NULL;
    char* x_str=NULL; char* y_str=NULL; char* d_str=NULL;
    unsigned int privlen = privlen_from_nid(key->nid);
    unsigned int i, n;

#ifdef ICA_FIPS
	if ((fips & ICA_FIPS_MODE) && (!FIPS_mode()))
		return EACCES;
#endif /* ICA_FIPS */

    if ((a = EC_KEY_new_by_curve_name(key->nid)) == NULL)
        goto err;

    if ((group = EC_KEY_get0_group(a)) == NULL)
        goto err;

    if (!EC_KEY_generate_key(a))
	goto err;

    /* provide private key */
    d = (BIGNUM*)EC_KEY_get0_private_key(a);
    d_str = BN_bn2hex(d);
    n = privlen - strlen(d_str)/2;
    for (i=0;i<n;i++)
	key->D[i] = 0x00;
    BN_bn2bin(d, &(key->D[n]));

    /* provide public key */
    q = EC_KEY_get0_public_key(a);
    x = BN_new();
    y = BN_new();
    if (!EC_POINT_get_affine_coordinates_GFp(group, q, x, y, NULL))
	goto err;

    /* pub(X) */
    x_str = BN_bn2hex(x);
    n = privlen - strlen(x_str)/2;
    for (i=0; i<n; i++)
	key->X[i] = 0x00;
    BN_bn2bin(x, &(key->X[n]));

    /* pub(Y) */
    y_str = BN_bn2hex(y);
    n = privlen - strlen(y_str)/2;
    for (i=0; i<n; i++)
	key->Y[i] = 0x00;
    BN_bn2bin(y, &(key->Y[n]));

    rc = 0;

err:
    /* cleanup */
	EC_KEY_free(a); /* also frees d */
    BN_clear_free(x);
    BN_clear_free(y);
	OPENSSL_free(d_str);
	OPENSSL_free(x_str);
	OPENSSL_free(y_str);

	return rc;
}
