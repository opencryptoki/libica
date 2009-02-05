/* This program is released under the Common Public License V1.0
 *
 * You should have received a copy of Common Public License V1.0 along with
 * with this program.
 */

/**
 * Authors: Felix Beck <felix.beck@de.ibm.com>
 *	    Christian Maaser <cmaaser@de.ibm.com>
 *
 * The content of this file has been moved from former icalinux.c to this file.
 *
 * Copyright IBM Corp. 2009
 */

#include <stdlib.h>
#include "mech_types.h"
#include "ica_api.h"
#include "include/s390_crypto.h"

/**
 * item is assumed to point to the last item in the list, and will be updated
 * by this macro.
 */
#define NEWMECH(mech, minkey, maxkey, flgs) \
if (1)                                                  \
{                                                       \
        item->next = malloc(sizeof(struct mech_list_item));     \
        if (item->next == NULL)                         \
                return;                                 \
        item = item->next;                              \
        item->element.mech_type = mech;         \
        item->element.mech_info.ulMinKeySize = minkey;  \
        item->element.mech_info.ulMaxKeySize = maxkey;  \
        item->element.mech_info.flags = flgs;           \
        item->next = NULL;                              \
} else (void)0

/**
 * Generates a list of supported mechanisms. This is the function that
 * openCryptoki will be calling directly with a pointer to a
 * placeholder mech_list_item struct.
 *
 * @param head Pointer to placeholder mech_list_item struct; this function
 *             fills in the list by tagging on newly malloc'd
 *             mech_list_item structs off of this struct.
 */
void generate_pkcs11_mech_list(struct mech_list_item *head)
{
        struct mech_list_item *item = head;
        ica_adapter_handle_t handle;

	unsigned char kmc_mask[16], kimd_mask[16];

	s390_kmc(S390_CRYPTO_QUERY, kmc_mask, NULL, NULL, 0);
	s390_kimd(S390_CRYPTO_QUERY, kimd_mask, NULL, 0);

        if (kimd_mask[0] & 0x40)
		/* sha1_switch */
                NEWMECH(CKM_SHA_1, 0, 0, CKF_HW | CKF_DIGEST);
        else
                NEWMECH(CKM_SHA_1, 0, 0, CKF_DIGEST);

        if (kimd_mask[0] & 0x20) {
		/* sha256_switch */
                NEWMECH(CKM_SHA224, 0, 0, CKF_HW | CKF_DIGEST);
                NEWMECH(CKM_SHA256, 0, 0, CKF_HW | CKF_DIGEST);
        } else {
                NEWMECH(CKM_SHA224, 0, 0, CKF_DIGEST);
                NEWMECH(CKM_SHA256, 0, 0, CKF_DIGEST);
        }

        if (kimd_mask[0] & 0x10) {
                NEWMECH(CKM_SHA384, 0, 0, CKF_HW | CKF_DIGEST);
                NEWMECH(CKM_SHA512, 0, 0, CKF_HW | CKF_DIGEST);
        } else {
                NEWMECH(CKM_SHA384, 0, 0, CKF_DIGEST);
                NEWMECH(CKM_SHA512, 0, 0, CKF_DIGEST);
        }

        if (kmc_mask[8] & 0x10) {
	/* prng_switch */
                NEWMECH(CKM_VENDOR_DEFINED, 0, 0, CKF_HW);
                NEWMECH(CKM_RSA_PKCS_KEY_PAIR_GEN, 0, 0,
                        CKF_HW | CKF_GENERATE_KEY_PAIR);
                NEWMECH(CKM_RSA_X9_31_KEY_PAIR_GEN, 0, 0,
                        CKF_HW | CKF_GENERATE_KEY_PAIR);
                NEWMECH(CKM_DSA_KEY_PAIR_GEN, 0, 0,
                        CKF_HW | CKF_GENERATE_KEY_PAIR);
                NEWMECH(CKM_DH_PKCS_KEY_PAIR_GEN, 0, 0,
                        CKF_HW | CKF_GENERATE_KEY_PAIR);
                NEWMECH(CKM_X9_42_DH_KEY_PAIR_GEN, 0, 0,
                        CKF_HW | CKF_GENERATE_KEY_PAIR);
                NEWMECH(CKM_RC2_KEY_GEN, 0, 0, CKF_HW | CKF_GENERATE);
                NEWMECH(CKM_RC4_KEY_GEN, 0, 0, CKF_HW | CKF_GENERATE);
                NEWMECH(CKM_DES_KEY_GEN, 0, 0, CKF_HW | CKF_GENERATE);
                NEWMECH(CKM_DES2_KEY_GEN, 0, 0, CKF_HW | CKF_GENERATE);
                NEWMECH(CKM_DES3_KEY_GEN, 0, 0, CKF_HW | CKF_GENERATE);
                NEWMECH(CKM_CDMF_KEY_GEN, 0, 0, CKF_HW | CKF_GENERATE);
                NEWMECH(CKM_CAST_KEY_GEN, 0, 0, CKF_HW | CKF_GENERATE);
                NEWMECH(CKM_CAST3_KEY_GEN, 0, 0, CKF_HW | CKF_GENERATE);
                NEWMECH(CKM_CAST5_KEY_GEN, 0, 0, CKF_HW | CKF_GENERATE);
                NEWMECH(CKM_CAST128_KEY_GEN, 0, 0, CKF_HW | CKF_GENERATE);
                NEWMECH(CKM_RC5_KEY_GEN, 0, 0, CKF_HW | CKF_GENERATE);
                NEWMECH(CKM_IDEA_KEY_GEN, 0, 0, CKF_HW | CKF_GENERATE);
                NEWMECH(CKM_GENERIC_SECRET_KEY_GEN, 0, 0,
                        CKF_HW | CKF_GENERATE);
                NEWMECH(CKM_SSL3_PRE_MASTER_KEY_GEN, 0, 0,
                        CKF_HW | CKF_GENERATE);
                NEWMECH(CKM_TLS_PRE_MASTER_KEY_GEN, 0, 0,
                        CKF_HW | CKF_GENERATE);
                NEWMECH(CKM_SKIPJACK_KEY_GEN, 0, 0, CKF_HW | CKF_GENERATE);
                NEWMECH(CKM_KEA_KEY_PAIR_GEN, 0, 0,
                        CKF_HW | CKF_GENERATE_KEY_PAIR);
                NEWMECH(CKM_BATON_KEY_GEN, 0, 0, CKF_HW | CKF_GENERATE);
                NEWMECH(CKM_EC_KEY_PAIR_GEN, 0, 0,
                        CKF_HW | CKF_GENERATE_KEY_PAIR);
                NEWMECH(CKM_JUNIPER_KEY_GEN, 0, 0, CKF_HW | CKF_GENERATE);
                NEWMECH(CKM_AES_KEY_GEN, 0, 0, CKF_HW | CKF_GENERATE);
        } else {
                NEWMECH(CKM_VENDOR_DEFINED, 0, 0, 0);
                NEWMECH(CKM_RSA_PKCS_KEY_PAIR_GEN, 0, 0, CKF_GENERATE_KEY_PAIR);
                NEWMECH(CKM_RSA_X9_31_KEY_PAIR_GEN, 0, 0,
                        CKF_GENERATE_KEY_PAIR);
                NEWMECH(CKM_DSA_KEY_PAIR_GEN, 0, 0, CKF_GENERATE_KEY_PAIR);
                NEWMECH(CKM_DH_PKCS_KEY_PAIR_GEN, 0, 0, CKF_GENERATE_KEY_PAIR);
                NEWMECH(CKM_X9_42_DH_KEY_PAIR_GEN, 0, 0, CKF_GENERATE_KEY_PAIR);
                NEWMECH(CKM_RC2_KEY_GEN, 0, 0, CKF_GENERATE);
                NEWMECH(CKM_RC4_KEY_GEN, 0, 0, CKF_GENERATE);
                NEWMECH(CKM_DES_KEY_GEN, 0, 0, CKF_GENERATE);
                NEWMECH(CKM_DES2_KEY_GEN, 0, 0, CKF_GENERATE);
                NEWMECH(CKM_DES3_KEY_GEN, 0, 0, CKF_GENERATE);
                NEWMECH(CKM_CDMF_KEY_GEN, 0, 0, CKF_GENERATE);
                NEWMECH(CKM_CAST_KEY_GEN, 0, 0, CKF_GENERATE);
                NEWMECH(CKM_CAST3_KEY_GEN, 0, 0, CKF_GENERATE);
                NEWMECH(CKM_CAST5_KEY_GEN, 0, 0, CKF_GENERATE);
                NEWMECH(CKM_CAST128_KEY_GEN, 0, 0, CKF_GENERATE);
                NEWMECH(CKM_RC5_KEY_GEN, 0, 0, CKF_GENERATE);
                NEWMECH(CKM_IDEA_KEY_GEN, 0, 0, CKF_GENERATE);
                NEWMECH(CKM_GENERIC_SECRET_KEY_GEN, 0, 0, CKF_GENERATE);
                NEWMECH(CKM_SSL3_PRE_MASTER_KEY_GEN, 0, 0, CKF_GENERATE);
                NEWMECH(CKM_TLS_PRE_MASTER_KEY_GEN, 0, 0, CKF_GENERATE);
                NEWMECH(CKM_SKIPJACK_KEY_GEN, 0, 0, CKF_GENERATE);
                NEWMECH(CKM_KEA_KEY_PAIR_GEN, 0, 0, CKF_GENERATE_KEY_PAIR);
                NEWMECH(CKM_BATON_KEY_GEN, 0, 0, CKF_GENERATE);
                NEWMECH(CKM_EC_KEY_PAIR_GEN, 0, 0, CKF_GENERATE_KEY_PAIR);
                NEWMECH(CKM_JUNIPER_KEY_GEN, 0, 0, CKF_GENERATE);
                NEWMECH(CKM_AES_KEY_GEN, 0, 0, CKF_GENERATE);
        }

        if (ica_open_adapter(&handle) == 0) {  // 0 == success
                NEWMECH(CKM_RSA_PKCS, 128, 2048,
                        CKF_HW | CKF_ENCRYPT | CKF_DECRYPT | CKF_SIGN |
                        CKF_SIGN_RECOVER | CKF_VERIFY | CKF_VERIFY_RECOVER |
                        CKF_WRAP | CKF_UNWRAP);
                NEWMECH(CKM_RSA_9796, 128, 2048,
                        CKF_HW | CKF_ENCRYPT | CKF_DECRYPT | CKF_SIGN |
                        CKF_SIGN_RECOVER | CKF_VERIFY | CKF_VERIFY_RECOVER |
                        CKF_WRAP | CKF_UNWRAP);
                NEWMECH(CKM_RSA_X_509, 128, 2048,
                        CKF_HW | CKF_ENCRYPT | CKF_DECRYPT | CKF_SIGN |
                        CKF_SIGN_RECOVER | CKF_VERIFY | CKF_VERIFY_RECOVER |
                        CKF_WRAP | CKF_UNWRAP);
                ica_close_adapter(handle);
        }

	if (kmc_mask[0] & 0x40) {
	/* des_switch */
                NEWMECH(CKM_DES_ECB, 8, 8,
                        CKF_HW | CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP |
                        CKF_UNWRAP);
                NEWMECH(CKM_DES_CBC, 8, 8,
                        CKF_HW | CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP |
                        CKF_UNWRAP);
        } else {
                NEWMECH(CKM_DES_ECB, 8, 8,
                        CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP);
                NEWMECH(CKM_DES_CBC, 8, 8,
                        CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP);
        }

        if (kmc_mask[0] & 0x10) {
	/* tdes_switch */
                NEWMECH(CKM_DES3_ECB, 24, 24,
                        CKF_HW | CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP |
                        CKF_UNWRAP);
                NEWMECH(CKM_DES3_CBC, 24, 24,
                        CKF_HW | CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP |
                        CKF_UNWRAP);
        } else {
                NEWMECH(CKM_DES3_ECB, 24, 24,
                        CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP);
                NEWMECH(CKM_DES3_CBC, 24, 24,
                        CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP);
        }

        if (kmc_mask[2] & 0x08) {
		/* aes256_switch */
                NEWMECH(CKM_AES_ECB, 16, 32,
                        CKF_HW | CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP
                        | CKF_UNWRAP);
                NEWMECH(CKM_AES_CBC, 16, 32,
                        CKF_HW | CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP
                        | CKF_UNWRAP);
        } else if (kmc_mask[2] & 0x10) {
	/* aes192_switch */
                NEWMECH(CKM_AES_ECB, 16, 24,
                        CKF_HW | CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP
                        | CKF_UNWRAP);
                NEWMECH(CKM_AES_CBC, 16, 24,
                        CKF_HW | CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP
                        | CKF_UNWRAP);
                NEWMECH(CKM_AES_ECB, 32, 32,
                        CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP);
                NEWMECH(CKM_AES_CBC, 32, 32,
                        CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP);
	} else if (kmc_mask[2] & 0x20) {
	/* aes128_switch */
                NEWMECH(CKM_AES_ECB, 16, 16,
                        CKF_HW | CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP
                        | CKF_UNWRAP);
                NEWMECH(CKM_AES_CBC, 16, 16,
                        CKF_HW | CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP
                        | CKF_UNWRAP);
                NEWMECH(CKM_AES_ECB, 24, 32,
                        CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP);
                NEWMECH(CKM_AES_CBC, 24, 32,
                        CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP);
        } else {
                NEWMECH(CKM_AES_ECB, 16, 32,
                        CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP);
                NEWMECH(CKM_AES_CBC, 16, 32,
                        CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP);
        }
}

