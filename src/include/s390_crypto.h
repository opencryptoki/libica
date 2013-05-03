/* This program is released under the Common Public License V1.0
 *
 * You should have received a copy of Common Public License V1.0 along with
 * with this program.
 */

/*
 *  Support for s390 cryptographic instructions.
 *
 *  Author(s): Thomas Spatzier
 *             Jan Glauber <jan.glauber@de.ibm.com>
 *             Ralph Wuerthner <rwuerthn@de.ibm.com>
 *	       Felix Beck <felix.beck@de.ibm.com>
 *	       Christian Maaser <cmaaser@de.ibm.com>
 *	       Holger Dengler <hd@linux.vnet.ibm.com>
 *	       Ingo Tuchscherer <ingo.tuchscherer.linux.vnet.ibm.com>
 *
 * Copyright IBM Corp. 2007, 2009, 2011, 2013
 */
#include <ica_api.h>
#ifndef S390_CRYPTO_H
#define S390_CRYPTO_H

#define S390_CRYPTO_TEST_MASK(mask, function) \
	(((unsigned char *)(mask))[((function) & 0x7F) >> 3] & \
        (0x80 >> ((function) & 0x07)))

#define KM   	1
#define KMC  	2
#define KIMD 	3
#define MSA4 	4
#define ADAPTER 5

#define ICA_FLAG_SHW 4 // symmetric operation support (CPACF)
#define ICA_FLAG_DHW 2 // asymmetric operation supported (crypto-card)
#define ICA_FLAG_SW  1 // software implementation 

#define SHA1	  	1
#define SHA224	  	2
#define SHA256	  	3
#define SHA384	  	4
#define SHA512	  	5
#define DES_ECB   	20
#define DES_CBC   	21
#define DES_CBC_CS 	22
#define DES_OFB   	23
#define DES_CFB  	24
#define DES_CTR  	25
#define DES_CTRLST  	26
#define DES_CBC_MAC  	27
#define DES_CMAC  	28
#define DES3_ECB 	41
#define DES3_CBC 	42
#define DES3_CBC_CS 	43
#define DES3_OFB 	44
#define DES3_CFB 	45
#define DES3_CTR 	46
#define DES3_CTRLST 	47
#define DES3_CBC_MAC 	48
#define DES3_CMAC 	49
#define AES_ECB  	60
#define AES_CBC  	61
#define AES_CBC_CS  	62
#define AES_OFB  	63
#define AES_CFB  	64
#define AES_CTR  	65
#define AES_CTRLST  	66
#define AES_CBC_MAC  	67
#define AES_CMAC  	68
#define AES_CCM  	69
#define AES_GCM  	70
#define AES_XTS  	71
#define P_RNG	  	80
#define RSA_ME  	90
#define RSA_CRT  	91
#define RSA_KEY_GEN_ME 	92
#define RSA_KEY_GEN_CRT	93

enum s390_crypto_instruction {
	S390_CRYPTO_DIRECTION_MASK = 0x80,
	S390_CRYPTO_FUNCTION_MASK = 0x7f
};

enum s390_crypto_function {
	/*
	 * The S390_QUERY function is always available for all 4 KM, KMC, KIMD and
	 * KLMD instructions to query the available functions.
	 */
	S390_CRYPTO_QUERY = 0x00,
	/*
	 * The S390_SHA_* functions are available for KIMD and KLMD instructions.
	 */
	S390_CRYPTO_SHA_1 = 0x01,
	S390_CRYPTO_SHA_256 = 0x02,
	S390_CRYPTO_SHA_512 = 0x03,
	S390_CRYPTO_GHASH = 0x41,
	/*
	 * The following functions are available for KM,KMC,KMF,KMO,
	 * and KMCTR instructions.
	 */
	S390_CRYPTO_DEA_ENCRYPT = 0x01,
	S390_CRYPTO_DEA_DECRYPT = 0x01 | 0x80,
	S390_CRYPTO_TDEA_128_ENCRYPT = 0x02,
	S390_CRYPTO_TDEA_128_DECRYPT = 0x02 | 0x80,
	S390_CRYPTO_TDEA_192_ENCRYPT = 0x03,
	S390_CRYPTO_TDEA_192_DECRYPT = 0x03 | 0x80,
	S390_CRYPTO_AES_128_ENCRYPT = 0x12,
	S390_CRYPTO_AES_128_DECRYPT = 0x12 | 0x80,
	S390_CRYPTO_AES_192_ENCRYPT = 0x13,
	S390_CRYPTO_AES_192_DECRYPT = 0x13 | 0x80,
	S390_CRYPTO_AES_256_ENCRYPT = 0x14,
	S390_CRYPTO_AES_256_DECRYPT = 0x14 | 0x80,
	/* XTS is only available for the KM instruction */
	S390_CRYPTO_AES_128_XTS_ENCRYPT = 0x32,
	S390_CRYPTO_AES_128_XTS_DECRYPT = 0x32 | 0x80,
	S390_CRYPTO_AES_256_XTS_ENCRYPT = 0x34,
	S390_CRYPTO_AES_256_XTS_DECRYPT = 0x34 | 0x80,
	/*
	 * The S390_PRNG is only available for the KMC instruction.
	 */
	S390_CRYPTO_PRNG = 0x43
};

unsigned int sha1_switch, sha256_switch, sha512_switch, des_switch,
	     tdes_switch, aes128_switch, aes192_switch, aes192_switch,
	     aes256_switch, prng_switch, tdea128_switch, tdea192_switch,
	     msa4_switch;

typedef struct {
	unsigned int dummy_fc;
	unsigned int hw_fc;
	unsigned int *enabled;
} s390_supported_function_t;

/* Append new dummy fc codes to the end of enumeration. They are used as index
 * to get the right fc code for the hardware. */
typedef enum {
	SHA_1,
	SHA_224,
	SHA_256,
	SHA_384,
	SHA_512,
	GHASH
} kimd_functions_t;

typedef enum {
	DEA_ENCRYPT,
	DEA_DECRYPT,
	TDEA_192_ENCRYPT,
	TDEA_192_DECRYPT,
	AES_128_ENCRYPT,
	AES_128_DECRYPT,
	AES_192_ENCRYPT,
	AES_192_DECRYPT,
	AES_256_ENCRYPT,
	AES_256_DECRYPT,
/* XTS belongs to the KM family */
	AES_128_XTS_ENCRYPT,
	AES_128_XTS_DECRYPT,
	AES_256_XTS_ENCRYPT,
	AES_256_XTS_DECRYPT,
/* PRNG only for KMC */
	PRNG,
} kmc_functions_t;

typedef enum {
	CMAC_AES_128_GENERATE,
	CMAC_AES_128_VERIFY,
	CMAC_AES_192_GENERATE,
	CMAC_AES_192_VERIFY,
	CMAC_AES_256_GENERATE,
	CMAC_AES_256_VERIFY
} pcc_functions_t;

s390_supported_function_t s390_kmc_functions[PRNG + 1];
s390_supported_function_t s390_msa4_functions[AES_256_XTS_DECRYPT + 1];
s390_supported_function_t s390_kimd_functions[GHASH + 1];

int s390_kimd(unsigned long func, void *param, const unsigned char *src,
	      long src_len);
int s390_klmd(unsigned long func, void *param, const unsigned char *src,
	      long src_len);
int s390_km(unsigned long func, void *param, unsigned char *dest,
	    const unsigned char *src, long src_len);
int s390_kmctr(unsigned long func, void *param, unsigned char *dest,
	       unsigned char *src, long src_len, unsigned char *counter);
int s390_kmc(unsigned long func, void *param, unsigned char *dest,
	     const unsigned char *src, long src_len);
int s390_kmo(unsigned long func, void *param, unsigned char *dest,
	     const unsigned char *src, long src_len);
int s390_kmf(unsigned long func, void *param, unsigned char *dest,
	     const unsigned char *src, long src_len, unsigned int *lcfb);
int s390_kmac(unsigned long func, void *param, const unsigned char *src,
	      long src_len);
int s390_stck(void *buf);
void s390_crypto_switches_init(void);
inline int s390_pcc(unsigned long func, void *param);
int s390_initialize_functionlist(void);
int s390_get_functionlist(libica_func_list_element *pmech_list, 
                                      unsigned int *pmech_list_len);
#endif

