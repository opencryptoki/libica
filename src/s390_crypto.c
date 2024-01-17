/* This program is released under the Common Public License V1.0
 *
 * You should have received a copy of Common Public License V1.0 along with
 * with this program.
 */

/*
 * Entry point for crypto graphic instructions on s390. If an instruction
 * is not available, the related function is simulated in software.
 *
 * Authors(s): Ralph Wuerthner <rwuerthn@de.ibm.com>
 *	       Jan Glauber <jan.glauber@de.ibm.com>
 *	       Felix Beck <felix.beck@de.ibm.com>
 *	       Christian Maaser <cmaaser@de.ibm.com>
 *	       Holger Dengler <hd@linux.vnet.ibm.com>
 *	       Ingo Tuchscherer <ingo.tuchscherer.linux.vnet.ibm.com>
 *
 * Copyright IBM Copr. 2007, 2009, 2011, 2013, 2016
 */

#include <stdint.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <dirent.h>

#include "fips.h"
#include "init.h"
#include "s390_crypto.h"

unsigned long long facility_bits[3];
unsigned int sha1_switch, sha256_switch, sha512_switch, sha3_switch, des_switch,
	     tdes_switch, aes128_switch, aes192_switch, aes256_switch,
	     prng_switch, tdea128_switch, tdea192_switch, sha512_drng_switch,
	     msa4_switch, msa5_switch, msa8_switch, trng_switch, msa9_switch,
		 ecc_via_online_card, any_card_online;
int msa;

#define CARD_AVAILABLE		0x01
#define CEXnA_AVAILABLE		0x02
#define CEXnC_AVAILABLE		0x04
#define CEX4C_AVAILABLE		0x08

s390_supported_function_t s390_kimd_functions[] = {
	{SHA_1, S390_CRYPTO_SHA_1, &sha1_switch},
	{SHA_224, S390_CRYPTO_SHA_256, &sha256_switch},
	{SHA_256, S390_CRYPTO_SHA_256, &sha256_switch},
	{SHA_384, S390_CRYPTO_SHA_512, &sha512_switch},
	{SHA_512, S390_CRYPTO_SHA_512, &sha512_switch},
	{SHA_3_224, S390_CRYPTO_SHA_3_224, &sha3_switch},
	{SHA_3_256, S390_CRYPTO_SHA_3_256, &sha3_switch},
	{SHA_3_384, S390_CRYPTO_SHA_3_384, &sha3_switch},
	{SHA_3_512, S390_CRYPTO_SHA_3_512, &sha3_switch},
	{SHAKE_128, S390_CRYPTO_SHAKE_128, &sha3_switch},
	{SHAKE_256, S390_CRYPTO_SHAKE_256, &sha3_switch},
	{GHASH, S390_CRYPTO_GHASH, &msa4_switch},
	{SHA_512_224, S390_CRYPTO_SHA_512, &sha512_switch},
	{SHA_512_256, S390_CRYPTO_SHA_512, &sha512_switch}
};

s390_supported_function_t s390_kmc_functions[] = {
	{DEA_ENCRYPT, S390_CRYPTO_DEA_ENCRYPT, &des_switch},
	{DEA_DECRYPT, S390_CRYPTO_DEA_DECRYPT, &des_switch},
	{TDEA_192_ENCRYPT, S390_CRYPTO_TDEA_192_ENCRYPT, &tdes_switch},
	{TDEA_192_DECRYPT, S390_CRYPTO_TDEA_192_DECRYPT, &tdes_switch},
	{AES_128_ENCRYPT, S390_CRYPTO_AES_128_ENCRYPT, &aes128_switch},
	{AES_128_DECRYPT, S390_CRYPTO_AES_128_DECRYPT, &aes128_switch},
	{AES_192_ENCRYPT, S390_CRYPTO_AES_192_ENCRYPT, &aes192_switch},
	{AES_192_DECRYPT, S390_CRYPTO_AES_192_DECRYPT, &aes192_switch},
	{AES_256_ENCRYPT, S390_CRYPTO_AES_256_ENCRYPT, &aes256_switch},
	{AES_256_DECRYPT, S390_CRYPTO_AES_256_DECRYPT, &aes256_switch},
	{AES_128_XTS_ENCRYPT, S390_CRYPTO_AES_128_XTS_ENCRYPT, &msa4_switch},
	{AES_128_XTS_DECRYPT, S390_CRYPTO_AES_128_XTS_DECRYPT, &msa4_switch},
	{AES_256_XTS_ENCRYPT, S390_CRYPTO_AES_256_XTS_ENCRYPT, &msa4_switch},
	{AES_256_XTS_DECRYPT, S390_CRYPTO_AES_256_XTS_DECRYPT, &msa4_switch},
	{PRNG, S390_CRYPTO_PRNG, &prng_switch}
};

s390_supported_function_t s390_msa4_functions[] = {
	{DEA_ENCRYPT, S390_CRYPTO_DEA_ENCRYPT, &msa4_switch},
	{DEA_DECRYPT, S390_CRYPTO_DEA_DECRYPT, &msa4_switch},
	{TDEA_192_ENCRYPT, S390_CRYPTO_TDEA_192_ENCRYPT, &msa4_switch},
	{TDEA_192_DECRYPT, S390_CRYPTO_TDEA_192_DECRYPT, &msa4_switch},
	{AES_128_ENCRYPT, S390_CRYPTO_AES_128_ENCRYPT, &msa4_switch},
	{AES_128_DECRYPT, S390_CRYPTO_AES_128_DECRYPT, &msa4_switch},
	{AES_192_ENCRYPT, S390_CRYPTO_AES_192_ENCRYPT, &msa4_switch},
	{AES_192_DECRYPT, S390_CRYPTO_AES_192_DECRYPT, &msa4_switch},
	{AES_256_ENCRYPT, S390_CRYPTO_AES_256_ENCRYPT, &msa4_switch},
	{AES_256_DECRYPT, S390_CRYPTO_AES_256_DECRYPT, &msa4_switch},
	{AES_128_XTS_ENCRYPT, S390_CRYPTO_AES_128_XTS_ENCRYPT, &msa4_switch},
	{AES_128_XTS_DECRYPT, S390_CRYPTO_AES_128_XTS_DECRYPT, &msa4_switch},
	{AES_256_XTS_ENCRYPT, S390_CRYPTO_AES_256_XTS_ENCRYPT, &msa4_switch},
	{AES_256_XTS_DECRYPT, S390_CRYPTO_AES_256_XTS_DECRYPT, &msa4_switch}
};

s390_supported_function_t s390_pcc_functions[] = {
	{0, 0, &msa4_switch},	/* CMAC_AES not supported */
	{0, 0, &msa4_switch},
	{0, 0, &msa4_switch},
	{0, 0, &msa4_switch},
	{0, 0, &msa4_switch},
	{0, 0, &msa4_switch},
	{SCALAR_MULTIPLY_P256, S390_CRYPTO_SCALAR_MULTIPLY_P256, &msa9_switch},
	{SCALAR_MULTIPLY_P384, S390_CRYPTO_SCALAR_MULTIPLY_P384, &msa9_switch},
	{SCALAR_MULTIPLY_P521, S390_CRYPTO_SCALAR_MULTIPLY_P521, &msa9_switch},
	{SCALAR_MULTIPLY_ED25519, S390_CRYPTO_SCALAR_MULTIPLY_ED25519, &msa9_switch},
	{SCALAR_MULTIPLY_ED448, S390_CRYPTO_SCALAR_MULTIPLY_ED448, &msa9_switch},
	{SCALAR_MULTIPLY_X25519, S390_CRYPTO_SCALAR_MULTIPLY_X25519, &msa9_switch},
	{SCALAR_MULTIPLY_X448, S390_CRYPTO_SCALAR_MULTIPLY_X448, &msa9_switch},
};

s390_supported_function_t s390_ppno_functions[] = {
	{SHA512_DRNG_GEN, S390_CRYPTO_SHA512_DRNG_GEN, &sha512_drng_switch},
	{SHA512_DRNG_SEED, S390_CRYPTO_SHA512_DRNG_SEED, &sha512_drng_switch},
	{TRNG, S390_CRYPTO_TRNG, &trng_switch},
};

s390_supported_function_t s390_kma_functions[] = {
	{0, 0, &msa8_switch},	/* DEA not supported */
	{0, 0, &msa8_switch},
	{0, 0, &msa8_switch},	/* TDEA not supported */
	{0, 0, &msa8_switch},
	{AES_128_GCM_ENCRYPT, S390_CRYPTO_AES_128_GCM_ENCRYPT, &msa8_switch},
	{AES_128_GCM_DECRYPT, S390_CRYPTO_AES_128_GCM_DECRYPT, &msa8_switch},
	{AES_192_GCM_ENCRYPT, S390_CRYPTO_AES_192_GCM_ENCRYPT, &msa8_switch},
	{AES_192_GCM_DECRYPT, S390_CRYPTO_AES_192_GCM_DECRYPT, &msa8_switch},
	{AES_256_GCM_ENCRYPT, S390_CRYPTO_AES_256_GCM_ENCRYPT, &msa8_switch},
	{AES_256_GCM_DECRYPT, S390_CRYPTO_AES_256_GCM_DECRYPT, &msa8_switch}
};

s390_supported_function_t s390_kdsa_functions[] = {
	{ECDSA_VERIFY_P256, S390_CRYPTO_ECDSA_VERIFY_P256, &msa9_switch},
	{ECDSA_VERIFY_P384, S390_CRYPTO_ECDSA_VERIFY_P384, &msa9_switch},
	{ECDSA_VERIFY_P521, S390_CRYPTO_ECDSA_VERIFY_P521, &msa9_switch},
	{ECDSA_SIGN_P256, S390_CRYPTO_ECDSA_SIGN_P256, &msa9_switch},
	{ECDSA_SIGN_P384, S390_CRYPTO_ECDSA_SIGN_P384, &msa9_switch},
	{ECDSA_SIGN_P521, S390_CRYPTO_ECDSA_SIGN_P521, &msa9_switch},
	{EDDSA_VERIFY_ED25519, S390_CRYPTO_EDDSA_VERIFY_ED25519, &msa9_switch},
	{EDDSA_VERIFY_ED448, S390_CRYPTO_EDDSA_VERIFY_ED448, &msa9_switch},
	{EDDSA_SIGN_ED25519, S390_CRYPTO_EDDSA_SIGN_ED25519, &msa9_switch},
	{EDDSA_SIGN_ED448, S390_CRYPTO_EDDSA_SIGN_ED448, &msa9_switch},
};

static int read_cpuinfo(void)
{
	int msa = 0;
	FILE *handle = fopen("/proc/cpuinfo", "r");
	if (handle) {
		char buffer[80];
		int i = 0;
		while(fgets(buffer, sizeof(buffer), handle)) {
			i++;
			if(strstr(buffer,"features") && strstr(buffer,"msa")) {
				msa = 1;
				break;
			}
		}
		fclose(handle);
	}
	return msa;
}

/*
 * Check if "vector enablement control"-bit and
 * "AFP register control"-bit in control register 0 are set.
 */
static int vx_enabled(void)
{
	FILE *fd;
	char buf[4096];

	if ((fd = fopen("/proc/cpuinfo", "r")) == NULL)
		return 0;

	buf[0] = '\0';

	while ((fgets(buf, sizeof(buf), fd) != NULL)
	       && (strstr(buf, "features") != buf));

	fclose(fd);

	return (strstr(buf, " vx ") != NULL) ? 1 : 0;
}

static int read_facility_bits(void)
{
	char *s;
	int env_msa;
	int msa = 0;
	struct sigaction oldact;
	sigset_t oldset;
	int rc = -1;

	memset(&oldact, 0, sizeof(oldact));
	memset(&oldset, 0, sizeof(oldset));
	memset(facility_bits, 0, sizeof(facility_bits));

	rc = begin_sigill_section(&oldact, &oldset);
	if (!rc)
		rc = __stfle(facility_bits, 3);

	end_sigill_section(&oldact, &oldset);

	/* __stfle always returns the no. of double words needed to store the
	 * facility bits. This quantity is machine dependent. With MSA8, we
	 * need the first three double words. */
	if(rc >= 2){
		if(facility_bits[0] & (1ULL << (63 - 17)))
			msa = 1;
		if(facility_bits[1] & (1ULL << (127 - 76)))
			msa = 3;
		if(facility_bits[1] & (1ULL << (127 - 77)))
			msa = 4;
		if(facility_bits[0] & (1ULL << (63 - 57)))
			msa = 5;
		if (facility_bits[2] & (1ULL << (191 - 146)))
			msa = 8;
		if (facility_bits[2] & (1ULL << (191 - 155)))
			msa = 9;
	}

	/**
	 * allow specifying the MSA level via environment variable
	 * to simulate older hardware.
	 */
	s = getenv("MSA");
	if (s) {
		if (sscanf(s, "%d", &env_msa) == 1)
			msa = env_msa > msa ? msa : env_msa;
	}

	/* protect against disabled vector facility */
	if (!vx_enabled()) {
		facility_bits[2] &= ~(1ULL << 56 | 1ULL << 57 | 1ULL << 62);
	}

	return msa;
}

static void set_switches(int msa)
{
	unsigned char mask[16];
	unsigned int n;
	struct sigaction oldact;
	sigset_t oldset;

	memset(&oldact, 0, sizeof(oldact));
	memset(&oldset, 0, sizeof(oldset));

	/* kmc query */
	memset(mask, 0, sizeof(mask));
	if (msa) {
		if (begin_sigill_section(&oldact, &oldset) == 0)
			s390_kmc(S390_CRYPTO_QUERY, mask, (void *) 0, (void *) 0, 0);
		end_sigill_section(&oldact, &oldset);
	}
	for (n = 0; n < (sizeof(s390_kmc_functions) /
			 sizeof(s390_supported_function_t)); n++)
		if (S390_CRYPTO_TEST_MASK(mask, s390_kmc_functions[n].hw_fc))
			*s390_kmc_functions[n].enabled = 1;

	/* kimd query */
	memset(mask, 0, sizeof(mask));
	if (msa) {
		if (begin_sigill_section(&oldact, &oldset) == 0)
			s390_kimd(S390_CRYPTO_QUERY, mask, (void *) 0, 0);
		end_sigill_section(&oldact, &oldset);
	}
	for (n = 0; n < (sizeof(s390_kimd_functions) /
			 sizeof(s390_supported_function_t)); n++)
		if (S390_CRYPTO_TEST_MASK(mask, s390_kimd_functions[n].hw_fc))
			*s390_kimd_functions[n].enabled = 1;

	/* pcc query */
	memset(mask, 0, sizeof(mask));
	if (4 <= msa) {
		msa4_switch = 1;
		if (begin_sigill_section(&oldact, &oldset) == 0)
			s390_pcc(S390_CRYPTO_QUERY, mask);
		end_sigill_section(&oldact, &oldset);
	}
	for (n = 0; n < (sizeof(s390_pcc_functions) /
			 sizeof(s390_supported_function_t)); n++)
		if (S390_CRYPTO_TEST_MASK(mask, s390_pcc_functions[n].hw_fc))
			*s390_pcc_functions[n].enabled = 1;

	/* ppno query */
	memset(mask, 0, sizeof(mask));
	if (5 <= msa) {
		msa5_switch = 1;
		if (begin_sigill_section(&oldact, &oldset) == 0)
			s390_ppno(S390_CRYPTO_QUERY, mask, NULL, 0, NULL, 0);
		end_sigill_section(&oldact, &oldset);
	}
	for (n = 0; n < (sizeof(s390_ppno_functions) /
			 sizeof(s390_supported_function_t)); n++)
		if (S390_CRYPTO_TEST_MASK(mask, s390_ppno_functions[n].hw_fc))
			*s390_ppno_functions[n].enabled = 1;

	/* kma query */
	memset(mask, 0, sizeof(mask));
	if (8 <= msa) {
		msa8_switch = 1;
		if (begin_sigill_section(&oldact, &oldset) == 0)
			s390_kma(S390_CRYPTO_QUERY, mask, NULL, NULL, 0, NULL, 0);
		end_sigill_section(&oldact, &oldset);
	}
	for (n = 0; n < (sizeof(s390_kma_functions) /
			 sizeof(s390_supported_function_t)); n++)
		if (S390_CRYPTO_TEST_MASK(mask, s390_kma_functions[n].hw_fc))
			*s390_kma_functions[n].enabled = 1;

	/* kdsa query */
	memset(mask, 0, sizeof(mask));
	if (9 <= msa) {
		msa9_switch = 1;
		if (begin_sigill_section(&oldact, &oldset) == 0)
			s390_kdsa(S390_CRYPTO_QUERY, mask, NULL, 0);
		end_sigill_section(&oldact, &oldset);
	}
	for (n = 0; n < (sizeof(s390_kdsa_functions) /
			 sizeof(s390_supported_function_t)); n++)
		if (S390_CRYPTO_TEST_MASK(mask, s390_kdsa_functions[n].hw_fc))
			*s390_kdsa_functions[n].enabled = 1;
}

int file_fgets(const char *fname, char *buf, size_t buflen)
{
	FILE *fp;
	char *end;
	int rc = 0;

	buf[0] = '\0';

	fp = fopen(fname, "r");
	if (fp == NULL) {
		return EIO;
	}
	if (fgets(buf, buflen, fp) == NULL) {
		rc = EIO;
		goto out_fclose;
	}

	end = memchr(buf, '\n', buflen);
	if (end)
		*end = 0;
	else
		buf[buflen - 1] = 0;

	if (strlen(buf) == 0) {
		rc = EIO;
		goto out_fclose;
	}

out_fclose:
	fclose(fp);
	return rc;
}

unsigned int get_device_type(const char *dev, char *devtype)
{
	unsigned int ret = 0;
	char *type = NULL;
	size_t size = 0;
	FILE *file;

	file = fopen(dev, "r");
	if (file == NULL)
		return 0;

	/* Read device type: e.g. 'CEX5C' */
	if (getline(&type, &size, file) == -1)
		goto end;

	/* Did we get something like 'CEX5C\n'? */
	if (strlen(type) != 6 || strncmp(type, "CEX", 3) != 0)
		goto end;

	memcpy(devtype, type, 5);
	ret = 1;

end:
	free(type);
	fclose(file);

	return ret;
}

#define AP_PATH  "/sys/devices/ap"
#define MAX_DEV_LEN 280

unsigned int search_for_cards()
{
	DIR *sysDir;
	unsigned int ret = 0;
	char dev[MAX_DEV_LEN] = AP_PATH;
	char buf[250];
	struct dirent *direntp;
	char type[6];
	int rc;

	if ((sysDir = opendir(dev)) == NULL)
		return 0;

	while ((direntp = readdir(sysDir)) != NULL) {

		/* Skip entries that are not like "card01", "card02", etc. */
		if (strncmp(direntp->d_name, "card", 4) != 0)
			continue;

		/* Check if device online, configured, and not in checkstop */
		snprintf(dev, MAX_DEV_LEN, "%s/%s/online", AP_PATH, direntp->d_name);
		rc = file_fgets(dev, buf, sizeof(buf));
		if (rc != 0 || strcmp(buf, "1") != 0)
			continue;

		snprintf(dev, MAX_DEV_LEN, "%s/%s/config", AP_PATH, direntp->d_name);
		rc = file_fgets(dev, buf, sizeof(buf));
		if (rc == 0 && strcmp(buf, "1") != 0)
			continue;

		snprintf(dev, MAX_DEV_LEN, "%s/%s/chkstop", AP_PATH, direntp->d_name);
		rc = file_fgets(dev, buf, sizeof(buf));
		if (rc == 0 && strcmp(buf, "0") != 0)
			continue;

		/* Get device type (string like "CEXnT") */
		snprintf(dev, MAX_DEV_LEN, "%s/%s/type", AP_PATH, direntp->d_name);
		memset(type, 0, sizeof(type));
		if (!get_device_type(dev, type))
			continue;

		/* Now setup return value according to found card */
		if (type[4] == 'A')
			ret |= CARD_AVAILABLE | CEXnA_AVAILABLE;

		if (type[4] == 'C')
			ret |= CARD_AVAILABLE | CEXnC_AVAILABLE;

		if (type[3] >= '4' && type[4] == 'C')
			ret |= CARD_AVAILABLE | CEX4C_AVAILABLE;
	}

	closedir(sysDir);

	return ret;
}

void s390_crypto_switches_init(void)
{
	int flags;

	msa = read_facility_bits();
	if (!msa)
		msa = read_cpuinfo();

	flags = search_for_cards();
	if (flags & CARD_AVAILABLE)
		any_card_online = 1;
	if (flags & CEX4C_AVAILABLE)
		ecc_via_online_card = 1;

	set_switches(msa);
}

/*
 * The first field represents the mechanism ID.
 * The second field represents the function family type (category),
 * The third field represents the function code.
 * This function code will be used later to check if HW support
 * is available and modifies the SW/HW-support-flag.
 * SHW - static hardware support (CPACF)
 * DHW - dynamic hardware support (crypto adapter)
 * SW  - software support
 * Bit field flags: [0|0|0|0|0|SHW|DHW|SW]
 * The last field represents the property flags indicating key lengths
 * Update with libica 4.2.0:
 *  - Added two more int fields for the fips service indicator. They do not
 *    affect the libica functionlist.
 */
libica_func_list_element_int icaList[] = {
 {SHA1,   KIMD, SHA_1  , 0, 0, 0, 0},
 {SHA224, KIMD, SHA_256, 0, 0, 0, 0},
 {SHA256, KIMD, SHA_256, 0, 0, 0, 0},
 {SHA384, KIMD, SHA_512, 0, 0, 0, 0},
 {SHA512, KIMD, SHA_512, 0, 0, 0, 0},
 {SHA512_224, KIMD, SHA_512_224, 0, 0, 0, 0},
 {SHA512_256, KIMD, SHA_512_256, 0, 0, 0, 0},
 {SHA3_224, KIMD, SHA_3_224, 0, 0, 0, 0},
 {SHA3_256, KIMD, SHA_3_256, 0, 0, 0, 0},
 {SHA3_384, KIMD, SHA_3_384, 0, 0, 0, 0},
 {SHA3_512, KIMD, SHA_3_512, 0, 0, 0, 0},
 {SHAKE128, KIMD, SHAKE_128, 0, 0, 0, 0},
 {SHAKE256, KIMD, SHAKE_256, 0, 0, 0, 0},
 {G_HASH, KIMD, GHASH, 0, 0, 0, 0},

 {DES_ECB,      KMC,  DEA_ENCRYPT, ICA_FLAG_SW, 0, 0, 0},
 {DES_CBC,      KMC,  DEA_ENCRYPT, ICA_FLAG_SW, 0, 0, 0},
 {DES_OFB,      MSA4, DEA_ENCRYPT, 0, 0, 0, 0},
 {DES_CFB,      MSA4, DEA_ENCRYPT, 0, 0, 0, 0},
 {DES_CTR,      MSA4, DEA_ENCRYPT, 0, 0, 0, 0},
 {DES_CMAC,     MSA4, DEA_ENCRYPT, 0, 0, 0, 0}, // CPACF only (MSA4)

 {DES3_ECB,     KMC,  TDEA_192_ENCRYPT, ICA_FLAG_SW, 0, 0, 0},
 {DES3_CBC,     KMC,  TDEA_192_ENCRYPT, ICA_FLAG_SW, 0, 0, 0},
 {DES3_OFB,     MSA4, TDEA_192_ENCRYPT,           0, 0, 0, 0},
 {DES3_CFB,     MSA4, TDEA_192_ENCRYPT,           0, 0, 0, 0},
 {DES3_CTR,     MSA4, TDEA_192_ENCRYPT,           0, 0, 0, 0},
 {DES3_CMAC,    MSA4, TDEA_192_ENCRYPT,           0, 0, 0, 0},

 {AES_ECB,      KMC,  AES_128_ENCRYPT, ICA_FLAG_SW, 0, 0, 0},
 {AES_CBC,      KMC,  AES_128_ENCRYPT, ICA_FLAG_SW, 0, 0, 0},
 {AES_OFB,      MSA4, AES_128_ENCRYPT,           0, 0, 0, 0},
 {AES_CFB,      MSA4, AES_128_ENCRYPT,           0, 0, 0, 0},
 {AES_CTR,      MSA4, AES_128_ENCRYPT,           0, 0, 0, 0},
 {AES_CMAC,     MSA4, AES_128_ENCRYPT,           0, 0, 0, 0},
 {AES_CCM,      MSA4, AES_128_ENCRYPT,           0, 0, 0, 0},
 {AES_GCM,      MSA4, AES_128_ENCRYPT,           0, 0, 0, 0},
 {AES_GCM_KMA,  MSA8, AES_128_GCM_ENCRYPT,       0, 0, 0, 0},
 {AES_XTS,      MSA4, AES_128_XTS_ENCRYPT,       0, 0, 0, 0},
 {P_RNG,        ADAPTER, 0, ICA_FLAG_SHW | ICA_FLAG_SW, 0, 0, 0}, // SHW (CPACF) + SW
 {EC_DH,        ADAPTER, 0, ICA_FLAG_SW, 0, 0, 0},
 {EC_DSA_SIGN,	ADAPTER, 0, ICA_FLAG_SW, 0, 0, 0},
 {EC_DSA_VERIFY, ADAPTER, 0, ICA_FLAG_SW, 0, 0, 0},
 {EC_KGEN,      ADAPTER, 0, ICA_FLAG_SW, 0, 0, 0},
 {ED25519_KEYGEN, MSA9, SCALAR_MULTIPLY_ED25519, 0, 0, 0, 0},
 {ED25519_SIGN,   MSA9, EDDSA_SIGN_ED25519, 0, 0, 0, 0},
 {ED25519_VERIFY, MSA9, EDDSA_VERIFY_ED25519, 0, 0, 0, 0},
 {ED448_KEYGEN,   MSA9, SCALAR_MULTIPLY_ED448, 0, 0, 0, 0},
 {ED448_SIGN,     MSA9, EDDSA_SIGN_ED448, 0, 0, 0, 0},
 {ED448_VERIFY,   MSA9, EDDSA_VERIFY_ED448, 0, 0, 0, 0},
 {X25519_KEYGEN,   MSA9, SCALAR_MULTIPLY_X25519, 0, 0, 0, 0},
 {X25519_DERIVE,   MSA9, SCALAR_MULTIPLY_X25519, 0, 0, 0, 0},
 {X448_KEYGEN,   MSA9, SCALAR_MULTIPLY_X448, 0, 0, 0, 0},
 {X448_DERIVE,   MSA9, SCALAR_MULTIPLY_X448, 0, 0, 0, 0},
 {RSA_ME,       ADAPTER, 0, ICA_FLAG_SW, 0, 0, 0},
 {RSA_CRT,      ADAPTER, 0, ICA_FLAG_SW, 0, 0, 0},
 {RSA_KEY_GEN_ME, ADAPTER, 0, ICA_FLAG_SW, 0, 0, 0},  // SW (openssl)
 {RSA_KEY_GEN_CRT, ADAPTER, 0, ICA_FLAG_SW, 0, 0, 0}, // SW (openssl)

 {SHA512_DRNG, PPNO, SHA512_DRNG_GEN, ICA_FLAG_SW, 0, 0, 0},

};

/*
 * initializes the libica function list
 * Query s390_xxx_functions for each algorithm to check
 * CPACF support and update the corresponding SHW-flags.
 */
int s390_initialize_functionlist()
{
	unsigned int list_len = sizeof(icaList)/sizeof(libica_func_list_element_int);
	unsigned int x;
	
	for (x = 0; x < list_len; x++) {

		libica_func_list_element_int *e = &icaList[x];

		switch ((int) e->type) {
		case KIMD:
			e->flags |= *s390_kimd_functions[e->id].enabled ? ICA_FLAG_SHW : 0;
			break;
		case KMC:
			e->flags |= *s390_kmc_functions[e->id].enabled ? ICA_FLAG_SHW : 0;
			if (e->id == AES_128_ENCRYPT) { // check for the maximum size
				if (*s390_kmc_functions[icaList[AES_256_ENCRYPT].id].enabled)
					e->property |= ICA_PROPERTY_AES_256;
				if (*s390_kmc_functions[icaList[AES_192_ENCRYPT].id].enabled)
					e->property |= ICA_PROPERTY_AES_192;
				if (*s390_kmc_functions[icaList[AES_128_ENCRYPT].id].enabled)
					e->property |= ICA_PROPERTY_AES_128;
			}
			break;
		case MSA4:
			e->flags |= *s390_msa4_functions[e->id].enabled ? ICA_FLAG_SHW : 0;
			if (e->id == AES_128_ENCRYPT) { // check for the maximum size
				if (*s390_msa4_functions[icaList[AES_256_ENCRYPT].id].enabled)
					e->property |= ICA_PROPERTY_AES_256;
				if (*s390_msa4_functions[icaList[AES_192_ENCRYPT].id].enabled)
					e->property |= ICA_PROPERTY_AES_192;
				if (*s390_msa4_functions[icaList[AES_128_ENCRYPT].id].enabled)
					e->property |= ICA_PROPERTY_AES_128;
			} else if (e->id == AES_128_XTS_ENCRYPT) { // check for the maximum size
				if (*s390_msa4_functions[icaList[AES_256_XTS_ENCRYPT].id].enabled)
					e->property |= ICA_PROPERTY_AES_256;
				if (*s390_msa4_functions[icaList[AES_128_XTS_ENCRYPT].id].enabled)
					e->property |= ICA_PROPERTY_AES_128;
			}
			break;
		case PPNO:
			e->flags |= *s390_ppno_functions[e->id].enabled ? ICA_FLAG_SHW : 0;
			break;
		case MSA8:
			e->flags |= *s390_kma_functions[e->id].enabled ? ICA_FLAG_SHW : 0;
			e->property |= ICA_PROPERTY_AES_128;
			e->property |= ICA_PROPERTY_AES_192;
			e->property |= ICA_PROPERTY_AES_256;
			break;
		case MSA9:
			if (e->mech_mode_id == ED25519_KEYGEN
				|| e->mech_mode_id == ED448_KEYGEN
				|| e->mech_mode_id == X25519_KEYGEN
				|| e->mech_mode_id == X25519_DERIVE
				|| e->mech_mode_id == X448_KEYGEN
				|| e->mech_mode_id == X448_DERIVE)
				e->flags |= *s390_pcc_functions[e->id].enabled ? ICA_FLAG_SHW : 0;
			else
				e->flags |= *s390_kdsa_functions[e->id].enabled ? ICA_FLAG_SHW : 0;
			e->property |= ICA_PROPERTY_EC_ED;
			break;
		default:
			/* Do nothing. */
			break;
		}

		switch ((int) e->mech_mode_id) {
		case EC_DH: /* fall-through */
		case EC_DSA_SIGN: /* fall-through */
		case EC_DSA_VERIFY: /* fall-through */
		case EC_KGEN:
			e->flags |= *s390_kdsa_functions[e->id].enabled ? ICA_FLAG_SHW : 0;
			if (e->flags)
				e->property |= ICA_PROPERTY_EC_NIST;
			if (ecc_via_online_card) {
				e->flags |= ICA_FLAG_DHW;
				e->property |= ICA_PROPERTY_EC_BP | ICA_PROPERTY_EC_NIST;
			}
			break;
		case RSA_ME: /* fall-through */
		case RSA_CRT:
			if (any_card_online) {
				e->flags |= ICA_FLAG_DHW;
				e->property |= ICA_PROPERTY_RSA_ALL;
			}
			break;
		case RSA_KEY_GEN_ME: /* fall-through */
		case RSA_KEY_GEN_CRT:
			if (any_card_online) {
				/* sw flag already pre-set in icaList */
				e->property |= ICA_PROPERTY_RSA_ALL;
			}
			break;
		default:
			/* Do nothing. */
			break;
		}
	}

	return 0;
}

/**
 * Function that returns a list of crypto mechanisms supported by libica.
 * @param pmech_list
 *    Pointer to an array of libica_func_list_element
 *    If NULL, the API will return the number of elements to allocate
 *    in the @pmech_list_len parameter.
 *    If not NULL, libica will assume @pmech_list is an array that has
 *    @pmech_list_len elements.
 *    On success, @pmech_list will be filled out with the supported libica
 *    crypto mechanisms.
 * @param pmech_list_len
 *    number of list entries
 *    On input, pointer to the number of elements allocated in the
 *    @pmech_list array.
 *    On output, @pmech_list_len will contain the number of items copied to
 *    the @pmech_list array, or the number of items libica would have returned
 *    in case the @pmech_list parameter is set to NULL.
 *
 * @return
 *    0 on success
 *    EINVAL if at least one invalid parameter is given
 *
 *   A typical usage scenario would be that an exploiter makes a first call to
 *   ica_get_functionlist() with @pmech_list set to NULL in order to determine
 *   the number of elements to allocate. This is followed by a second call to
 *   ica_get_functionlist() with a valid pointer @pmech_list to an array of
 *   libica_func_list_element structures with @pmech_list_len elements.
 */
int s390_get_functionlist(libica_func_list_element *pmech_list,
				      unsigned int *pmech_list_len) {
  unsigned int x;

  if (!pmech_list_len) {
	return EINVAL;
  }

  if (!pmech_list) {
	*pmech_list_len = sizeof(icaList)/sizeof(libica_func_list_element_int);
	return 0;
  } else if (*pmech_list_len <
	     (sizeof(icaList)/sizeof(libica_func_list_element_int)) ) {
	return EINVAL;
  }

  for (x = 0; x < *pmech_list_len; x++) {
      pmech_list[x].mech_mode_id = icaList[x].mech_mode_id;
      pmech_list[x].flags        = icaList[x].flags;
      pmech_list[x].property     = icaList[x].property;
#ifdef ICA_FIPS
	/* Disable the algorithm in the following cases:
	 * - We are running in FIPS mode and the algorithm is not FIPS
	 *   approved.
	 * - We are in an error state.
	 * */
	if (((fips & ICA_FIPS_MODE) && !fips_approved(pmech_list[x].mech_mode_id &&
		!fips_override(pmech_list[x].mech_mode_id)))
	    || fips >> 1) {
		pmech_list[x].flags = 0;
		pmech_list[x].property = 0;
	}

	/* Adjust the flags and properties for algorithms that are allowed in fips
	 * mode, but not on any hardware, with any openssl, not with any key
	 * length, curve etc. */
	if (fips & ICA_FIPS_MODE) {
		/* RSA >= 2048 bits in FIPS 140-3 mode */
		switch (pmech_list[x].mech_mode_id) {
		case RSA_KEY_GEN_ME:
		case RSA_KEY_GEN_CRT:
		case RSA_ME:
		case RSA_CRT:
			if (pmech_list[x].flags)
				pmech_list[x].property = ICA_PROPERTY_RSA_FIPS;
			else
				pmech_list[x].property = 0;
			break;
		default:
			break;
		}

		/* ECDSA/ECDH in FIPS 140-3 mode */
		switch (pmech_list[x].mech_mode_id) {
		case EC_KGEN:
			/* EC keygen only via openssl because of internal key checks */
			pmech_list[x].flags = ICA_FLAG_SW;
			pmech_list[x].property &= ~ICA_PROPERTY_EC_BP;
			pmech_list[x].property &= ~ICA_PROPERTY_EC_ED;
			break;
		case EC_DH:
		case EC_DSA_SIGN:
		case EC_DSA_VERIFY:
			/* EC sign/verify/dh only NIST curves via CPACF because of self-tests */
			pmech_list[x].flags &= ~ICA_FLAG_DHW;
			pmech_list[x].property &= ~ICA_PROPERTY_EC_BP;
			pmech_list[x].property &= ~ICA_PROPERTY_EC_ED;
			break;
		default:
			break;
		}
	}
#endif /* ICA_FIPS */

#ifdef NO_CPACF
	pmech_list[x].flags &= ~ICA_FLAG_SHW;
	/* NO_CPACF also removes sw fallbacks for CPACF based functions, but not
	 * for card-based functions and RSA keygen, which is only available in sw. */
	if (pmech_list[x].flags & ICA_FLAG_SW && !(pmech_list[x].flags & ICA_FLAG_DHW) &&
		pmech_list[x].mech_mode_id != RSA_KEY_GEN_ME &&
		pmech_list[x].mech_mode_id != RSA_KEY_GEN_CRT) {
		pmech_list[x].flags &= ~ICA_FLAG_SW;
	}
#endif /* NO_CPACF */

#ifdef NO_SW_FALLBACKS
	/* Set SW flag to 0 if we don't have sw fallbacks, except for RSA keygen,
	 * because there is no hw path for RSA keygen. */
	if (pmech_list[x].mech_mode_id != RSA_KEY_GEN_ME &&
		pmech_list[x].mech_mode_id != RSA_KEY_GEN_CRT)
		pmech_list[x].flags &= ~ICA_FLAG_SW;
#endif /* NO_SW_FALLBACKS */

#ifdef ICA_FIPS
	if (fips & ICA_FIPS_MODE) {
		/* When running in fips mode, finally enable EC keygen via sw only.
		 * This was already set above, but the NO_SW_FALLBACKS block might
		 * have toggled the sw flag off. The property field is already set. */
		if (pmech_list[x].mech_mode_id == EC_KGEN)
			pmech_list[x].flags = ICA_FLAG_SW;
	}
#endif

	/* Finally zeroize properties if no flags set, i.e. function not available */
	if (pmech_list[x].flags == 0)
		pmech_list[x].property = 0;
  }
  return 0;
}

#ifdef ICA_FIPS
int s390_get_fips_indicator(libica_fips_indicator_element *indicator_list,
						unsigned int *indicator_list_len)
{
	size_t i;

	if (!indicator_list_len)
		return EINVAL;

	if (!indicator_list) {
		*indicator_list_len = sizeof(icaList) / sizeof(libica_fips_indicator_element);
		return 0;
	}

	if (*indicator_list_len < (sizeof(icaList) / sizeof(libica_fips_indicator_element)))
		return EINVAL;

	for (i = 0; i < *indicator_list_len; i++) {
		indicator_list[i].mech_mode_id = icaList[i].mech_mode_id;
		indicator_list[i].fips_approved = fips_approved(icaList[i].mech_mode_id);
		indicator_list[i].fips_override = fips_override(icaList[i].mech_mode_id);
	}

	return 0;
}
#endif /* ICA_FIPS */
