/*
 * This program is released under the Common Public License V1.0
 *
 * You should have received a copy of Common Public License V1.0 along with
 * with this program.
 *
 * Author(s): Patrick Steuer <patrick.steuer@de.ibm.com>
 *
 * Copyright IBM Corp. 2015
 */

#ifdef ICA_FIPS

#include <errno.h>
#include <fcntl.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <dlfcn.h>
#include <link.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include <openssl/opensslconf.h>
#ifdef OPENSSL_FIPS
#include <openssl/fips.h>
#endif /* OPENSSL_FIPS */

#include "fips.h"
#include "ica_api.h"
#include "test_vec.h"
#include "s390_crypto.h"

#if OPENSSL_VERSION_PREREQ(3, 0)
#include <openssl/crypto.h>
#include <openssl/provider.h>
extern OSSL_LIB_CTX *openssl_libctx;
extern OSSL_PROVIDER *openssl_provider;
#endif

extern pthread_rwlock_t fips_list_lock;

extern int ica_stats_enabled;

int openssl_in_fips_mode(void)
{
#if !OPENSSL_VERSION_PREREQ(3, 0)
	return FIPS_mode();
#else
	if (fips & ICA_FIPS_INTEGRITY)
		return 0;
	else
		return 1;
#endif
}

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define HMAC_PREFIX "."
#define HMAC_SUFFIX ".hmac"
#define READ_BUFFER_LENGTH 16384

#ifndef ICA_INTERNAL_TEST
/*
 * The hard-coded HMAC key to be optionally provided for the library
 * integrity test. The recommended key size for HMAC-SHA256 is 64 bytes.
 * The known HMAC is supposed to be provided as hex string in a file
 * .libica.so.VERSION.hmac in the same directory as the .so module.
 */
static const char hmackey[] =
	"0000000000000000000000000000000000000000000000000000000000000000"
	"0000000000000000000000000000000000000000000000000000000000000000";

#endif /* ICA_INTERNAL_TEST */

int fips;

#define LIBICA_FIPS_CONFIG		LIBICA_CONFDIR "/libica/openssl3-fips.cnf"

static int drbg_kat(void);
static int aes_ecb_kat(void);
static int aes_cbc_kat(void);
static int aes_cbc_cs_kat(void);
static int aes_cfb_kat(void);
static int aes_ofb_kat(void);
static int aes_ctr_kat(void);
static int aes_ccm_kat(void);
static int aes_gcm_kat(void);
static int aes_xts_kat(void);
static int aes_cmac_kat(void);

static int rsa_kat(void);
static int ecdsa_kat(void);
static int ecdh_kat(void);

static int function_supported_via_cpacf(unsigned int func)
{
	ica_adapter_handle_t ah;
	libica_func_list_element* libica_func_list = NULL;
	unsigned int count;
	size_t i;
	int ret = 0;

	if (ica_open_adapter(&ah))
		return ret;

	if (ica_get_functionlist(NULL, &count) != 0)
		return ret;

	libica_func_list = malloc(sizeof(libica_func_list_element) * count);
	if (!libica_func_list)
		return ret;

	if (ica_get_functionlist(libica_func_list, &count) != 0)
		goto done;

	for (i = 0; i < count; i++) {
		if (libica_func_list[i].mech_mode_id == func &&
			libica_func_list[i].flags == ICA_FLAG_SHW) {
			ret = 1;
			goto done;
		}
	}

done:
	free(libica_func_list);
	ica_close_adapter(ah);
	return ret;
}

#ifndef NO_CPACF
#define SHA_KAT(_sha_, _ctx_)						\
static int sha##_sha_##_kat(void) {					\
	sha##_ctx_##_context_t ctx;					\
	size_t i;							\
	unsigned char out[SHA##_sha_##_HASH_LENGTH];			\
	if (!function_supported_via_cpacf(SHA1))			\
		return 0;										\
	for (i = 0; i < SHA##_sha_##_TV_LEN; i++) {			\
		if (ica_sha##_sha_(SHA_MSG_PART_ONLY,			\
		    SHA##_sha_##_TV[i].msg_len, SHA##_sha_##_TV[i].msg,	\
		    &ctx, out) || memcmp(SHA##_sha_##_TV[i].md, out,	\
		    SHA##_sha_##_HASH_LENGTH)) {			\
			syslog(LOG_ERR, "Libica SHA-%d test failed.",	\
			    _sha_);					\
			return 1;					\
		}							\
	}								\
	return 0;							\
}
SHA_KAT(1, );
SHA_KAT(224, 256);
SHA_KAT(256, 256);
SHA_KAT(384, 512);
SHA_KAT(512, 512);
#undef SHA_KAT
#else /* Don't write any error msg to syslog when CPACF is not avail */
#define SHA_KAT(_sha_, _ctx_)						\
static int sha##_sha_##_kat(void) {					\
	sha##_ctx_##_context_t ctx;					\
	size_t i;							\
	unsigned char out[SHA##_sha_##_HASH_LENGTH];			\
	if (!function_supported_via_cpacf(SHA1))			\
		return 0;										\
	for (i = 0; i < SHA##_sha_##_TV_LEN; i++) {			\
		if (ica_sha##_sha_(SHA_MSG_PART_ONLY,			\
		    SHA##_sha_##_TV[i].msg_len, SHA##_sha_##_TV[i].msg,	\
		    &ctx, out) || memcmp(SHA##_sha_##_TV[i].md, out,	\
		    SHA##_sha_##_HASH_LENGTH)) {			\
			return 1;					\
		}							\
	}								\
	return 0;							\
}
SHA_KAT(1, );
SHA_KAT(224, 256);
SHA_KAT(256, 256);
SHA_KAT(384, 512);
SHA_KAT(512, 512);
#undef SHA_KAT
#endif

static inline int sha3_available(void)
{
	sha3_224_context_t sha3_224_context;
	unsigned char output_hash[SHA3_224_HASH_LENGTH];
	unsigned char test_data[] = { 0x61,0x62,0x63 };
	int rc = 0;

	rc = ica_sha3_224(SHA_MSG_PART_ONLY, sizeof(test_data), test_data,
			&sha3_224_context, output_hash);

	return (rc != 0 ? 0 : 1);
}

#ifndef NO_CPACF
#define SHA3_KAT(_sha_, _ctx_)						\
static int sha3_##_sha_##_kat(void) {					\
	sha3_##_ctx_##_context_t ctx;					\
	size_t i;							\
	unsigned char out[SHA3_##_sha_##_HASH_LENGTH];			\
	if (!sha3_available()) 						\
		return 0; 						\
	for (i = 0; i < SHA3_##_sha_##_TV_LEN; i++) {			\
		if (ica_sha3_##_sha_(SHA_MSG_PART_ONLY,			\
		    SHA3_##_sha_##_TV[i].msg_len, SHA3_##_sha_##_TV[i].msg,	\
		    &ctx, out) || memcmp(SHA3_##_sha_##_TV[i].md, out,	\
		    SHA3_##_sha_##_HASH_LENGTH)) {			\
			syslog(LOG_ERR, "Libica SHA-3 %d test failed.",	\
			    _sha_);					\
			return 1;					\
		}							\
	}								\
	return 0;							\
}
SHA3_KAT(224, 224);
SHA3_KAT(256, 256);
SHA3_KAT(384, 384);
SHA3_KAT(512, 512);
#undef SHA3_KAT
#else /* Don't write any error msg to syslog when CPACF is not avail */
#define SHA3_KAT(_sha_, _ctx_)						\
static int sha3_##_sha_##_kat(void) {					\
	sha3_##_ctx_##_context_t ctx;					\
	size_t i;							\
	unsigned char out[SHA3_##_sha_##_HASH_LENGTH];			\
	if (!sha3_available()) 						\
		return 0; 						\
	for (i = 0; i < SHA3_##_sha_##_TV_LEN; i++) {			\
		if (ica_sha3_##_sha_(SHA_MSG_PART_ONLY,			\
		    SHA3_##_sha_##_TV[i].msg_len, SHA3_##_sha_##_TV[i].msg,	\
		    &ctx, out) || memcmp(SHA3_##_sha_##_TV[i].md, out,	\
		    SHA3_##_sha_##_HASH_LENGTH)) {			\
			return 1;					\
		}							\
	}								\
	return 0;							\
}
SHA3_KAT(224, 224);
SHA3_KAT(256, 256);
SHA3_KAT(384, 384);
SHA3_KAT(512, 512);
#undef SHA3_KAT
#endif

void
fips_get_indicator(void)
{
	FILE *fd;
	char fips_flag;
	char *fips_override;

	if ((fd = fopen(FIPS_FLAG, "r")) == NULL)
		return;

	if (fread(&fips_flag, sizeof(fips_flag), 1, fd) != 1) {
		fclose(fd);
		return;
	}
	fclose(fd);

	/* Allow to override the kernel fips indication for testing on
	 * non-fips systems. */
	fips_override = getenv("LIBICA_FIPS_FLAG");
	if ((fips_override != NULL) && (atoi(fips_override) == 1))
		fips_flag = '1';

	if (fips_flag - '0') {
		/* Set libica into FIPS mode. */
		fips |= ICA_FIPS_MODE;
	}
}

void
fips_init(void)
{
	if (fips & ICA_FIPS_MODE) {
#if !OPENSSL_VERSION_PREREQ(3, 0)
		/* Try to set OpenSSL into FIPS mode. If this is not possible,
		 * all software fallbacks (including RSA key generation) will
		 * be disabled. OpenSSL FIPS mode can be queried using the
		 * FIPS_mode() function. */
		FIPS_mode_set(1);
#else
#ifndef NO_FIPS_CONFIG_LOAD
		/* Allow to skip reading the openssl 3.x fips config. Tests showed
		 * that this step must be skipped on RHEL9 systems. But on other
		 * systems, or with a locally built openssl, this step is necessary. */
		if (!OSSL_LIB_CTX_load_config(openssl_libctx, LIBICA_FIPS_CONFIG)) {
			syslog(LOG_ERR, "Libica failed to load openssl fips config %s\n",
					LIBICA_FIPS_CONFIG);
			fips = ICA_FIPS_INTEGRITY;
			return;
		}
#endif

		openssl_provider = OSSL_PROVIDER_load(openssl_libctx, "fips");
		if (openssl_provider == NULL) {
			syslog(LOG_ERR, "Libica failed to load fips provider.\n");
			fips = ICA_FIPS_INTEGRITY;
			return;
		}

		if (!EVP_set_default_properties(openssl_libctx, "fips=yes")) {
			syslog(LOG_ERR, "Libica failed to set default properties 'fips=yes'\n");
			fips = ICA_FIPS_INTEGRITY;
			return;
		}
#endif
	} else {
		/* kernel fips flag == 0, load default provider in case we are
		 * running with openssl 3.0 */
#if OPENSSL_VERSION_PREREQ(3, 0)
		openssl_provider = OSSL_PROVIDER_load(openssl_libctx, "default");
		if (openssl_provider == NULL) {
			syslog(LOG_ERR, "Libica: failed to load default provider\n");
			fips |= ICA_FIPS_INTEGRITY;
			return;
		}
#endif
	}
}

#ifndef ICA_INTERNAL_TEST

static char *make_hmac_path(const char *origpath)
{
	char *path;
	const char *fn;

	path = calloc(1, sizeof(HMAC_PREFIX) + sizeof(HMAC_SUFFIX) + strlen(origpath) + 1);
	if (path == NULL)
		return NULL;

	fn = strrchr(origpath, '/');
	if (fn == NULL) {
		fn = origpath;
	} else {
		++fn;
	}

	strncpy(path, origpath, fn - origpath);
	strcat(path, HMAC_PREFIX);
	strcat(path, fn);
	strcat(path, HMAC_SUFFIX);

	return path;
}

static EVP_PKEY *get_pkey(void)
{
	unsigned char *keybuf;
	long keylen;
	EVP_PKEY *pkey = NULL;

	keybuf = OPENSSL_hexstr2buf(hmackey, &keylen);
	if (keybuf == NULL)
		goto end;

	pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, keybuf, (int)keylen);
end:
	if (keybuf) {
		OPENSSL_cleanse(keybuf, keylen);
		OPENSSL_free(keybuf);
	}
	return pkey;
}

static void* mmap_file(const char *path, struct stat *statbuf)
{
	int fd;
	void *ptr = NULL;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		goto end;

	if (fstat(fd, statbuf) < 0)
		goto end_close;

	ptr = mmap(0, statbuf->st_size, PROT_READ, MAP_SHARED, fd, 0);
	if (ptr == MAP_FAILED)
		ptr = NULL;
end_close:
	close(fd);
end:
	return ptr;
}

static int compute_file_hmac(const char *path, void **buf, size_t *hmaclen)
{
	int rc = -1;
	unsigned char tmp[32];
	size_t tmp_len = sizeof(tmp);
	EVP_MD_CTX *mdctx = NULL;
	EVP_PKEY *pkey = NULL;
	void *fdata = NULL;
	struct stat fdata_stat;

	BEGIN_OPENSSL_LIBCTX(openssl_libctx, rc);

	pkey = get_pkey();
	if (!pkey)
		goto end;

	mdctx = EVP_MD_CTX_create();
	if (!mdctx)
		goto end;

	fdata = mmap_file(path, &fdata_stat);
	if (fdata == NULL)
		goto end;

	if (EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, pkey) != 1)
		goto end;

	if (EVP_DigestSign(mdctx, tmp, &tmp_len, fdata, fdata_stat.st_size) != 1)
		goto end;

	*buf = malloc(tmp_len);
	if (*buf == NULL)
		goto end;

	*hmaclen = tmp_len;
	memcpy(*buf, tmp, tmp_len);

	rc = 0;

end:
	if (fdata != NULL)
		munmap(fdata, fdata_stat.st_size);

	if (pkey != NULL)
		EVP_PKEY_free(pkey);

	if (mdctx != NULL)
		EVP_MD_CTX_destroy(mdctx);

	OPENSSL_cleanse(tmp, sizeof(tmp));
	END_OPENSSL_LIBCTX(rc);

	return rc;
}

static int load_known_hmac(const char *path, unsigned char **hmac, long *hmaclen)
{
	int rc = -1;
	FILE *fp = NULL;
	char *known_hmac_str = NULL;
	char *hmacpath, *p;
	size_t n;

	hmacpath = make_hmac_path(path);
	if (hmacpath == NULL)
		return rc;

	if ((fp = fopen(hmacpath, "r")) == NULL)
		goto end;

	if (getline(&known_hmac_str, &n, fp) <= 0)
		goto end;

	if ((p = strchr(known_hmac_str, '\n')) != NULL)
		*p = '\0';

	*hmac = OPENSSL_hexstr2buf(known_hmac_str, hmaclen);
	rc = 0;
end:
	if (fp != NULL)
		fclose(fp);
	if (known_hmac_str)
		OPENSSL_cleanse(known_hmac_str, strlen(known_hmac_str));
	free(known_hmac_str);
	free(hmacpath);

	return rc;
}

/**
 * Performs the FIPS check.
 *
 * @return  1 if check succeeded
 *          0 otherwise
 */
static int FIPSCHECK_verify(const char *path)
{
	int rc = 0;
	unsigned char *known_hmac = NULL;
	long known_hmac_len = 0;
	void *computed_hmac = NULL;
	size_t computed_hmac_len = 0;

	if (load_known_hmac(path, &known_hmac,  &known_hmac_len) != 0)
		goto end;

	if (compute_file_hmac(path, &computed_hmac, &computed_hmac_len) != 0)
		goto end;

	if ((size_t)known_hmac_len != computed_hmac_len)
		goto end;

	if (memcmp(computed_hmac, known_hmac, computed_hmac_len) != 0)
		goto end;

	rc = 1;
end:
	if (computed_hmac)
		OPENSSL_cleanse(computed_hmac, computed_hmac_len);
	if (known_hmac)
		OPENSSL_cleanse(known_hmac, known_hmac_len);
	free(computed_hmac);
	OPENSSL_free(known_hmac);

	return rc;
}

static const char msg1[] = "Libica FIPS library integrity check failed. Cannot determine library path.\n";
static const char msg2[] = "Libica FIPS library integrity check failed. Module %s probably corrupted.\n";

struct phdr_cb_data {
	/* User-provided storage for library path. */
	char *librarypath;
	/* Length of storage provided by user. */
	size_t length;
	/* How many times did we find a proper library. This is used
	 * as a sanity check. */
	int count;
};

static int phdr_callback(struct dl_phdr_info *info, size_t size, void *data)
{
	int j;
	unsigned long start, end;
	struct phdr_cb_data *d = data;
	unsigned long myaddr = (unsigned long)&phdr_callback;

	(void)size;
	for (j = 0; j < info->dlpi_phnum; j++) {
		// Only consider loadable program segments
		if (info->dlpi_phdr[j].p_type == PT_LOAD) {
			start = info->dlpi_addr + info->dlpi_phdr[j].p_vaddr;
			end = start + info->dlpi_phdr[j].p_memsz;
			if (start <= myaddr && myaddr < end) {
				if (d->librarypath[0] == 0
					&& strlen(info->dlpi_name) < d->length) {
					strcpy(d->librarypath, info->dlpi_name);
				}
				d->count++;
			}
		}
	}
	return 0;
}

/*
 * Perform an integrity check on libica.so by calculating an HMAC from
 * the file contents using a static HMAC key, and comparing it to a
 * pre-calculated HMAC in a separate file. The HMAC key and HMAC file
 * may be provided by a Distributor when building the packet.
 */
static void fips_lib_integrity_check(void)
{
	char path[PATH_MAX];
	struct phdr_cb_data data = {
		.librarypath = (char *)path,
		.length = sizeof(path),
		.count = 0
	};

	path[0] = 0;
	dl_iterate_phdr(phdr_callback, &data);
	if (data.count != 1) {
		syslog(LOG_ERR, msg1);
		fips |= ICA_FIPS_INTEGRITY;
		return;
	}

	if (!FIPSCHECK_verify(path)) {
		syslog(LOG_ERR, msg2, path);
		fips |= ICA_FIPS_INTEGRITY;
		return;
	}
}
#endif /* ICA_INTERNAL_TEST */

void
fips_powerup_tests(void)
{
	typedef int (*kat_func)(void);
	kat_func kats[] = {
		drbg_kat, sha1_kat, sha224_kat, sha256_kat, sha384_kat, sha512_kat,
		sha3_224_kat, sha3_256_kat, sha3_384_kat, sha3_512_kat, aes_ecb_kat,
		aes_cbc_kat, aes_cbc_cs_kat, aes_cfb_kat, aes_ctr_kat, aes_ofb_kat,
		aes_ccm_kat, aes_gcm_kat, aes_xts_kat, aes_cmac_kat, rsa_kat,
		ecdsa_kat, ecdh_kat,
	};
	size_t i, num_kats = sizeof(kats) / sizeof(kat_func);
	int stats_mode_temp = ica_stats_enabled;

	ica_stats_enabled = 0;

	for (i = 0; i < num_kats; i++) {
		if (kats[i]() != 0) {
			fips |= ICA_FIPS_CRYPTOALG;
			ica_stats_enabled = stats_mode_temp;
			return;
		}
	}

	ica_stats_enabled = stats_mode_temp;

/* ICA internal test does not link against the library. So we should
 * skip the library integrity check in that case.
 */
#ifndef ICA_INTERNAL_TEST
	/* Library integrity test */
	fips_lib_integrity_check();
#endif
}

static int drbg_kat(void)
{
	if (!function_supported_via_cpacf(SHA512_DRNG))
		return 0;

	return ica_drbg_health_test(ica_drbg_generate, 256, true, ICA_DRBG_SHA512);
}

static int
aes_ecb_kat(void) {
	const struct aes_ecb_tv *tv;
	size_t i;
	unsigned char *out;

	if (!function_supported_via_cpacf(AES_ECB))
		return 0;

	for (i = 0; i < AES_ECB_TV_LEN; i++) {
		tv = &AES_ECB_TV[i];

		out = malloc(tv->len);

		if (out == NULL)
			goto _err_;

		if (ica_aes_ecb(tv->plaintext, out, tv->len, tv->key,
		    tv->keylen, ICA_ENCRYPT) || memcmp(tv->ciphertext, out,
		    tv->len) || ica_aes_ecb(tv->ciphertext, out, tv->len,
		    tv->key, tv->keylen, ICA_DECRYPT) || memcmp(tv->plaintext,
		    out, tv->len))
			goto _err_;

		free(out);
	}
	return 0;

_err_:
	free(out);
#ifndef NO_CPACF
	syslog(LOG_ERR, "Libica AES-ECB test failed.");
#endif
	return 1;
}

static int
aes_cbc_kat(void) {
	const struct aes_cbc_tv *tv;
	size_t i;
	unsigned char iv[AES_BLKSIZE], *out;

	if (!function_supported_via_cpacf(AES_CBC))
		return 0;

	for (i = 0; i < AES_CBC_TV_LEN; i++) {
		tv = &AES_CBC_TV[i];

		out = malloc(tv->len);

		if (out == NULL)
			goto _err_;

		memcpy(iv, tv->iv, AES_BLKSIZE);
		if (ica_aes_cbc(tv->plaintext, out, tv->len, tv->key,
		    tv->keylen, iv, ICA_ENCRYPT) || memcmp(tv->ciphertext, out,
		    tv->len))
			goto _err_;

		memcpy(iv, AES_CBC_TV[i].iv, AES_BLKSIZE);
		if (ica_aes_cbc(tv->ciphertext, out, tv->len, tv->key,
		    tv->keylen, iv, ICA_DECRYPT) || memcmp(tv->plaintext, out,
		    tv->len))
			goto _err_;

		free(out);
	}
	return 0;

_err_:
	free(out);
#ifndef NO_CPACF
	syslog(LOG_ERR, "Libica AES-CBC test failed.");
#endif
	return 1;
}

static int
aes_cbc_cs_kat(void)
{
	const struct aes_cbc_cs_tv *tv;
	size_t i;
	unsigned char iv[AES_BLKSIZE], *out;

	if (!function_supported_via_cpacf(AES_CBC_CS))
		return 0;

	for (i = 0; i < AES_CBC_CS_TV_LEN; i++) {
		tv = &AES_CBC_CS_TV[i];

		out = malloc(tv->len);

		if (out == NULL)
			goto _err_;

		memcpy(iv, tv->iv, AES_BLKSIZE);
		if (ica_aes_cbc_cs(tv->plaintext, out, tv->len, tv->key,
		    tv->keylen, iv, ICA_ENCRYPT, tv->variant)
		    || memcmp(tv->ciphertext, out, tv->len)
		    || memcmp(tv->iv_out, iv, AES_BLKSIZE))
			goto _err_;

		memcpy(iv, AES_CBC_CS_TV[i].iv, AES_BLKSIZE);
		if (ica_aes_cbc_cs(tv->ciphertext, out, tv->len, tv->key,
		    tv->keylen, iv, ICA_DECRYPT, tv->variant)
		    || memcmp(tv->plaintext, out, tv->len))
			goto _err_;

		free(out);
	}
	return 0;

_err_:
	free(out);
#ifndef NO_CPACF
	syslog(LOG_ERR, "Libica AES-CBC-CS test failed.");
#endif
	return 1;
}

static int
aes_cfb_kat(void) {
	const struct aes_cfb_tv *tv;
	size_t i;
	unsigned char iv[AES_BLKSIZE], *out;

	if (!function_supported_via_cpacf(AES_CFB))
		return 0;

	for (i = 0; i < AES_CFB_TV_LEN; i++) {
		tv = &AES_CFB_TV[i];

		out = malloc(tv->len);

		if (out == NULL)
			goto _err_;

		memcpy(iv, tv->iv, AES_BLKSIZE);
		if (ica_aes_cfb(tv->plaintext, out, tv->len, tv->key,
		    tv->keylen, iv, tv->lcfb, ICA_ENCRYPT)
		    || memcmp(tv->ciphertext, out, tv->len))
			goto _err_;

		memcpy(iv, tv->iv, AES_BLKSIZE);
		if (ica_aes_cfb(tv->ciphertext, out, tv->len, tv->key,
		    tv->keylen, iv, tv->lcfb, ICA_DECRYPT)
		    || memcmp(tv->plaintext, out, tv->len))
			goto _err_;

		free(out);
	}
	return 0;

_err_:
	free(out);
#ifndef NO_CPACF
	syslog(LOG_ERR, "Libica AES-CFB test failed.");
#endif
	return 1;
}

static int
aes_ofb_kat(void) {
	const struct aes_ofb_tv *tv;
	size_t i;
	unsigned char iv[AES_BLKSIZE], *out;

	if (!function_supported_via_cpacf(AES_OFB))
		return 0;

	for (i = 0; i < AES_OFB_TV_LEN; i++) {
		tv = &AES_OFB_TV[i];

		out = malloc(tv->len);

		if (out == NULL)
			goto _err_;

		memcpy(iv, tv->iv, AES_BLKSIZE);
		if (ica_aes_ofb(tv->plaintext, out, tv->len, tv->key,
		    tv->keylen, iv, ICA_ENCRYPT) || memcmp(tv->ciphertext, out,
		    tv->len))
			goto _err_;

		memcpy(iv, tv->iv, AES_BLKSIZE);
		if (ica_aes_ofb(tv->ciphertext, out, tv->len, tv->key,
		    tv->keylen, iv, ICA_DECRYPT) || memcmp(tv->plaintext, out,
		    tv->len))
			goto _err_;

		free(out);
	}
	return 0;

_err_:
	free(out);
#ifndef NO_CPACF
	syslog(LOG_ERR, "Libica AES-OFB test failed.");
#endif
	return 1;
}

static int
aes_ctr_kat(void) {
	const struct aes_ctr_tv *tv;
	size_t i;
	unsigned char *out, ctr[AES_BLKSIZE];

	if (!function_supported_via_cpacf(AES_CTR))
		return 0;

	for (i = 0; i < AES_CTR_TV_LEN; i++) {
		tv = &AES_CTR_TV[i];

		out = malloc(tv->len);

		if (out == NULL)
			goto _err_;

		memcpy(ctr, tv->ctr, AES_BLKSIZE);
		if (ica_aes_ctr(tv->plaintext, out, tv->len, tv->key,
		    tv->keylen, ctr, 32, ICA_ENCRYPT) || memcmp(tv->ciphertext,
		    out, tv->len))
			goto _err_;

		memcpy(ctr, tv->ctr, AES_BLKSIZE);
		if (ica_aes_ctr(tv->ciphertext, out, tv->len, tv->key,
		    tv->keylen, ctr, 32, ICA_DECRYPT) || memcmp(tv->plaintext,
		    out, tv->len))
			goto _err_;

		free(out);
	}
	return 0;

_err_:
	free(out);
#ifndef NO_CPACF
	syslog(LOG_ERR, "Libica AES-CTR test failed.");
#endif
	return 1;
}

static int
aes_ccm_kat(void) {
	const struct aes_ccm_tv *tv;
	size_t i;
	unsigned char *ciphertext, *payload;

	if (!function_supported_via_cpacf(AES_CCM))
		return 0;

	for (i = 0; i < AES_CCM_TV_LEN; i++) {
		tv = &AES_CCM_TV[i];

		ciphertext = malloc(tv->payloadlen + tv->taglen);
		payload = malloc(tv->payloadlen);

		if (payload == NULL || ciphertext == NULL)
			goto _err_;

		if (ica_aes_ccm(payload, tv->payloadlen, tv->ciphertext,
		    tv->taglen, tv->adata, tv->adatalen, tv->nonce,
		    tv->noncelen, tv->key, tv->keylen, ICA_DECRYPT)
		    != tv->rv)
			goto _err_;

		if ((tv->rv == 0) && (memcmp(tv->payload, payload,
		    tv->payloadlen) || ica_aes_ccm(tv->payload, tv->payloadlen,
		    ciphertext, tv->taglen, tv->adata, tv->adatalen, tv->nonce,
		    tv->noncelen, tv->key, tv->keylen, ICA_ENCRYPT)
		    || memcmp(tv->ciphertext, ciphertext, tv->payloadlen
		    + tv->taglen)))
			goto _err_;

		free(payload);
		free(ciphertext);
	}
	return 0;

_err_:
	free(ciphertext);
	free(payload);
#ifndef NO_CPACF
	syslog(LOG_ERR, "Libica AES-CCM test failed.");
#endif
	return 1;
}

static int
aes_gcm_kat(void) {
	const struct aes_gcm_tv *tv;
	size_t i, lastlen;
	unsigned char *out, *tag, icb[AES_BLKSIZE], ucb[AES_BLKSIZE],
	    subkey[AES_BLKSIZE];

	if (!function_supported_via_cpacf(AES_GCM))
		return 0;

	for (i = 0; i < AES_GCM_TV_LEN; i++) {
		tv = &AES_GCM_TV[i];

		out = malloc(tv->len);
		tag = malloc(tv->taglen);

		if (tag == NULL || out == NULL)
			goto _err_;

		if ((ica_aes_gcm_internal(out, tv->len, tv->ciphertext, tv->iv,
		    tv->ivlen, tv->aad, tv->aadlen, tv->tag, tv->taglen,
		    tv->key, tv->keylen, ICA_DECRYPT) != tv->rv)
		    || ((tv->rv == 0)
		    && memcmp(tv->plaintext, out, tv->len)))
			goto _err_;

		if ((tv->rv == 0) && (ica_aes_gcm_internal(tv->plaintext, tv->len,
		    out, tv->iv, tv->ivlen, tv->aad, tv->aadlen, tag,
		    tv->taglen, tv->key, tv->keylen, ICA_ENCRYPT)
		    || memcmp(tv->tag, tag, tv->taglen)
		    || memcmp(tv->ciphertext, out, tv->len)))
			goto _err_;

		free(tag);
		free(out);
	}

	for (i = 0; i < AES_GCM_TV_LEN; i++) {
		tv = &AES_GCM_TV[i];

		/* Divide the test vector into two chunks. */
		if (tv->len  <= AES_BLKSIZE)
			lastlen = 0;
		else {
			lastlen = tv->len % AES_BLKSIZE;
			/* Last chunk can only be 16 bytes long, if test
			 * vector is at least 32 bytes long. */
			if (lastlen == 0 && tv->len >= 2 * AES_BLKSIZE)
				lastlen = AES_BLKSIZE;
		}

		out = malloc(tv->len);
		tag = malloc(AES_BLKSIZE);

		if (tag == NULL || out == NULL)
			goto _err_;

		memset(tag, 0, AES_BLKSIZE);
		if (ica_aes_gcm_initialize_internal(tv->iv, tv->ivlen, tv->key,
		    tv->keylen, icb, ucb, subkey, ICA_DECRYPT)
		    || ica_aes_gcm_intermediate(out, tv->len - lastlen,
		    tv->ciphertext, ucb, tv->aad, tv->aadlen, tag,
		    tv->taglen, tv->key, tv->keylen, subkey, ICA_DECRYPT)
		    || ica_aes_gcm_intermediate(out + (tv->len - lastlen),
		    lastlen, tv->ciphertext + (tv->len - lastlen), ucb,
		    NULL, 0, tag, tv->taglen, tv->key, tv->keylen,
		    subkey, ICA_DECRYPT) || (ica_aes_gcm_last(icb, tv->aadlen,
		    tv->len, tag, tv->tag, tv->taglen, tv->key, tv->keylen,
		    subkey, ICA_DECRYPT) != tv->rv) || ((tv->rv == 0)
		    && memcmp(tv->plaintext, out, tv->len)))
			goto _err_;

		memset(tag, 0, AES_BLKSIZE);
		memset(out, 0, tv->len);
		memset(icb, 0, sizeof(icb));
		memset(ucb, 0, sizeof(ucb));
		memset(subkey, 0, sizeof(subkey));
		ica_allow_external_gcm_iv_in_fips_mode(1);
		if ((tv->rv == 0) && (ica_aes_gcm_initialize_internal(tv->iv, tv->ivlen,
		    tv->key, tv->keylen, icb, ucb, subkey, ICA_ENCRYPT)
		    || ica_aes_gcm_intermediate(tv->plaintext,
		    tv->len - lastlen, out, ucb, tv->aad, tv->aadlen, tag,
		    tv->taglen, tv->key, tv->keylen, subkey, ICA_ENCRYPT)
		    || ica_aes_gcm_intermediate(tv->plaintext
		    + (tv->len - lastlen), lastlen, out + (tv->len - lastlen),
		    ucb, NULL, 0, tag, tv->taglen, tv->key, tv->keylen, subkey,
		    ICA_ENCRYPT) || ica_aes_gcm_last(icb, tv->aadlen, tv->len,
		    tag, NULL, tv->taglen, tv->key, tv->keylen, subkey,
		    ICA_ENCRYPT) || memcmp(tv->ciphertext, out, tv->len)
		    || memcmp(tv->tag, tag, tv->taglen)))
			goto _err_;
		ica_allow_external_gcm_iv_in_fips_mode(0);

		free(tag);
		free(out);
	}
	return 0;

_err_:
	ica_allow_external_gcm_iv_in_fips_mode(0);
	free(tag);
	free(out);
#ifndef NO_CPACF
	syslog(LOG_ERR, "Libica AES-GCM test failed.");
#endif
	return 1;
}

static int
aes_xts_kat(void) {
	const struct aes_xts_tv *tv;
	size_t i;
	unsigned char *out, tweak[16];

	if (!function_supported_via_cpacf(AES_XTS))
		return 0;

	for (i = 0; i < AES_XTS_TV_LEN; i++) {
		tv = &AES_XTS_TV[i];

		out = malloc(tv->len);

		if (out == NULL)
			goto _err_;

		memcpy(tweak, tv->tweak, sizeof(tweak));
		if (ica_aes_xts(tv->plaintext, out, tv->len, tv->key1,
		    tv->key2, tv->keylen, tweak, ICA_ENCRYPT)
		    || memcmp(tv->ciphertext, out, tv->len))
			goto _err_;

		memcpy(tweak, tv->tweak, sizeof(tweak));
		if (ica_aes_xts(tv->ciphertext, out, tv->len, tv->key1,
		    tv->key2, tv->keylen, tweak, ICA_DECRYPT)
		    || memcmp(tv->plaintext, out, tv->len))
			goto _err_;

		free(out);
	}
	return 0;

_err_:
	free(out);
#ifndef NO_CPACF
	syslog(LOG_ERR, "Libica AES-XTS test failed.");
#endif
	return 1;
}

static int
aes_cmac_kat(void)
{
	const struct aes_cmac_tv *tv;
	size_t i, lastlen;
	unsigned char *mac, iv[AES_BLKSIZE];

	if (!function_supported_via_cpacf(AES_CMAC))
		return 0;

	for (i = 0; i < AES_CMAC_TV_LEN; i++) {
		tv = &AES_CMAC_TV[i];

		mac = malloc(tv->maclen);

		if (mac == NULL)
			goto _err_;

		if ((ica_aes_cmac(tv->msg, tv->msglen, tv->mac, tv->maclen,
		    tv->key, tv->keylen, ICA_DECRYPT) != tv->rv)
		    || ((tv->rv == 0) && (ica_aes_cmac(tv->msg, tv->msglen,
		    mac, tv->maclen, tv->key, tv->keylen, ICA_ENCRYPT)
		    || memcmp(tv->mac, mac, tv->maclen))))
			goto _err_;

		free(mac);
	}

	for (i = 0; i < AES_CMAC_TV_LEN; i++) {
		tv = &AES_CMAC_TV[i];

		if (tv->msglen <= AES_BLKSIZE)
			continue;

		lastlen = tv->msglen % AES_BLKSIZE ? tv->msglen % AES_BLKSIZE
		    : AES_BLKSIZE;
		memset(iv, 0, AES_BLKSIZE);

		if (ica_aes_cmac_intermediate(tv->msg, tv->msglen - lastlen,
		    tv->key, tv->keylen, iv) || (ica_aes_cmac_last(tv->msg
		    + (tv->msglen - lastlen), lastlen, tv->mac, tv->maclen,
		    tv->key, tv->keylen, iv, ICA_DECRYPT) != tv->rv))
			return 1;

		if (tv->rv != 0)
			continue;

		mac = malloc(tv->maclen);

		if (mac == NULL)
			goto _err_;

		memset(iv, 0, AES_BLKSIZE);
		if (ica_aes_cmac_intermediate(tv->msg, tv->msglen - lastlen,
		    tv->key, tv->keylen, iv) || ica_aes_cmac_last(tv->msg
		    + (tv->msglen - lastlen), lastlen, mac, tv->maclen,
		    tv->key, tv->keylen, iv, ICA_ENCRYPT) || memcmp(tv->mac,
		    mac, tv->maclen))
			goto _err_;

		free(mac);
	}
	return 0;

_err_:
	free(mac);
#ifndef NO_CPACF
	syslog(LOG_ERR, "Libica AES-CMAC test failed.");
#endif
	return 1;
}

static int
ecdh_kat()
{
	ica_adapter_handle_t ah;
	const struct ecdh_kat_tv *tv;
	unsigned char shared_secret[MAX_ECC_PRIV_SIZE];
	ICA_EC_KEY *eckey_A, *eckey_B;
	unsigned int privlen;
	size_t i;

	if (!function_supported_via_cpacf(EC_DH))
		return 0;

	if (ica_open_adapter(&ah))
		return 1;

	for (i = 0; i < ECDH_KAT_TV_LEN; i++) {

		tv = &ECDH_KAT_TV[i];

		eckey_A = ica_ec_key_new(tv->nid, &privlen);
		eckey_B = ica_ec_key_new(tv->nid, &privlen);
		if (!eckey_A || !eckey_B)
			goto _err_;

		/* calculate shared secret with pub_B, priv_A */
		if (ica_ec_key_init(NULL, NULL, tv->da, eckey_A))
			goto _err_;

		if (ica_ec_key_init(tv->xb, tv->yb, NULL, eckey_B))
			goto _err_;

		memset(shared_secret, 0, sizeof(shared_secret));
		if (ica_ecdh_derive_secret(ah, eckey_A, eckey_B, shared_secret, privlen))
			goto _err_;

		/* compare result with known result */
		if (memcmp(shared_secret, tv->z, tv->privlen) != 0)
			goto _err_;

		ica_ec_key_free(eckey_A);
		ica_ec_key_free(eckey_B);

		eckey_A = ica_ec_key_new(tv->nid, &privlen);
		eckey_B = ica_ec_key_new(tv->nid, &privlen);
		if (!eckey_A || !eckey_B)
			goto _err_;

		/* calculate shared secret with pub_A, priv_B */
		if (ica_ec_key_init(NULL, NULL, tv->db, eckey_B))
			goto _err_;

		if (ica_ec_key_init(tv->xa, tv->ya, NULL, eckey_A))
			goto _err_;

		memset(shared_secret, 0, sizeof(shared_secret));
		if (ica_ecdh_derive_secret(ah, eckey_B, eckey_A, shared_secret, privlen))
			goto _err_;

		/* compare result with known result */
		if (memcmp(shared_secret, tv->z, tv->privlen) != 0)
			goto _err_;

		ica_ec_key_free(eckey_A);
		ica_ec_key_free(eckey_B);
	}

	ica_close_adapter(ah);
	return 0;

_err_:
	ica_ec_key_free(eckey_A);
	ica_ec_key_free(eckey_B);
	ica_close_adapter(ah);
	syslog(LOG_ERR, "Libica ECDH test failed.");
	return 1;
}

static int
ecdsa_kat(void)
{
	ICA_EC_KEY *eckey;
	const struct ecdsa_kat_tv *tv;
	unsigned char sigbuf[MAX_ECDSA_SIG_SIZE];
	unsigned int privlen;
	size_t i;
	int rc;

	if (!function_supported_via_cpacf(EC_DSA_SIGN))
		return 0;

	for (i = 0; i < ECDSA_KAT_TV_LEN; i++) {
		tv = &ECDSA_KAT_TV[i];
		eckey = ica_ec_key_new(tv->nid, &privlen);
		if (!eckey)
			goto _err_;
		rc = ica_ec_key_init(tv->x, tv->y, tv->d, eckey);
		if (rc)
			goto _err_;
		/* adapter handle not needed here, just CPACF */
		rc = ica_ecdsa_sign_ex_internal(0, eckey, tv->hash, tv->hashlen,
								sigbuf, tv->siglen, tv->k);
		if (rc)
			goto _err_;
		if (memcmp(sigbuf, tv->sig, tv->siglen) != 0) {
			goto _err_;
		}
		ica_ec_key_free(eckey);
	}

	return 0;

_err_:
	ica_ec_key_free(eckey);
	syslog(LOG_ERR, "Libica ECDSA test failed.");
	return 1;
}

static int
rsa_kat(void)
{
	ica_rsa_key_mod_expo_t pubkey = { 0 };
	ica_rsa_key_crt_t privkey = { 0 };
	ica_adapter_handle_t ah = DRIVER_NOT_LOADED;
	const struct rsa_tv *tv;
	size_t i, keylen, crtparamlen;
	unsigned char *out = NULL;
	libica_func_list_element* libica_func_list = NULL;
	unsigned int count;

	if (ica_open_adapter(&ah))
		return 1;

	if (ica_get_functionlist(NULL, &count) != 0)
		goto _err_;

	libica_func_list = malloc(sizeof(libica_func_list_element) * count);
	if (!libica_func_list)
		goto _err_;

	if (ica_get_functionlist(libica_func_list, &count) != 0)
		goto _err_;

	for (i = 0; i < count; i++) {
		if (libica_func_list[i].mech_mode_id == RSA_CRT &&
			libica_func_list[i].flags == 0) {
			/* RSA_CRT, and probably also RSA_ME, not available, skip test.
			 * Looks like we don't have cards nor sw fallbacks. */
			free(libica_func_list);
			ica_close_adapter(ah);
			return 0;
		}
	}

	for (i = 0; i < RSA_TV_LEN; i++) {
		tv = &RSA_TV[i];

		keylen = (tv->mod + 7) / 8;
		crtparamlen = (keylen + 1) / 2;

		pubkey.key_length = keylen;
		privkey.key_length = keylen;

		out = malloc(keylen);
		pubkey.exponent = malloc(keylen);
		pubkey.modulus = malloc(keylen);
		privkey.q = malloc(crtparamlen);
		privkey.dq = malloc(crtparamlen);
		/* Some values have 8 bytes of zero padding. */
		privkey.p = malloc(crtparamlen + 8);
		privkey.dp = malloc(crtparamlen + 8);
		privkey.qInverse = malloc(crtparamlen + 8);

		if (privkey.qInverse == NULL || privkey.dq == NULL
		    || privkey.dp == NULL || privkey.q == NULL
		    || privkey.p == NULL || pubkey.modulus == NULL
		    || pubkey.exponent == NULL || out == NULL)
			goto _err_;

		memcpy(pubkey.exponent, tv->e, keylen);
		memcpy(pubkey.modulus, tv->n, keylen);
		memcpy(privkey.q, tv->q, crtparamlen);
		memcpy(privkey.dq, tv->dq, crtparamlen);
		memcpy(privkey.p, tv->p, crtparamlen + 8);
		memcpy(privkey.dp, tv->dp, crtparamlen + 8);
		memcpy(privkey.qInverse, tv->qinv, crtparamlen + 8);

		if (ica_rsa_mod_expo(ah, tv->plaintext, &pubkey, out)
		    || memcmp(tv->ciphertext, out, keylen)
		    || ica_rsa_crt(ah, tv->ciphertext, &privkey, out)
		    || memcmp(tv->plaintext, out, keylen))
			goto _err_;

		free(out);
		free(pubkey.exponent);
		free(pubkey.modulus);
		free(privkey.p);
		free(privkey.q);
		free(privkey.dp);
		free(privkey.dq);
		free(privkey.qInverse);
	}
	free(libica_func_list);
	ica_close_adapter(ah);
	return 0;

_err_:
	free(libica_func_list);
	ica_close_adapter(ah);
	free(out);
	free(pubkey.exponent);
	free(pubkey.modulus);
	free(privkey.p);
	free(privkey.q);
	free(privkey.dp);
	free(privkey.dq);
	free(privkey.qInverse);
	syslog(LOG_ERR, "Libica RSA test failed.");
	return 1;
}

/*
 * List of non-fips-approved algorithms
 */
int FIPS_BLACKLIST[] = {DES_ECB, DES_CBC, DES_CBC_CS, DES_OFB,
	DES_CFB, DES_CTR, DES_CTRLST, DES_CBC_MAC, DES_CMAC, P_RNG, DES3_ECB,
	DES3_CBC, DES3_CBC_CS, DES3_OFB, DES3_CFB, DES3_CTR, DES3_CTRLST,
	DES3_CBC_MAC, DES3_CMAC, ED25519_KEYGEN, ED25519_SIGN, ED25519_VERIFY,
	ED448_KEYGEN, ED448_SIGN, ED448_VERIFY, X25519_KEYGEN, X25519_DERIVE,
	X448_KEYGEN, X448_DERIVE, RSA_ME, RSA_CRT, SHA512_DRNG, -1, -1 };
const size_t FIPS_BLACKLIST_LEN
	= sizeof(FIPS_BLACKLIST) / sizeof(FIPS_BLACKLIST[0]);

/*
 * FIPS service indicator: List of tolerated but non-approved algorithms.
 */
int FIPS_OVERRIDE_LIST[] = { RSA_ME, RSA_CRT, SHA512_DRNG, -1, -1 };
const size_t FIPS_OVERRIDE_LIST_LEN
	= sizeof(FIPS_OVERRIDE_LIST) / sizeof(FIPS_OVERRIDE_LIST[0]);

/*
 * Returns 1 if the algorithm identified by @id is FIPS approved.
 * Returns 0 otherwise.
 */
int fips_approved(int id)
{
	size_t i;
	int rc;

	if (pthread_rwlock_rdlock(&fips_list_lock) != 0) {
		syslog(LOG_ERR, "Error obtaining read-lock in fips_approved");
		return 0;
	}

	for (i = 0; i < FIPS_BLACKLIST_LEN; i++) {
		if (id == FIPS_BLACKLIST[i]) {
			rc = 0;
			goto done;
		}
	}

	rc = 1;

done:
	if (pthread_rwlock_unlock(&fips_list_lock) != 0) {
		syslog(LOG_ERR, "Error unlock read-lock in fips_approved");
		return 0;
	}

	return rc;
}

/*
 * Returns 1 if the algorithm identified by @id is FIPS tolerated, i.e. it is
 * available via the API in fips mode, but considered non-approved.
 * Returns 0 otherwise.
 */
int fips_override(int id)
{
	size_t i;
	int rc;

	if (pthread_rwlock_rdlock(&fips_list_lock) != 0) {
		syslog(LOG_ERR, "Error obtaining read-lock in fips_override");
		return 0;
	}

	for (i = 0; i < FIPS_OVERRIDE_LIST_LEN; i++) {
		if (id == FIPS_OVERRIDE_LIST[i]) {
			rc = 1;
			goto done;
		}
	}

	rc = 0;

done:
	if (pthread_rwlock_unlock(&fips_list_lock) != 0) {
		syslog(LOG_ERR, "Error unlock read-lock in fips_override");
		return 0;
	}

	return rc;
}

/*
 * Following routines add an algo id to a fips list by replacing a
 * placeholder indicated by -1 by the given id.
 */
void add_to_fips_black_list(int id)
{
	size_t i;

	if (pthread_rwlock_wrlock(&fips_list_lock) != 0) {
		syslog(LOG_ERR, "Error obtaining write-lock in add_to_fips_black_list");
		return;
	}

	for (i = 0; i < FIPS_BLACKLIST_LEN; i++) {
		if (FIPS_BLACKLIST[i] == -1) {
			FIPS_BLACKLIST[i] = id;
			goto done;
		}
	}

done:
	if (pthread_rwlock_unlock(&fips_list_lock) != 0)
		syslog(LOG_ERR, "Error unlock write-lock in add_to_fips_black_list");
}

void add_to_fips_override_list(int id)
{
	size_t i;

	if (pthread_rwlock_wrlock(&fips_list_lock) != 0) {
		syslog(LOG_ERR, "Error obtaining write-lock in add_to_fips_override_list");
		return;
	}

	for (i = 0; i < FIPS_OVERRIDE_LIST_LEN; i++) {
		if (FIPS_OVERRIDE_LIST[i] == -1) {
			FIPS_OVERRIDE_LIST[i] = id;
			goto done;
		}
	}

done:
	if (pthread_rwlock_unlock(&fips_list_lock) != 0)
		syslog(LOG_ERR, "Error unlock write-lock in add_to_fips_override_list");
}

/*
 * Following routines remove an algo id from a fips list by replacing the
 * algo id by the placeholder indicated by -1.
 */
void remove_from_fips_black_list(int id)
{
	size_t i;

	if (pthread_rwlock_wrlock(&fips_list_lock) != 0) {
		syslog(LOG_ERR, "Error obtaining write-lock in remove_from_fips_black_list");
		return;
	}

	for (i = 0; i < FIPS_BLACKLIST_LEN; i++) {
		if (FIPS_BLACKLIST[i] == id) {
			FIPS_BLACKLIST[i] = -1;
			goto done;
		}
	}

done:
	if (pthread_rwlock_unlock(&fips_list_lock) != 0)
		syslog(LOG_ERR, "Error unlock write-lock in remove_from_fips_black_list");
}

void remove_from_fips_override_list(int id)
{
	size_t i;

	if (pthread_rwlock_wrlock(&fips_list_lock) != 0) {
		syslog(LOG_ERR, "Error obtaining write-lock in remove_from_fips_override_list");
		return;
	}

	for (i = 0; i < FIPS_OVERRIDE_LIST_LEN; i++) {
		if (FIPS_OVERRIDE_LIST[i] == id) {
			FIPS_OVERRIDE_LIST[i] = -1;
			goto done;
		}
	}

done:
	if (pthread_rwlock_unlock(&fips_list_lock) != 0)
		syslog(LOG_ERR, "Error unlock write-lock in remove_from_fips_override_list");
}
#endif /* FIPS_H */
