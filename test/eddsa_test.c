/*
 * This program is released under the Common Public License V1.0
 *
 * You should have received a copy of Common Public License V1.0 along with
 * with this program.
 *
 * Copyright IBM Corp. 2018
 */

#include <pthread.h>
#include <openssl/evp.h>

#include "ica_api.h"
#include "testcase.h"
#include "eddsa_test.h"

#define THREADS		256
#define ITERATIONS	1000
#define MSGLEN		(16384 * 2ULL)

#ifndef NO_CPACF
static void check_functionlist(void);

static void ed25519_kat(void);
static void ed448_kat(void);

static void ed25519_pc(void);
static void ed448_pc(void);

static void ed25519_stress(void);
static void ed448_stress(void);

static void ed25519_speed(void);
static void ed448_speed(void);

static void *thread_ed25519(void *arg);
static void *thread_ed448(void *arg);

time_t seed;
pthread_t threads[THREADS];
#endif /* NO_CPACF */

int perform_tests(int argc, char *argv[])
{
	int i;

	set_verbosity(argc, argv);

	check_functionlist();

	srand(time(&seed));

	VV_(printf("\n=== ED25519 KAT ===\n"));
	ed25519_kat();

	VV_(printf("\n=== ED448 KAT ===\n"));
	ed448_kat();

	VV_(printf("\n=== ED25519 PC ===\n"));
	for (i = 0; i < ITERATIONS; i++)
		ed25519_pc();

	VV_(printf("\n=== ED448 PC ===\n"));
	for (i = 0; i < ITERATIONS; i++)
		ed448_pc();

	VV_(printf("\n=== ED25519 STRESS ===\n"));
	ed25519_stress();

	VV_(printf("\n=== ED448 STRESS ===\n"));
	ed448_stress();

	VV_(printf("\n=== ED25519 SPEED ===\n"));
	ed25519_speed();

	VV_(printf("\n=== ED448 SPEED ===\n"));
	ed448_speed();

	return TEST_SUCC;
}

int main(int argc, char *argv[])
{
#if defined(NO_CPACF)
	UNUSED(argc);
	UNUSED(argv);
	printf("Skipping ED-DSA test, because CPACF support disabled via config option.\n");
	return TEST_SKIP;
#else

#if defined(ICA_FIPS)
	if (ica_fips_status() & ICA_FIPS_MODE) {
		printf("Skipping ED-DSA test, because of FIPS mode.\n");
		return TEST_SKIP;
	}
#endif

	return perform_tests(argc, argv);
#endif
}

#ifndef NO_CPACF
static void check_functionlist(void)
{
	unsigned int i, listlen, func;
	libica_func_list_element *list;

	if (ica_get_functionlist(NULL, &listlen))
		EXIT_ERR("ica_get_functionlist failed.");

	func = 0;

	list = calloc(1, sizeof(*list) * listlen);
	if (list == NULL)
		EXIT_ERR("calloc failed.");

	if (ica_get_functionlist(list, &listlen))
		EXIT_ERR("ica_get_functionlist failed.");

	for (i = 0; i < listlen; i++) {
		if (list[i].mech_mode_id == ED25519_KEYGEN
		    && (list[i].flags & 4))
			func |= 0x01;
		if (list[i].mech_mode_id == ED25519_SIGN
		    && (list[i].flags & 4))
			func |= 0x02;
		if (list[i].mech_mode_id == ED25519_VERIFY
		    && (list[i].flags & 4))
			func |= 0x04;
		if (list[i].mech_mode_id == ED448_KEYGEN
		    && (list[i].flags & 4))
			func |= 0x08;
		if (list[i].mech_mode_id == ED448_SIGN
		    && (list[i].flags & 4))
			func |= 0x10;
		if (list[i].mech_mode_id == ED448_VERIFY
		    && (list[i].flags & 4))
			func |= 0x20;
	}

	free(list);

	if (func != (0x01 | 0x02 | 0x04 | 0x08 | 0x10 | 0x20))
		exit(TEST_SKIP);
}

static void ed25519_kat(void)
{
	unsigned char pub[32], sig[64];
	ICA_ED25519_CTX *ctx;
	const struct eddsa_tv *tv;
	size_t i;

	if (ica_ed25519_ctx_new(&ctx))
		EXIT_ERR("ica_ed25519_ctx_new failed.");

	tv = &EDDSA_TV[0];

	for (i = 0; i < EDDSA_TV_LEN; i++, tv++) {
		if (tv->nid != NID_ED25519)
			continue;

		VV_(printf("--- Test vector %lu ---\n", (i + 1)));

		if (ica_ed25519_key_set(ctx, tv->priv, NULL))
			EXIT_ERR("ica_ed25519_key_set failed.");

		if (ica_ed25519_key_get(ctx, NULL, pub))
			EXIT_ERR("ica_ed25519_key_get failed.");

		if (memcmp(pub, tv->pub, sizeof(pub))) {
			VV_(printf("Derived pub:\n"));
			dump_array(pub, sizeof(pub));
			VV_(printf("Correct pub:\n"));
			dump_array((unsigned char*)tv->pub, sizeof(pub));
			EXIT_ERR("Public key derivation failed.");
		}

		if (ica_ed25519_sign(ctx, sig, tv->msg, tv->msglen))
			EXIT_ERR("ica_ed25519_sign failed.");

		if (memcmp(sig, tv->sig, sizeof(sig))) {
			VV_(printf("Computed sig:\n"));
			dump_array(sig, sizeof(sig));
			VV_(printf("Correct sig:\n"));
			dump_array((unsigned char *)tv->sig, sizeof(sig));
			EXIT_ERR("Invalid signature.");
		}

		if (ica_ed25519_verify(ctx, sig, tv->msg, tv->msglen))
			EXIT_ERR("ica_ed25519_verify failed.");

		/* flip a random bit */
		sig[rand() % sizeof(sig)] ^= (1 << (rand() % 8));

		if (!ica_ed25519_verify(ctx, sig, tv->msg, tv->msglen)) {
			VV_(printf("Verified invalid signature:\n"));
			dump_array(sig, sizeof(sig));
			EXIT_ERR("ica_ed25519_verify succeeded"
				 " with invalid signature.");
		}

		VV_(printf("--- Passed. ---\n"));
	}

	if (ica_ed25519_ctx_del(&ctx))
		EXIT_ERR("ica_ed25519_ctx_del failed.");
}

static void ed448_kat(void)
{
	unsigned char pub[57], sig[114];
	ICA_ED448_CTX *ctx;
	const struct eddsa_tv *tv;
	size_t i;

	if (ica_ed448_ctx_new(&ctx))
		EXIT_ERR("ica_ed448_ctx_new failed.");

	tv = &EDDSA_TV[0];

	for (i = 0; i < EDDSA_TV_LEN; i++, tv++) {
		if (tv->nid != NID_ED448)
			continue;

		VV_(printf("--- Test vector %lu ---\n", (i + 1)));

		if (ica_ed448_key_set(ctx, tv->priv, NULL))
			EXIT_ERR("ica_ed448_key_set failed.");

		if (ica_ed448_key_get(ctx, NULL, pub))
			EXIT_ERR("ica_ed448_key_get failed.");

		if (memcmp(pub, tv->pub, sizeof(pub))) {
			VV_(printf("Derived pub:\n"));
			dump_array(pub, sizeof(pub));
			VV_(printf("Correct pub:\n"));
			dump_array((unsigned char *)tv->pub, sizeof(pub));
			EXIT_ERR("Public key derivation failed.");
		}

		if (ica_ed448_sign(ctx, sig, tv->msg, tv->msglen))
			EXIT_ERR("ica_ed448_sign failed.");

		if (memcmp(sig, tv->sig, sizeof(sig))) {
			VV_(printf("Computed sig:\n"));
			dump_array(sig, sizeof(sig));
			VV_(printf("Correct sig:\n"));
			dump_array((unsigned char *)tv->sig, sizeof(sig));
			EXIT_ERR("Invalid signature.");
		}

		if (ica_ed448_verify(ctx, sig, tv->msg, tv->msglen))
			EXIT_ERR("ica_ed448_verify failed.");

		/* flip a random bit */
		sig[rand() % sizeof(sig)] ^= (1 << (rand() % 8));

		if (!ica_ed448_verify(ctx, sig, tv->msg, tv->msglen)) {
			VV_(printf("Verified invalid signature:\n"));
			dump_array(sig, sizeof(sig));
			EXIT_ERR("ica_ed448_verify succeded"
				 " with invalid signature.");
		}

		VV_(printf("--- Passed. ---\n"));
	}

	if (ica_ed448_ctx_del(&ctx))
		EXIT_ERR("ica_ed448_ctx_del failed.");
}

static void ed25519_pc(void)
{
	ICA_ED25519_CTX *ctx;
	EVP_PKEY_CTX *pctx = NULL;
	EVP_MD_CTX *ctx2;
	EVP_PKEY *pkey;
	unsigned char priv[32], ossl_sig[64], ica_sig[64];
	unsigned char *msg;
	size_t msglen, out = 64;
	FILE *fd;

	msglen = rand() % MSGLEN;

	msg = malloc(msglen);
	if (msg == NULL)
		EXIT_ERR("malloc failed.");

	if (msglen > 0) {
		fd = fopen("/dev/urandom", "r");
		if (fd == NULL)
			EXIT_ERR("fopen failed.");

		if (fread(msg, msglen, 1, fd) != 1)
			EXIT_ERR("fread failed.");
		fclose(fd);
	}

	if (ica_ed25519_ctx_new(&ctx))
		EXIT_ERR("ica_ed448_ctx_new failed.");

	if (ica_ed25519_key_gen(ctx))
		EXIT_ERR("ica_ed25519_key_gen failed.");

	if (ica_ed25519_key_get(ctx, priv, NULL))
		EXIT_ERR("ica_ed25519_key_get failed.");

	ctx2 = EVP_MD_CTX_new();
	if (ctx2 == NULL)
		EXIT_ERR("EVP_MD_CTX_new failed.");

	pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL,
					    priv, sizeof(priv));
	if (pkey == NULL)
		EXIT_ERR("EVP_PKEY_new_raw_private_key failed.");

	if (EVP_DigestSignInit(ctx2, &pctx, NULL, NULL, pkey) != 1)
		EXIT_ERR("EVP_DigestSignInit failed.");

	if (EVP_DigestSign(ctx2, ossl_sig, &out, msg, msglen) != 1)
		EXIT_ERR("EVP_DigestSign failed.");

	if (ica_ed25519_sign(ctx, ica_sig, msg, msglen))
		EXIT_ERR("ica_ed25519_sign failed.");

	if (memcmp(ica_sig, ossl_sig, sizeof(ica_sig))) {
		VV_(printf("Private key:\n"));
		dump_array(priv, sizeof(priv));
		VV_(printf("Message:\n"));
		dump_array(msg, msglen);
		VV_(printf("Signature (libica):\n"));
		dump_array(ica_sig, sizeof(ica_sig));
		VV_(printf("Signature (libcrypto):\n"));
		dump_array(ossl_sig, sizeof(ossl_sig));
		EXIT_ERR("libcrypto Ed25519 signature differs.");
	}

	if (EVP_DigestVerifyInit(ctx2, &pctx, NULL, NULL, pkey) != 1)
		EXIT_ERR("EVP_DigestVerifyInit failed.");

	if (EVP_DigestVerify(ctx2, ica_sig, sizeof(ica_sig), msg, msglen) != 1)
		EXIT_ERR("EVP_DigestVerify failed.");

	if (ica_ed25519_verify(ctx, ossl_sig, msg, msglen))
		EXIT_ERR("ica_ed25519_verify failed.");

	EVP_MD_CTX_free(ctx2);
	EVP_PKEY_free(pkey);

	if (ica_ed25519_ctx_del(&ctx))
		EXIT_ERR("ica_ed25519_ctx_del failed.");

	free(msg);
}

static void ed448_pc(void)
{
	ICA_ED448_CTX *ctx;
	EVP_PKEY_CTX *pctx = NULL;
	EVP_MD_CTX *ctx2;
	EVP_PKEY *pkey;
	unsigned char priv[57], ossl_sig[114], ica_sig[114];
	unsigned char *msg;
	size_t msglen, out = 114;
	FILE *fd;

	msglen = rand() % MSGLEN;

	msg = malloc(msglen);
	if (msg == NULL)
		EXIT_ERR("malloc failed.");

	if (msglen > 0) {
		fd = fopen("/dev/urandom", "r");
		if (fd == NULL)
			EXIT_ERR("fopen failed.");

		if (fread(msg, msglen, 1, fd) != 1)
			EXIT_ERR("fread failed.");

		fclose(fd);
	}

	if (ica_ed448_ctx_new(&ctx))
		EXIT_ERR("ica_ed448_ctx_new failed.");

	if (ica_ed448_key_gen(ctx))
		EXIT_ERR("ica_ed448_key_gen failed.");

	if (ica_ed448_key_get(ctx, priv, NULL))
		EXIT_ERR("ica_ed448_key_get failed.");

	ctx2 = EVP_MD_CTX_new();
	if (ctx2 == NULL)
		EXIT_ERR("EVP_MD_CTX_new failed.");

	pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED448, NULL,
					    priv, sizeof(priv));
	if (pkey == NULL)
		EXIT_ERR("EVP_PKEY_new_raw_private_key failed.");

	if (EVP_DigestSignInit(ctx2, &pctx, NULL, NULL, pkey) != 1)
		EXIT_ERR("EVP_DigestSignInit failed.");

	if (EVP_DigestSign(ctx2, ossl_sig, &out, msg, msglen) != 1)
		EXIT_ERR("EVP_DigestSign failed.");

	if (ica_ed448_sign(ctx, ica_sig, msg, msglen))
		EXIT_ERR("ica_ed448_sign failed.");

	if (memcmp(ica_sig, ossl_sig, sizeof(ica_sig))) {
		VV_(printf("Private key:\n"));
		dump_array(priv, sizeof(priv));
		VV_(printf("Message:\n"));
		dump_array(msg, msglen);
		VV_(printf("Signature (libica):\n"));
		dump_array(ica_sig, sizeof(ica_sig));
		VV_(printf("Signature (libcrypto):\n"));
		dump_array(ossl_sig, sizeof(ossl_sig));
		EXIT_ERR("libcrypto Ed448 signature differs.");
	}

	if (EVP_DigestVerifyInit(ctx2, &pctx, NULL, NULL, pkey) != 1)
		EXIT_ERR("EVP_DigestVerifyInit failed.");

	if (EVP_DigestVerify(ctx2, ica_sig, sizeof(ica_sig), msg, msglen) != 1)
		EXIT_ERR("EVP_DigestVerify failed.");

	if (ica_ed448_verify(ctx, ossl_sig, msg, msglen))
		EXIT_ERR("ica_ed448_verify failed.");

	EVP_MD_CTX_free(ctx2);
	EVP_PKEY_free(pkey);

	if (ica_ed448_ctx_del(&ctx))
		EXIT_ERR("ica_ed448_ctx_del failed.");

	free(msg);
}

static void ed25519_stress(void)
{
	int rc, i;
	ICA_ED25519_CTX *ctx[THREADS];

	for (i = 0; i < THREADS; i++) {
		if (ica_ed25519_ctx_new(&ctx[i]))
			EXIT_ERR("ica_ed25519_ctx_new failed.");
	}

	for (i = 0; i < THREADS; i++) {
		while((rc = pthread_create(&threads[i], NULL, thread_ed25519,
					   ctx[i])) == EAGAIN)
		if (rc)
			EXIT_ERR("pthread_create failed.");
	}

	for (i = 0; i < THREADS; i++) {
		rc = pthread_join(threads[i], NULL);
		if (rc)
			EXIT_ERR("pthread_join failed.");
	}

	for (i = 0; i < THREADS; i++) {
		if (ica_ed25519_ctx_del(&ctx[i]))
			EXIT_ERR("ica_ed25519_ctx_del failed.");
	}
}

static void *thread_ed25519(void *arg)
{
	ICA_ED25519_CTX *ctx = (ICA_ED25519_CTX *)arg;
	unsigned char sig[64], msg[MSGLEN];
	int i;

	for (i = 0; i < ITERATIONS; i++) {
		if (ica_ed25519_key_gen(ctx))
			EXIT_ERR("ica_ed25519_key_gen failed.");
		if (ica_ed25519_sign(ctx, sig, msg, sizeof(msg)))
			EXIT_ERR("ica_ed25519_sign failed.");
		if (ica_ed25519_verify(ctx, sig, msg, sizeof(msg)))
			EXIT_ERR("ica_ed25519_verify failed.");
	}

	return NULL;
}

static void ed448_stress(void)
{
	int rc, i;
	ICA_ED448_CTX *ctx[THREADS];

	for (i = 0; i < THREADS; i++) {
		if (ica_ed448_ctx_new(&ctx[i]))
			EXIT_ERR("ica_ed448_ctx_new failed.");
	}

	for (i = 0; i < THREADS; i++) {
		while((rc = pthread_create(&threads[i], NULL, thread_ed448,
					   ctx[i])) == EAGAIN)
		if (rc)
			EXIT_ERR("pthread_create failed.");
	}

	for (i = 0; i < THREADS; i++) {
		rc = pthread_join(threads[i], NULL);
		if (rc)
			EXIT_ERR("pthread_join failed.");
	}

	for (i = 0; i < THREADS; i++) {
		if (ica_ed448_ctx_del(&ctx[i]))
			EXIT_ERR("ica_ed448_ctx_del failed.");
	}
}

static void *thread_ed448(void *arg)
{
	ICA_ED448_CTX *ctx = (ICA_ED448_CTX *)arg;
	unsigned char sig[114], msg[MSGLEN];
	int i;

	for (i = 0; i < ITERATIONS; i++) {
		if (ica_ed448_key_gen(ctx))
			EXIT_ERR("ica_ed448_key_gen failed.");
		if (ica_ed448_sign(ctx, sig, msg, sizeof(msg)))
			EXIT_ERR("ica_ed448_sign failed.");
		if (ica_ed448_verify(ctx, sig, msg, sizeof(msg)))
			EXIT_ERR("ica_ed448_verify failed.");
	}

	return NULL;
}

static void ed25519_speed(void)
{
	struct timeval start, stop;
	unsigned long long delta;
	unsigned char sig[64], msg[MSGLEN];
	long double ops;
	ICA_ED25519_CTX *ctx;
	int i;

	if (ica_ed25519_ctx_new(&ctx))
		EXIT_ERR("ica_ed25519_ctx_new failed.");

	gettimeofday(&start, NULL);
	for (i = 0; i < ITERATIONS; i++) {
		if (ica_ed25519_key_gen(ctx))
			EXIT_ERR("ica_ed25519_key_gen failed.");
	}
	gettimeofday(&stop, NULL);
	delta = delta_usec(&start, &stop);
	ops = ops_per_sec(ITERATIONS, delta);
	printf("ica_ed25519_key_gen\t%.2Lf ops/sec\n", ops);

	gettimeofday(&start, NULL);
	for (i = 0; i < ITERATIONS; i++) {
		if (ica_ed25519_sign(ctx, sig, msg, sizeof(msg)))
			EXIT_ERR("ica_ed25519_sign failed.");
	}
	gettimeofday(&stop, NULL);
	delta = delta_usec(&start, &stop);
	ops = ops_per_sec(ITERATIONS, delta);
	printf("ica_ed25519_sign(%llu bytes)\t%.2Lf ops/sec\n", MSGLEN, ops);

	gettimeofday(&start, NULL);
	for (i = 0; i < ITERATIONS; i++) {
		if (ica_ed25519_verify(ctx, sig, msg, sizeof(msg)))
			EXIT_ERR("ica_ed25519_verify failed.");
	}
	gettimeofday(&stop, NULL);
	delta = delta_usec(&start, &stop);
	ops = ops_per_sec(ITERATIONS, delta);
	printf("ica_ed25519_verify(%llu bytes)\t%.2Lf ops/sec\n", MSGLEN, ops);

	if (ica_ed25519_ctx_del(&ctx))
		EXIT_ERR("ica_ed25519_ctx_del failed.");
}

static void ed448_speed(void)
{
	struct timeval start, stop;
	unsigned long long delta;
	unsigned char sig[114], msg[MSGLEN];
	long double ops;
	ICA_ED448_CTX *ctx;
	int i;

	if (ica_ed448_ctx_new(&ctx))
		EXIT_ERR("ica_ed448_ctx_new failed.");

	gettimeofday(&start, NULL);
	for (i = 0; i < ITERATIONS; i++) {
		if (ica_ed448_key_gen(ctx))
			EXIT_ERR("ica_ed448_key_gen failed.");
	}
	gettimeofday(&stop, NULL);
	delta = delta_usec(&start, &stop);
	ops = ops_per_sec(ITERATIONS, delta);
	printf("ica_ed448_key_gen\t%.2Lf ops/sec\n", ops);

	gettimeofday(&start, NULL);
	for (i = 0; i < ITERATIONS; i++) {
		if (ica_ed448_sign(ctx, sig, msg, sizeof(msg)))
			EXIT_ERR("ica_ed448_sign failed.");
	}
	gettimeofday(&stop, NULL);
	delta = delta_usec(&start, &stop);
	ops = ops_per_sec(ITERATIONS, delta);
	printf("ica_ed448_sign(%llu bytes)\t%.2Lf ops/sec\n", MSGLEN, ops);

	gettimeofday(&start, NULL);
	for (i = 0; i < ITERATIONS; i++) {
		if (ica_ed448_verify(ctx, sig, msg, sizeof(msg)))
			EXIT_ERR("ica_ed448_verify failed.");
	}
	gettimeofday(&stop, NULL);
	delta = delta_usec(&start, &stop);
	ops = ops_per_sec(ITERATIONS, delta);
	printf("ica_ed448_verify(%llu bytes)\t%.2Lf ops/sec\n", MSGLEN, ops);

	if (ica_ed448_ctx_del(&ctx))
		EXIT_ERR("ica_ed448_ctx_del failed.");
}
#endif /* NO_CPACF */
