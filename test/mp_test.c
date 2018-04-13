/*
 * This program is released under the Common Public License V1.0
 *
 * You should have received a copy of Common Public License V1.0 along with
 * with this program.
 *
 * Author(s): Patrick Steuer <patrick.steuer@de.ibm.com>
 *
 * Copyright IBM Corp. 2018
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>
#include <sys/time.h>

#include "ica_api.h"
#include "testcase.h"

/*
 * known-answer tests
 */
static void mul_kat(void);
static void sqr_kat(void);

/*
 * pairwise-consintency tests
 * libica multiple-precision vs openssl bignum
 */
unsigned long long OPS_PC = 10000ULL;
static void mul_pc(void);
static void sqr_pc(void);

/*
 * performance benchmarking tests
 * libica multiple-precision vs openssl bignum
 */
unsigned long long OPS_BENCH = 100000000ULL;
static void mul_bench(void);
static void sqr_bench(void);

enum {
	EMPTY,
	OSSL_MUL,
	OSSL_SQR,
	ICA_MUL,
	ICA_SQR
} perf_opt;

uint64_t ica_num[512 / 64], ica_num2[512 / 64], ica_res[1024 / 64],
         ossl_res2[1024 / 64];
struct timeval start, stop;
BIGNUM *ossl_num, *ossl_num2, *ossl_res;
BN_CTX *ossl_ctx;
unsigned long long i, delta;

struct {
	uint64_t a[512 / 64];
	uint64_t b[512 / 64];
	uint64_t res[1024 / 64];
} mul_kat_vec[] = {
	{
		{0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL},
		{0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL},
		{0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL,
		 0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL}
	},
	{
		{~0ULL, ~0ULL, ~0ULL, ~0ULL, ~0ULL, ~0ULL, ~0ULL, ~0ULL},
		{~0ULL, ~0ULL, ~0ULL, ~0ULL, ~0ULL, ~0ULL, ~0ULL, ~0ULL},
		{1ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL,
		 0xfffffffffffffffe, ~0ULL, ~0ULL, ~0ULL, ~0ULL, ~0ULL, ~0ULL,
		 ~0ULL}
	}
};
const unsigned long long MUL_KATS = sizeof(mul_kat_vec)
				  / sizeof(mul_kat_vec[0]);

struct {
	uint64_t a[512 / 64];
	uint64_t res[1024 / 64];
} sqr_kat_vec[] = {
	{
		{0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL},
		{0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL,
		 0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL}
	},
	{
		{~0ULL, ~0ULL, ~0ULL, ~0ULL, ~0ULL, ~0ULL, ~0ULL, ~0ULL},
		{1ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL,
		 0xfffffffffffffffe, ~0ULL, ~0ULL, ~0ULL, ~0ULL, ~0ULL, ~0ULL,
		 ~0ULL}
	}
};
const unsigned long long SQR_KATS = sizeof(sqr_kat_vec)
				  / sizeof(sqr_kat_vec[0]);

static inline void swap_u64(uint64_t *a, uint64_t *b)
{
	*a ^= *b;
	*b ^= *a;
	*a ^= *b;
}

int main(int argc, char *argv[])
{
	uint64_t num[1024 / 64];

	set_verbosity(argc, argv);

	if (argc > 2) {
		if (strcasestr(argv[1], "-ossl_mul")) {
			perf_opt = OSSL_MUL;
			OPS_BENCH = strtoull(argv[2], NULL, 0);
		} else if (strcasestr(argv[1], "-ossl_sqr")) {
			perf_opt = OSSL_SQR;
			OPS_BENCH = strtoull(argv[2], NULL, 0);
		} else if (strcasestr(argv[1], "-ica_mul")) {
			perf_opt = ICA_MUL;
			OPS_BENCH = strtoull(argv[2], NULL, 0);
		} else if (strcasestr(argv[1], "-ica_sqr")) {
			perf_opt = ICA_SQR;
			OPS_BENCH = strtoull(argv[2], NULL, 0);
		} else {
			perf_opt = EMPTY;
		}
	}

	if (ica_mp_mul512(num, num, num) != 0) {
		printf("Vector facilities not enabled.\n");
		return TEST_SKIP;
	}

	ossl_ctx = BN_CTX_new();
	if (ossl_ctx == NULL) {
		printf("ERROR: BN_CTX_new\n");
		exit(TEST_FAIL);
	}

	ossl_res = BN_new();
	if (ossl_res == NULL) {
		printf("ERROR: BN_CTX_new\n");
		exit(TEST_FAIL);
	}

	ossl_num = BN_new();
	if (ossl_num == NULL) {
		printf("ERROR: BN_new\n");
		exit(TEST_FAIL);
	}

	ossl_num2 = BN_new();
	if (ossl_num2 == NULL) {
		printf("ERROR: BN_new\n");
		exit(TEST_FAIL);
	}

	if (perf_opt == EMPTY) {
		printf("Known-answer MUL (%llu tests):\n", MUL_KATS);
		mul_kat();
		printf("OK.\n\n");

		printf("Known-answer SQR (%llu tests):\n", SQR_KATS);
		sqr_kat();
		printf("OK.\n\n");

		printf("Pairwise-consistency MUL (%llu tests):\n", OPS_PC);
		for (i = 0; i < OPS_PC; i++)
			mul_pc();
		printf("OK.\n\n");

		printf("Pairwise-consistency SQR (%llu tests):\n", OPS_PC);
		for (i = 0; i < OPS_PC; i++)
			sqr_pc();
		printf("OK.\n\n");
	}

	if (perf_opt != ICA_SQR && perf_opt != OSSL_SQR) {
		printf("Performance benchmark MUL (%llu ops):\n", OPS_BENCH);
		mul_bench();
		printf("\n");
	}

	if (perf_opt != ICA_MUL && perf_opt != OSSL_MUL) {
		printf("Performance benchmark SQR (%llu ops):\n", OPS_BENCH);
		sqr_bench();
		printf("\n");
	}

	BN_free(ossl_num);
	BN_free(ossl_num2);
	BN_free(ossl_res);
	BN_CTX_free(ossl_ctx);

	printf("All ica_mp tests passed.\n");
	return TEST_SUCC;
}

static void mul_kat(void)
{
	for (i = 0; i < MUL_KATS; i++) {
		if (ica_mp_mul512(ica_res, mul_kat_vec[i].a, mul_kat_vec[i].b)) {
			printf("ERROR: ica_mp_mul512\n");
			exit(TEST_FAIL);
		}

		if (memcmp(mul_kat_vec[i].res, ica_res, 1024 / 8)) {
			printf("ERROR: ica_mp_mul512 result doesnt match\n");
			VV_(printf("a:\n"));
			VV_(dump_array_u64(mul_kat_vec[i].a, 512 / 64));
			VV_(printf("b:\n"));
			VV_(dump_array_u64(mul_kat_vec[i].b, 512 / 64));
			VV_(printf("known answer (a*b):\n"));
			VV_(dump_array_u64(mul_kat_vec[i].res, 1024 / 64));
			VV_(printf("ica_mp_mul512 (a*b):\n"));
			VV_(dump_array_u64(ica_res, 1024 / 64));
			VV_(printf("(little-endian digits)\n"));
			exit(TEST_FAIL);
		}
	}
}

static void sqr_kat(void)
{
	for (i = 0; i < SQR_KATS; i++) {
		if (ica_mp_sqr512(ica_res, sqr_kat_vec[i].a)) {
			printf("ERROR: ica_mp_mul512\n");
			exit(TEST_FAIL);
		}

		if (memcmp(sqr_kat_vec[i].res, ica_res, 1024 / 8)) {
			printf("ERROR: ica_mp_sqr512 result doesnt match\n");
			VV_(printf("a:\n"));
			VV_(dump_array_u64(sqr_kat_vec[i].a, 512 / 64));
			VV_(printf("known answer (a^2):\n"));
			VV_(dump_array_u64(sqr_kat_vec[i].res, 1024 / 64));
			VV_(printf("ica_mp_sqr512 (a^2):\n"));
			VV_(dump_array_u64(ica_res, 1024 / 64));
			VV_(printf("(little-endian digits)\n"));
			exit(TEST_FAIL);
		}
	}
}

static void mul_pc(void)
{
	if (!BN_pseudo_rand(ossl_num, 512, 0, 0)) {
		printf("ERROR: BN_pseudo_rand\n");
		exit(TEST_FAIL);
	}

	if (!BN_pseudo_rand(ossl_num2, 512, 0, 0)) {
		printf("ERROR: BN_pseudo_rand\n");
		exit(TEST_FAIL);
	}

	memset(ica_num, 0, sizeof(ica_num));
	if (BN_bn2bin(ossl_num, (unsigned char *)ica_num) != 512 / 8) {
		printf("ERROR: BN_bn2bin\n");
		exit(TEST_FAIL);
	}

	memset(ica_num2, 0, sizeof(ica_num2));
	if (BN_bn2bin(ossl_num2, (unsigned char *)ica_num2) != 512 / 8) {
		printf("ERROR: BN_bn2bin\n");
		exit(TEST_FAIL);
	}

	/* swap to little-endian digits */
	swap_u64(&ica_num[7], &ica_num[0]);
	swap_u64(&ica_num[6], &ica_num[1]);
	swap_u64(&ica_num[5], &ica_num[2]);
	swap_u64(&ica_num[4], &ica_num[3]);
	swap_u64(&ica_num2[7], &ica_num2[0]);
	swap_u64(&ica_num2[6], &ica_num2[1]);
	swap_u64(&ica_num2[5], &ica_num2[2]);
	swap_u64(&ica_num2[4], &ica_num2[3]);

	if (!BN_mul(ossl_res, ossl_num, ossl_num2, ossl_ctx)) {
		printf("ERROR: BN_mul\n");
		exit(TEST_FAIL);
	}

	if (ica_mp_mul512(ica_res, ica_num, ica_num2)) {
		printf("ERROR: ica_mp_mul512\n");
		exit(TEST_FAIL);
	}

	BN_bn2bin(ossl_res, (unsigned char *)ossl_res2);

	/* swap to big-endian digits */
	swap_u64(&ica_res[15], &ica_res[0]);
	swap_u64(&ica_res[14], &ica_res[1]);
	swap_u64(&ica_res[13], &ica_res[2]);
	swap_u64(&ica_res[12], &ica_res[3]);
	swap_u64(&ica_res[11], &ica_res[4]);
	swap_u64(&ica_res[10], &ica_res[5]);
	swap_u64(&ica_res[9], &ica_res[6]);
	swap_u64(&ica_res[8], &ica_res[7]);

	if (memcmp(ossl_res2, ica_res, 1024 / 8)) {
		printf("ERROR: BN_mul/ica_mp_mul512 results dont match\n");
		/* swap to big-endian digits */
		swap_u64(&ica_num[7], &ica_num[0]);
		swap_u64(&ica_num[6], &ica_num[1]);
		swap_u64(&ica_num[5], &ica_num[2]);
		swap_u64(&ica_num[4], &ica_num[3]);
		swap_u64(&ica_num2[7], &ica_num2[0]);
		swap_u64(&ica_num2[6], &ica_num2[1]);
		swap_u64(&ica_num2[5], &ica_num2[2]);
		swap_u64(&ica_num2[4], &ica_num2[3]);
		VV_(printf("a:\n"));
		VV_(dump_array_u64(ica_num, 512 / 64));
		VV_(printf("b:\n"));
		VV_(dump_array_u64(ica_num2, 512 / 64));
		VV_(printf("BN_mul (a*b):\n"));
		VV_(dump_array_u64(ossl_res2, 1024 / 64));
		VV_(printf("ica_mp_mul512 (a*b):\n"));
		VV_(dump_array_u64(ica_res, 1024 / 64));
		VV_(printf("(big-endian digits)\n"));
		exit(TEST_FAIL);
	}
}

static void sqr_pc(void)
{
	if (!BN_pseudo_rand(ossl_num, 512, 0, 0)) {
		printf("ERROR: BN_pseudo_rand\n");
		exit(TEST_FAIL);
	}

	memset(ica_num, 0, sizeof(ica_num));
	if (BN_bn2bin(ossl_num, (unsigned char *)ica_num) != 512 / 8) {
		printf("ERROR: BN_bn2bin\n");
		exit(TEST_FAIL);
	}

	/* swap to little-endian digits */
	swap_u64(&ica_num[7], &ica_num[0]);
	swap_u64(&ica_num[6], &ica_num[1]);
	swap_u64(&ica_num[5], &ica_num[2]);
	swap_u64(&ica_num[4], &ica_num[3]);

	if (!BN_sqr(ossl_res, ossl_num, ossl_ctx)) {
		printf("ERROR: BN_sqr\n");
		exit(TEST_FAIL);
	}

	if (ica_mp_sqr512(ica_res, ica_num)) {
		printf("ERROR: ica_mp_sqr512\n");
		exit(TEST_FAIL);
	}

	BN_bn2bin(ossl_res, (unsigned char *)ossl_res2);

	/* swap to big-endian digits */
	swap_u64(&ica_res[15], &ica_res[0]);
	swap_u64(&ica_res[14], &ica_res[1]);
	swap_u64(&ica_res[13], &ica_res[2]);
	swap_u64(&ica_res[12], &ica_res[3]);
	swap_u64(&ica_res[11], &ica_res[4]);
	swap_u64(&ica_res[10], &ica_res[5]);
	swap_u64(&ica_res[9], &ica_res[6]);
	swap_u64(&ica_res[8], &ica_res[7]);

	if (memcmp(ossl_res2, ica_res, 1024 / 8)) {
		printf("ERROR: BN_sqr/ica_mp_sqr512 results dont match\n");
		/* swap to big-endian digits */
		swap_u64(&ica_num[7], &ica_num[0]);
		swap_u64(&ica_num[6], &ica_num[1]);
		swap_u64(&ica_num[5], &ica_num[2]);
		swap_u64(&ica_num[4], &ica_num[3]);
		VV_(printf("a:\n"));
		VV_(dump_array_u64(ica_num, 512 / 64));
		VV_(printf("BN_sqr (a^2):\n"));
		VV_(dump_array_u64(ossl_res2, 1024 / 64));;
		VV_(printf("ica_mp_sqr512 (a^2):\n"));
		VV_(dump_array_u64(ica_res, 1024 / 64));
		VV_(printf("(big-endian digits)\n"));
		exit(TEST_FAIL);
	}
}

static void mul_bench(void)
{
	if (!BN_pseudo_rand(ossl_num, 512, 0, 0)) {
		printf("ERROR: BN_pseudo_rand\n");
		exit(TEST_FAIL);
	}

	if (!BN_pseudo_rand(ossl_num2, 512, 0, 0)) {
		printf("ERROR: BN_pseudo_rand\n");
		exit(TEST_FAIL);
	}

	memset(ica_num, 0, sizeof(ica_num));
	if (BN_bn2bin(ossl_num, (unsigned char *)ica_num) != 512 / 8) {
		printf("ERROR: BN_bn2bin\n");
		exit(TEST_FAIL);
	}

	memset(ica_num2, 0, sizeof(ica_num2));
	if (BN_bn2bin(ossl_num2, (unsigned char *)ica_num2) != 512 / 8) {
		printf("ERROR: BN_bn2bin\n");
		exit(TEST_FAIL);
	}

	/* swap to little-endian digits */
	swap_u64(&ica_num[7], &ica_num[0]);
	swap_u64(&ica_num[6], &ica_num[1]);
	swap_u64(&ica_num[5], &ica_num[2]);
	swap_u64(&ica_num[4], &ica_num[3]);
	swap_u64(&ica_num2[7], &ica_num2[0]);
	swap_u64(&ica_num2[6], &ica_num2[1]);
	swap_u64(&ica_num2[5], &ica_num2[2]);
	swap_u64(&ica_num2[4], &ica_num2[3]);

	if (perf_opt == EMPTY || perf_opt == OSSL_MUL) {
		gettimeofday(&start, NULL);
		for (i = 0; i < OPS_BENCH; i++) {
			if (!BN_mul(ossl_res, ossl_num, ossl_num, ossl_ctx)) {
				printf("ERROR: BN_mul\n");
				exit(TEST_FAIL);
			}
		}
		gettimeofday(&stop, NULL);
		delta = delta_usec(&start, &stop);
		printf("BN_mul: %llu usec [%.2Lf ops/sec].\n",
		       delta, ops_per_sec(OPS_BENCH, delta));
	}

	if (perf_opt == EMPTY || perf_opt == ICA_MUL) {
		gettimeofday(&start, NULL);
		for (i = 0; i < OPS_BENCH; i++) {
			if (ica_mp_mul512(ica_res, ica_num, ica_num)) {
				printf("ERROR: ica_mp_mul512\n");
				exit(TEST_FAIL);
			}
		}
		gettimeofday(&stop, NULL);
		delta = delta_usec(&start, &stop);
		printf("ica_mp_mul512: %llu usec [%.2Lf ops/sec].\n",
		       delta, ops_per_sec(OPS_BENCH, delta));
	}
}

static void sqr_bench(void)
{
	if (!BN_pseudo_rand(ossl_num, 512, 0, 0)) {
		printf("ERROR: BN_pseudo_rand\n");
		exit(TEST_FAIL);
	}

	memset(ica_num, 0, sizeof(ica_num));
	if (BN_bn2bin(ossl_num, (unsigned char *)ica_num) != 512 / 8) {
		printf("ERROR: BN_bn2bin\n");
		exit(TEST_FAIL);
	}

	/* swap to little-endian digits */
	swap_u64(&ica_num[7], &ica_num[0]);
	swap_u64(&ica_num[6], &ica_num[1]);
	swap_u64(&ica_num[5], &ica_num[2]);
	swap_u64(&ica_num[4], &ica_num[3]);
	if (perf_opt == EMPTY || perf_opt == OSSL_SQR) {
		gettimeofday(&start, NULL);
		for (i = 0; i < OPS_BENCH; i++) {
			if (!BN_sqr(ossl_res, ossl_num, ossl_ctx)) {
				printf("ERROR: BN_sqr\n");
				exit(TEST_FAIL);
			}
		}
		gettimeofday(&stop, NULL);
		delta = delta_usec(&start, &stop);
		printf("BN_sqr: %llu usec [%.2Lf ops/sec].\n",
		       delta, ops_per_sec(OPS_BENCH, delta));
	}

	if (perf_opt == EMPTY || perf_opt == ICA_SQR) {
		gettimeofday(&start, NULL);
		for (i = 0; i < OPS_BENCH; i++) {
			if (ica_mp_sqr512(ica_res, ica_num)) {
				printf("ERROR: ica_mp_sqr512\n");
				exit(TEST_FAIL);
			}
		}
		gettimeofday(&stop, NULL);
		delta = delta_usec(&start, &stop);
		printf("ica_mp_sqr512: %llu usec [%.2Lf ops/sec].\n",
		       delta, ops_per_sec(OPS_BENCH, delta));
	}
}
