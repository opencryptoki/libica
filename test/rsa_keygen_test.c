#include <errno.h>
#include <openssl/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include <openssl/opensslconf.h>
#ifdef OPENSSL_FIPS
#include <openssl/fips.h>
#endif /* OPENSSL_FIPS */

#include "ica_api.h"
#include "testcase.h"

#define ZERO_PADDING 8

#define BITSTOBYTES(bits) (((bits)+7)/8)
#define EXPO_TYPE_3 3
#define EXPO_TYPE_65537 65537
#define EXPO_TYPE_R 1

/* print error report after function return */
static void print_error_report(unsigned int rc_sv, int errno_sv,
			       const char *func_name);

extern int errno;

int main(int argc, char **argv)
{
	struct timeval start, end;
	unsigned int rc = 0, rc_test = 0, expo_type = 0, key_bit_length = 0;
	int argno_expo = 2, argno_key = 1;

	set_verbosity(argc, argv);

	/* first cmd line arg may be verbosity */
	if (verbosity_ != 0) {
		argc--;
		argno_expo++;
		argno_key++;
	}

	if(argc < 3){
		printf( "usage: %s [<verbosity> (-v or -vv)] <key_bit_length>"
		    " (57..4096) <exponent_type> (3, 65537 or r [random])\n",
		    argv[0]);
		return TEST_ERR;
	}

	if((0 == (key_bit_length=strtol(argv[argno_key], &argv[argno_key],
	    10))) || ('\0' != *argv[argno_key]) ){
		printf( "error - possible values for"
				" <key_bit_length> are integers"
				" greater than 0.\n");
		return TEST_ERR;
	}

	if(BITSTOBYTES(key_bit_length) < 8){
		printf("error - <key_bit_length> must be at least 57.\n");
		return TEST_ERR;
	}

	if(0 == (strcmp(argv[argno_expo], "3")))
		expo_type = EXPO_TYPE_3;
	else if(0 == (strcmp(argv[argno_expo], "65537")))
		expo_type = EXPO_TYPE_65537;
	else if(0 == (strcmp(argv[argno_expo], "r")))
		expo_type = EXPO_TYPE_R;
	else {
		printf( "error -  possible values for <exponent_type>"
				" are 3, 65537 or r (random)\n");
		return TEST_ERR;
	}

	unsigned char ciphertext[BITSTOBYTES(key_bit_length)],
	    decrypted[BITSTOBYTES(key_bit_length)],
	    plaintext[BITSTOBYTES(key_bit_length)];
	memset(ciphertext, 0, (size_t) BITSTOBYTES(key_bit_length));
	memset(decrypted, 0, (size_t) BITSTOBYTES(key_bit_length));
	memset(plaintext, 0, (size_t) BITSTOBYTES(key_bit_length));

	unsigned char modexpo_public_e[BITSTOBYTES(key_bit_length)];
	memset(modexpo_public_e, 0, (size_t) BITSTOBYTES(key_bit_length));
	unsigned char modexpo_public_n[BITSTOBYTES(key_bit_length)];
	memset(modexpo_public_n, 0, (size_t) BITSTOBYTES(key_bit_length));

	unsigned char crt_private_p[BITSTOBYTES(key_bit_length) / 2 + 1 + ZERO_PADDING];
	memset(crt_private_p, 0, (size_t) (BITSTOBYTES(key_bit_length) / 2 + 1 + ZERO_PADDING));
	unsigned char crt_private_q[BITSTOBYTES(key_bit_length) / 2 + 1];
	memset(crt_private_q, 0, (size_t) (BITSTOBYTES(key_bit_length) / 2 + 1));
	unsigned char crt_private_dp[BITSTOBYTES(key_bit_length) / 2 + 1 + ZERO_PADDING];
	memset(crt_private_dp, 0, (size_t) (BITSTOBYTES(key_bit_length) / 2 + 1 + ZERO_PADDING));
	unsigned char crt_private_dq[BITSTOBYTES(key_bit_length) / 2 + 1];
	memset(crt_private_dq, 0, (size_t) (BITSTOBYTES(key_bit_length) / 2 + 1));
	unsigned char crt_private_inv_q[BITSTOBYTES(key_bit_length) / 2 + 1 + ZERO_PADDING];
	memset(crt_private_inv_q, 0, (size_t) (BITSTOBYTES(key_bit_length) / 2 + 1 + ZERO_PADDING));

	ica_rsa_key_mod_expo_t modexpo_public_key = {
	.modulus = modexpo_public_n, .exponent = modexpo_public_e,
	.key_length = BITSTOBYTES(key_bit_length)};

	ica_rsa_key_crt_t crt_private_key = {
	.p = crt_private_p, .q = crt_private_q, .dp = crt_private_dp,
	.dq = crt_private_dq, .qInverse = crt_private_inv_q,
	.key_length = BITSTOBYTES(key_bit_length)};

	ica_adapter_handle_t adapter_handle = 0;

	V_(printf("[TEST RSA CRT]\n"));
	V_(printf("generate random plaintext...\n"));
	if((rc = ica_random_number_generate(BITSTOBYTES(key_bit_length) ,plaintext)) != 0){
		++rc_test;
		print_error_report(rc, errno, "ica_random_number_generate");
	}

	/* make sure that plaintext < modulus */
	plaintext[0] = 0;

	VV_(printf("plaintext:\n"));
	dump_array(plaintext, BITSTOBYTES(key_bit_length));

	if((rc = ica_open_adapter(&adapter_handle)) != 0){
		++rc_test;
		print_error_report(rc, errno, "ica_open_adapter");
	}
	if(adapter_handle == DRIVER_NOT_LOADED) {
		V_(printf("adapter handle is %d\n", adapter_handle));
	}

	switch(expo_type){
	case EXPO_TYPE_3:
		*(unsigned long*)((unsigned char *)modexpo_public_key.exponent +
				  modexpo_public_key.key_length -
				  sizeof(unsigned long)) = (unsigned long) EXPO_TYPE_3;
		break;
	case EXPO_TYPE_65537:
		*(unsigned long*)((unsigned char *)modexpo_public_key.exponent +
				  modexpo_public_key.key_length -
				  sizeof(unsigned long)) = (unsigned long) EXPO_TYPE_65537;
		break;
	case EXPO_TYPE_R:
		/* .exponent element is not set here.
		 * if .exponent element is not set, ica_rsa_generate_mod_expo
		 * will randomly generate it */
		break;
	default:
		printf( "error - unknown <exponent_type>\n");
		return TEST_ERR;
	}

	V_(printf("generate keys...\n"));

	gettimeofday(&start, NULL);
	if((rc = ica_rsa_key_generate_crt(adapter_handle,
					       key_bit_length,
					       &modexpo_public_key,
					       &crt_private_key)) != 0){
		++rc_test;
		print_error_report(rc, errno, "ica_rsa_key_generate_crt");
	}
	gettimeofday(&end, NULL);
	V_(printf("RSA CRT Key_gen with key length %d took: %06lu µs.\n",
	    key_bit_length, (end.tv_sec * 1000000 + end.tv_usec)
	    - (start.tv_sec * 1000000 + start.tv_usec)));

	VV_(printf("public key (e,n):\ne =\n"));
	dump_array(modexpo_public_key.exponent, BITSTOBYTES(key_bit_length));
	VV_(printf("n =\n"));
	dump_array(modexpo_public_key.modulus, BITSTOBYTES(key_bit_length));
	VV_(printf("private key (p,q,dp,dq,q^-1):\np =\n"));
	dump_array(crt_private_key.p,
	    BITSTOBYTES(key_bit_length) / 2 + 1 + ZERO_PADDING);
	VV_(printf("q =\n"));
	dump_array(crt_private_key.q, BITSTOBYTES(key_bit_length) / 2 + 1);
	VV_(printf("dp =\n"));
	dump_array(crt_private_key.dp,
	    BITSTOBYTES(key_bit_length) / 2 + 1 +ZERO_PADDING);
	VV_(printf("dq =\n"));
	dump_array(crt_private_key.dq, BITSTOBYTES(key_bit_length) / 2 + 1);
	VV_(printf("q^-1 =\n"));
	dump_array(crt_private_key.qInverse,
	    BITSTOBYTES(key_bit_length) / 2 + 1 + ZERO_PADDING);

	V_(printf("encrypt...\n"));
	if((rc = ica_rsa_mod_expo(adapter_handle, plaintext, &modexpo_public_key,
				  ciphertext)) != 0){
		++rc_test;
		print_error_report(rc, errno, "ica_rsa_mod_expo");
	}

	VV_(printf("ciphertext:\n"));
	dump_array(ciphertext, BITSTOBYTES(key_bit_length));

	V_(printf("decrypt...\n"));
	if((rc = ica_rsa_crt(adapter_handle, ciphertext, &crt_private_key,
				  decrypted)) != 0){
		++rc_test;
		print_error_report(rc, errno, "ica_rsa_crt");
	}

	VV_(printf("result:\n"));
	dump_array(decrypted, BITSTOBYTES(key_bit_length));

	if((rc = ica_close_adapter(adapter_handle)) != 0){
		++rc_test;
		print_error_report(rc, errno, "ica_close_adapter");
	}

	V_(printf("compare ciphertext to plaintext...\n"));
	if(memcmp(plaintext,ciphertext,BITSTOBYTES(key_bit_length)) == 0) {
		V_(printf("FAILED\nerror - ciphertext equals plaintext.\n"));
		++rc_test;
	}

	V_(printf("compare result to plaintext...\n"));
	if(memcmp(plaintext,decrypted,BITSTOBYTES(key_bit_length)) != 0) {
		V_(printf("FAILED\nerror - decryption result doesn't match plaintext.\n"));
		++rc_test;
	}

	if(0 == rc_test) {
		printf("All RSA keygen (%u bit) tests passed.\n",
		    key_bit_length);

		return TEST_SUCC;
	} else {
		printf("RSA keygen (%u) tests failed: %u errors.",
		    key_bit_length, rc_test);
		if (FIPS_mode())
			printf(" (Parameters might be non FIPS conformant.)");
		printf("\n");

		return TEST_FAIL;
	}
}

static void print_error_report(unsigned int rc_sv, int errno_sv,
			       const char *func_name)
{
	V_(printf("FAILED\nerror - %s returned %u: ", func_name, rc_sv));
	switch (rc_sv) {
	case EFAULT:
		V_(printf("the message authentication failed.\n"));
		break;
	case EINVAL:
		V_(printf("incorrect parameter.\n"));
		break;
	case EIO:
		V_(printf("I/O error.\n"));
		break;
	case EPERM:
		V_(printf("operation not permitted by hardware (CPACF).\n"));
		break;
	case ENODEV:
		V_(printf("no such device.\n"));
		break;
	case ENOMEM:
		V_(printf("not enough memory.\n"));
		break;
	default:
		V_(printf("unknown return code. this shouldn't happen.\n"));
	}

	V_(printf("errno "));
	if (0 == errno_sv){
		V_(printf("not set.\n"));
	}
	else{
		V_(printf("set to %d: %s.\n",
			errno_sv, strerror(errno_sv)));
	}
}
