#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include "ica_api.h"
#include <sys/time.h>

#define ZERO_PADDING 8

#define BITSTOBYTES(bits) (((bits)+7)/8)
#define EXPO_TYPE_3 3
#define EXPO_TYPE_65537 65537
#define EXPO_TYPE_R 1

/* print error report after function return */
static void print_error_report(unsigned int rc_sv, int errno_sv,
			       const char *func_name);
/* print bytes in hex */
static void dump_array(const char *array, int size);

extern int errno;

int main(int argc, char **argv)
{
	unsigned int rc = 0, rc_test = 0, expo_type = 0, key_bit_length = 0;
	unsigned int silent = 0;
	struct timeval start,end;

	if(argc < 3){
		printf( "usage: %s <key_bit_length> (57..4096) <exponent_type> "
			"(3, 65537 or r [random])\n", argv[0]);
		return EXIT_FAILURE;
	}

	if((0 == (key_bit_length=strtol(argv[1], &argv[1], 10))) ||
	   ('\0' != *argv[1]) ){
		printf( "error - possible values for"
				" <key_bit_length> are integers"
				" greater than 0.\n");
		return EXIT_FAILURE;
	}

	if(BITSTOBYTES(key_bit_length) < 8){
		printf("error - <key_bit_length> must be at least 57.\n");
		return EXIT_FAILURE;
	}

	if(0 == (strcmp(argv[2], "3")))
		expo_type = EXPO_TYPE_3;
	else if(0 == (strcmp(argv[2], "65537")))
		expo_type = EXPO_TYPE_65537;
	else if(0 == (strcmp(argv[2], "r")))
		expo_type = EXPO_TYPE_R;
	else {
		printf( "error -  possible values for <exponent_type>"
				" are 3, 65537 or r (random)\n");
		return EXIT_FAILURE;
	}

	if (argv[3]) {
		if (strstr(argv[3], "silent"))
			silent = 1;
	}

	unsigned char	ciphertext[BITSTOBYTES(key_bit_length)],
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

	if (!silent) {
		printf("[TEST RSA CRT]\n");
		printf("generate random plaintext\t...");
	}
	if((rc = ica_random_number_generate(BITSTOBYTES(key_bit_length) ,plaintext)) != 0){
		++rc_test;
		print_error_report(rc, errno, "ica_random_number_generate");
	}

	/* make sure that plaintext < modulus */
	plaintext[0] = 0;

	if (!silent) {
		printf("plaintext:\n");
		dump_array((char *)plaintext, BITSTOBYTES(key_bit_length));
	}
	if((rc = ica_open_adapter(&adapter_handle)) != 0){
		++rc_test;
		print_error_report(rc, errno, "ica_open_adapter");
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
		return EXIT_FAILURE;
	} 

	if (!silent) {
		printf("generate keys\t\t\t...\n");
	}

	gettimeofday(&start, NULL);
	if((rc = ica_rsa_key_generate_crt(adapter_handle,
					       key_bit_length,
					       &modexpo_public_key,
					       &crt_private_key)) != 0){
		++rc_test;
		print_error_report(rc, errno, "ica_rsa_key_generate_crt");
	}
	gettimeofday(&end, NULL);
	if (!silent)
		printf("RSA CRT Key_gen with key length %d took: %06lu µs.\n",
				key_bit_length, (end.tv_sec*1000000+end.tv_usec)-
					(start.tv_sec*1000000+start.tv_usec));

	if (!silent) {
		printf("public key (e,n):\ne =\n");
		dump_array((char *) (char *)modexpo_public_key.exponent,
			BITSTOBYTES(key_bit_length));
		printf("n =\n");
		dump_array((char *) (char *)modexpo_public_key.modulus,
			BITSTOBYTES(key_bit_length));
		printf("private key (p,q,dp,dq,q^-1):\np =\n");
		dump_array((char *) (char *) crt_private_key.p,
			BITSTOBYTES(key_bit_length) / 2 + 1 + ZERO_PADDING);
		printf("q =\n");
		dump_array((char *) (char *)crt_private_key.q,
			BITSTOBYTES(key_bit_length) / 2 + 1);
		printf("dp =\n");
		dump_array((char *) (char *)crt_private_key.dp,
			BITSTOBYTES(key_bit_length) / 2 + 1 +ZERO_PADDING);
		printf("dq =\n");
		dump_array((char *) (char *)crt_private_key.dq,
			BITSTOBYTES(key_bit_length) / 2 + 1);
		printf("q^-1 =\n");
		dump_array((char *) (char *)crt_private_key.qInverse,
			BITSTOBYTES(key_bit_length) / 2 + 1 + ZERO_PADDING);
	}

	if (!silent) {
		printf("encrypt...\n");
	}
	if((rc = ica_rsa_mod_expo(adapter_handle, plaintext, &modexpo_public_key, 
				  ciphertext)) != 0){
		++rc_test;
		print_error_report(rc, errno, "ica_rsa_mod_expo");
	}

	if (!silent) {
		printf("ciphertext:\n");
		dump_array((char *) ciphertext, BITSTOBYTES(key_bit_length));
	}

	if (!silent) {
		printf("decrypt...\n");
	}
	if((rc = ica_rsa_crt(adapter_handle, ciphertext, &crt_private_key, 
				  decrypted)) != 0){
		++rc_test;
		print_error_report(rc, errno, "ica_rsa_crt");
	}

	if (!silent) {
		printf("result:\n");
		dump_array((char *) decrypted, BITSTOBYTES(key_bit_length));
	}

	if((rc = ica_close_adapter(adapter_handle)) != 0){
		++rc_test;
		print_error_report(rc, errno, "ica_close_adapter");
	}

	if (!silent) {
		printf("compare ciphertext to plaintext...\n");
	}
	if(memcmp(plaintext,ciphertext,BITSTOBYTES(key_bit_length)) == 0) {
		printf("\t\tFAILED\nerror - ciphertext equals plaintext.\n");
		++rc_test;
	}

	if (!silent) {
		printf("compare result to plaintext...\n");
	}
	if(memcmp(plaintext,decrypted,BITSTOBYTES(key_bit_length)) != 0) {
		printf("\t\tFAILED\nerror - decryption result doesn't match plaintext.\n");
		++rc_test;
	}

	if(0 == rc_test)
		printf("All Keygen tests passed successfully\n");
	else
		printf("Keygen tests failed: %u errors\n",rc_test);

	return rc_test;
}

static void print_error_report(unsigned int rc_sv, int errno_sv,
			       const char *func_name)
{
	printf( "\t\tFAILED\nerror - %s returned %u: ", func_name, rc_sv);
	switch (rc_sv) {
	case EFAULT:
		printf( "the message authentication failed.\n");
		break;
	case EINVAL:
		printf( "incorrect parameter.\n");
		break;
	case EIO:
		printf( "I/O error.\n");
		break;
	case EPERM:
		printf(
			"operation not permitted by hardware (CPACF).\n");
		break;
	case ENODEV:
		printf( "no such device.\n");
		break;
	case ENOMEM:
		printf( "not enough memory.\n");
		break;
	default:
		printf(
			"unknown return code. this shouldn't happen.\n");
	}

	printf( "\terrno ");
	if (0 == errno_sv)
		printf("not set.\n");
	else
		printf("set to %d: %s.\n",
			errno_sv, strerror(errno_sv));
}

static void dump_array(const char *array, int size)
{
	const char *ptr;
	int i = 1;

	ptr = array;
	while (ptr < array+size) {
		printf("0x%02x ",(unsigned char ) *ptr);
		++ptr;
		if (8 == i) {
			printf("\n");
			i = 1;
		} else {
			++i;
		}
	}
	if((i > 1) && (i <= 8))
		printf("\n");
}
