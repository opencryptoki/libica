/* This program is released under the Common Public License V1.0
 *
 * You should have received a copy of Common Public License V1.0 along with
 * with this program.
 */

/* (C) COPYRIGHT International Business Machines Corp. 2001, 2009          */
#include <sys/errno.h>
#include <fcntl.h>
#include <memory.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include "ica_api.h"

#define KEY_BYTES ((key_bits + 7) / 8)
#define KEY_BYTES_MAX 256

extern int errno;

void dump_array(char *ptr, int size)
{
	char *ptr_end;
	char *h;
	int i = 1;

	h = ptr;
	ptr_end = ptr + size;
	while (h < ptr_end) {
		printf("0x%02x ",(unsigned char ) *h);
		h++;
		if (i == 8) {
			printf("\n");
			i = 1;
		} else {
			++i;
		}
	}
	printf("\n");
}


int main(int argc, char **argv)
{
	ICA_ADAPTER_HANDLE adapter_handle;
	ICA_KEY_RSA_CRT crtkey;
	ICA_KEY_RSA_MODEXPO wockey, wockey2;
	unsigned char decrypted[KEY_BYTES_MAX], encrypted[KEY_BYTES_MAX],
		      original[KEY_BYTES_MAX];
	int rc;
	unsigned int length, length2;
	unsigned int exponent_type = RSA_PUBLIC_FIXED, key_bits = 1024;

	length = sizeof wockey;
	length2 = sizeof wockey2;
	bzero(&wockey, sizeof wockey);
	bzero(&wockey2, sizeof wockey2);

	rc = icaOpenAdapter(0, &adapter_handle);
	if (rc != 0) {
		printf("icaOpenAdapter failed and returned %d (0x%x).\n", rc,
		       rc);
	}
	exponent_type = RSA_PUBLIC_FIXED;
	printf("a fixed exponent . . .\n");
	rc = icaRandomNumberGenerate(adapter_handle, KEY_BYTES,
				     wockey.keyRecord);
	if (rc != 0) {
	      	printf("icaRandomNumberGenerate failed and returned %d (0x%x)"
		       ".\n", rc, rc);
		return -1;   	
	}		
	wockey.nLength = KEY_BYTES / 2;
	wockey.expLength = sizeof(unsigned long);
 	wockey.expOffset = SZ_HEADER_MODEXPO;
	wockey.keyRecord[wockey.expLength - 1] |= 1;
	if (argc > 1) {
		key_bits = atoi(argv[1]);
		if (key_bits > KEY_BYTES_MAX * 8) {
			printf("The maximum key length is %d bits.\n",
			       KEY_BYTES_MAX * 8);
			exit(1);
		}
		wockey.modulusBitLength = key_bits;
		printf("Using %u-bit keys and ", key_bits);
		if (argc > 2) {
			switch (argv[2][0]) {
			case '3':
				exponent_type = RSA_PUBLIC_3;
				printf("exponent 3 . . .\n");
				wockey.expLength = 1;
				break;
			case '6':
				exponent_type = RSA_PUBLIC_65537;
				printf("exponent 65537 . . .\n");
				wockey.expLength = 3;
				break;
			case 'R':
			case 'r':
				exponent_type = RSA_PUBLIC_RANDOM;
				printf("a random exponent . . .\n");
				break;
			default:
				printf("Usage: %s <key_lenght_in_bits> <exponent_type>\n", argv[0]);
				printf("<exponent_type>: 3, 65537 or r(andom)\n");
				exit(1);
			}
		} else {
			printf("Usage: %s <key_lenght_in_bits> <exponent_type>\n", argv[0]);
			printf("<exponent_type>: 3, 65537 or r(andom)\n");
			exit(1);
		}
	} else {
		printf("Usage: %s <key_lenght_in_bits> <exponent_type>\n", argv[0]);
		printf("<exponent_type>: 3, 65537 or r(andom)\n");
		exit(1);
	}

	rc = icaRandomNumberGenerate(adapter_handle, sizeof(original),
				     original);
	if (rc != 0) {
		printf("icaRandomNumberGenerate failed and returned %d (0x%x)"
		       ".\n", rc, rc);
		return rc;
	}
	original[0] = 0;

	rc = icaRsaKeyGenerateModExpo(adapter_handle, key_bits, exponent_type,
				      &length, &wockey, &length2, &wockey2);
	if (rc != 0) {
		printf("icaRsaKeyGenerateModExpo failed and returned %d (0x%x)"
		       ".\n", rc, rc);
		return rc;
	}

	printf("Public key:\n");
	dump_array((char *) wockey.keyRecord, 2 * KEY_BYTES);
	printf("Private key:\n");
	dump_array((char *) wockey2.keyRecord, 2 * KEY_BYTES);

	bzero(encrypted, KEY_BYTES);
	length = KEY_BYTES;
	printf("encrypt \n");
	rc = icaRsaModExpo(adapter_handle, KEY_BYTES, original, &wockey,
			   &length, encrypted);
	if (rc != 0) {
		printf("icaRsaModExpo failed and returned %d (0x%x).\n", rc, rc);
		return rc;  
	}
	bzero(decrypted, KEY_BYTES);
	length = KEY_BYTES;
	printf("decrypt \n");
	rc = icaRsaModExpo(adapter_handle, KEY_BYTES, encrypted, &wockey2,
			   &length, decrypted);
	if (rc != 0) {
		printf("icaRsaModExpo failed and returned %d (0x%x).\n", rc,
		       rc);
		return rc;
	}

	printf("Original:\n");
	dump_array((char *) original, KEY_BYTES);
	printf("Result of encrypt:\n");
	dump_array((char *) encrypted, KEY_BYTES);
	printf("Result of decrypt:\n");
	dump_array((char *) decrypted, KEY_BYTES);
	if (memcmp(original, decrypted, KEY_BYTES) != 0) {
		printf("This does not match the original plaintext.  Failure!\n");
		icaCloseAdapter(adapter_handle);
		return errno ? errno : -1;
	} else {
		printf("Success!  The key pair checks out.\n");
		if (memcmp(original, encrypted, KEY_BYTES) == 0) {
			printf("But the ciphertext equals the plaintext."
			       "That can't be good.\n");
			return -1;
		}
	}
	fflush(stdout);

	length = sizeof wockey;
	length2 = sizeof crtkey;
	bzero(&wockey, sizeof wockey);
	wockey.expLength = sizeof(unsigned long);
	if (exponent_type == RSA_PUBLIC_FIXED) {
		wockey.keyType = KEYTYPE_MODEXPO;
		wockey.keyLength = sizeof wockey;
		wockey.modulusBitLength = key_bits;
		wockey.nLength = KEY_BYTES;
		wockey.expOffset = SZ_HEADER_MODEXPO;
		wockey.expLength = sizeof (unsigned long);
		wockey.nOffset = KEY_BYTES + wockey.expOffset;
		rc = icaRandomNumberGenerate(adapter_handle, KEY_BYTES,
					     wockey.keyRecord);
		if (rc != 0) {
			printf("icaRandomNumberGenerate failed and returned %d"
			       "(0x%x).\n", rc, rc);
			return rc;
		}
		wockey.keyRecord[wockey.expLength - 1] |= 1;
	}
	rc = icaRsaKeyGenerateCrt(adapter_handle, key_bits, exponent_type,
				  &length, &wockey, &length2, &crtkey);
	printf("wockey.modulusBitLength = %i, crtkey.modulusBitLength = %i"
	       " \n", wockey.modulusBitLength, crtkey.modulusBitLength);
	if (rc != 0) {
		printf("icaRsaKeyGenerateCrt failed and returned %d (0x%x)"
		       ".\n", rc, rc);
		return rc;
	}

	printf("Public key:\n");
	dump_array((char *) wockey.keyRecord, 2 * KEY_BYTES);
	printf("Private key:\n");
	dump_array((char *) crtkey.keyRecord, 5 * KEY_BYTES / 2 + 24);

	bzero(encrypted, KEY_BYTES);
	length = KEY_BYTES;
	rc = icaRsaModExpo(adapter_handle, KEY_BYTES, original, &wockey,
			   &length, encrypted);
	if (rc != 0)
		printf("icaRsaModExpo failed and returned %d (0x%x).\n", rc, rc);

	bzero(decrypted, KEY_BYTES);
	length = KEY_BYTES;
	rc = icaRsaCrt(adapter_handle, KEY_BYTES, encrypted, &crtkey, &length,
		       decrypted);
	if (rc != 0)
		printf("icaRsaCrt failed and returned %d (0x%x).\n", rc, rc);

	printf("Original:\n");
	dump_array((char *) original, KEY_BYTES);
	printf("Result of encrypt:\n");
	dump_array((char *) encrypted, KEY_BYTES);
	printf("Result of decrypt:\n");
	dump_array((char *) decrypted, KEY_BYTES);
	if (memcmp(original, decrypted, KEY_BYTES) != 0) {
		printf("This does not match the original plaintext.  Failure!\n");
		icaCloseAdapter(adapter_handle);
		return errno ? errno : -1;
	} else {
		printf("Success!  The key pair checks out.\n");
		if (memcmp(original, encrypted, KEY_BYTES) == 0) {
			printf("But the ciphertext equals the plaintext.  That can't be good.\n");
			return -1;
		}
	}
	fflush(stdout);

	printf("TEST NEW API - MOD_EXPO\n");
	rc = ica_close_adapter(adapter_handle);
	printf("ica_close_adapter rc = %i\n", rc);
	
	rc = ica_open_adapter(&adapter_handle);
	if (rc)
		printf("Adapter not open\n");
	else
		printf("Adapter open\n");

	ica_rsa_key_mod_expo_t modexpo_public_key;
	unsigned char modexpo_public_n[KEY_BYTES];
	bzero(modexpo_public_n, KEY_BYTES);
	unsigned char modexpo_public_e[KEY_BYTES];	
	bzero(modexpo_public_e, KEY_BYTES);
	modexpo_public_key.modulus = modexpo_public_n;
	modexpo_public_key.exponent = modexpo_public_e;
	modexpo_public_key.key_length = KEY_BYTES;
	if (exponent_type == RSA_PUBLIC_65537)
		*(unsigned long*)((unsigned char *)modexpo_public_key.exponent +
				modexpo_public_key.key_length -
				sizeof(unsigned long)) = 65537;
	if (exponent_type == RSA_PUBLIC_3)
		*(unsigned long*)((unsigned char *)modexpo_public_key.exponent +
				modexpo_public_key.key_length -
				sizeof(unsigned long)) = 3;

	ica_rsa_key_mod_expo_t modexpo_private_key;
	unsigned char modexpo_private_n[KEY_BYTES];
	bzero(modexpo_private_n, KEY_BYTES);
	unsigned char modexpo_private_e[KEY_BYTES];	
	bzero(modexpo_private_e, KEY_BYTES);
	modexpo_private_key.modulus = modexpo_private_n;
	modexpo_private_key.exponent = modexpo_private_e;
	modexpo_private_key.key_length = KEY_BYTES;

	rc = ica_rsa_key_generate_mod_expo(adapter_handle,
					   key_bits,
					   &modexpo_public_key,
					   &modexpo_private_key);
	if (rc)
		printf("ica_rsa_key_generate_mod_expo rc = %i\n",rc);

	printf("Public key:\n");
	dump_array((char *) (char *)modexpo_public_key.exponent, KEY_BYTES);
	dump_array((char *) (char *)modexpo_public_key.modulus, KEY_BYTES);
	printf("Private key:\n");
	dump_array((char *) (char *)modexpo_private_key.exponent, KEY_BYTES);
	dump_array((char *) (char *)modexpo_private_key.modulus, KEY_BYTES);

	bzero(encrypted, KEY_BYTES);
	length = KEY_BYTES;
	printf("encrypt \n");
	rc = ica_rsa_mod_expo(adapter_handle, original, &modexpo_public_key,
			      encrypted);

	if (rc != 0) {
		printf("ica_rsa_mod_expo failed and returned %d (0x%x).\n", rc,
		       rc);
		return rc;
	}
	bzero(decrypted, KEY_BYTES);
	length = KEY_BYTES;
	printf("decrypt \n");
	rc = ica_rsa_mod_expo(adapter_handle, encrypted, &modexpo_private_key,
			      decrypted);
	if (rc != 0) {
		printf("ica_rsa_mod_expo failed and returned %d (0x%x).\n", rc,
		       rc);
		return rc;
	}

	printf("Original:\n");
	dump_array((char *) original, KEY_BYTES);
	printf("Result of encrypt:\n");
	dump_array((char *) encrypted, KEY_BYTES);
	printf("Result of decrypt:\n");
	dump_array((char *) decrypted, KEY_BYTES);
	if (memcmp(original, decrypted, KEY_BYTES) != 0) {
		printf("This does not match the original plaintext.  Failure!\n");
		return -1;
	} else {
		printf("Success!  The key pair checks out.\n");
		if (memcmp(original, encrypted, KEY_BYTES) == 0) {
			printf("But the ciphertext equals the plaintext.  That can't be good.\n");
			return -1;
		}
	}
	fflush(stdout);

	printf("TEST NEW API - CRT\n");
	ica_rsa_key_mod_expo_t public_key;
	ica_rsa_key_crt_t private_key;

	unsigned char public_n[KEY_BYTES];	
	bzero(public_n, KEY_BYTES);
	unsigned char public_e[KEY_BYTES];	
	bzero(public_e, KEY_BYTES);
	public_key.modulus = public_n;
	public_key.exponent = public_e;
	public_key.key_length = KEY_BYTES;

	unsigned char private_p[(key_bits + 7) / (8 * 2) + 8];
	bzero(private_p, KEY_BYTES + 1);
	unsigned char private_q[(key_bits + 7) / (8 * 2)];
	bzero(private_q, KEY_BYTES);
	unsigned char private_dp[(key_bits + 7) / (8 * 2) + 8];
	bzero(private_dp, KEY_BYTES + 1);
	unsigned char private_dq[(key_bits + 7) / (8 * 2)];
	bzero(private_dq, KEY_BYTES);
	unsigned char private_qInverse[(key_bits + 7) / (8 * 2) + 8];
	bzero(private_qInverse, KEY_BYTES + 1);
	private_key.p = private_p;
	private_key.q = private_q;
	private_key.dp = private_dp;
	private_key.dq = private_dq;
	private_key.qInverse = private_qInverse;
	private_key.key_length = (key_bits + 7) / 8;

	if (exponent_type == RSA_PUBLIC_65537)
                *(unsigned long*)((unsigned char *)public_key.exponent +
                                public_key.key_length -
                                sizeof(unsigned long)) = 65537;
        if (exponent_type == RSA_PUBLIC_3)
                *(unsigned long*)((unsigned char *)public_key.exponent +
                                public_key.key_length -
                                sizeof(unsigned long)) = 3;
	
	rc = ica_rsa_key_generate_crt(adapter_handle, key_bits, &public_key,
				      &private_key);
	if (rc != 0) {
		printf("ica_rsa_key_generate_crt failed and returned %d (0x%x)"
		       ".\n", rc, rc);
		return rc;
	}
	
	printf("Public key:\n");
	dump_array((char *) (char *)&public_key, 2 * KEY_BYTES);
	printf("Private key:\n");
	dump_array((char *) (char *)&private_key, 5 * KEY_BYTES / 2 + 24);

	bzero(encrypted, KEY_BYTES);
	length = KEY_BYTES;
	rc = ica_rsa_mod_expo(adapter_handle, original, &public_key, encrypted);
	if (rc != 0) {
		printf("ica_rsa_mod_expo failed and returned %d (0x%x).\n",
		       rc, rc);
		return rc;
	}
	bzero(decrypted, KEY_BYTES);
	length = KEY_BYTES;
	rc = ica_rsa_crt(adapter_handle, encrypted, &private_key, decrypted);
	if (rc != 0) {
		printf("icaRsaCrt failed and returned %d (0x%x).\n", rc, rc);
		return rc;
	}

	printf("Original:\n");
	dump_array((char *) original, KEY_BYTES);
	printf("Result of encrypt:\n");
	dump_array((char *) encrypted, KEY_BYTES);
	printf("Result of decrypt:\n");
	dump_array((char *) decrypted, KEY_BYTES);
	if (memcmp(original, decrypted, KEY_BYTES) != 0) {
		printf("This does not match the original plaintext."
		       "Failure!\n");
	} else {
		printf("Success!  The key pair checks out.\n");
		if (memcmp(original, encrypted, KEY_BYTES) == 0) {
			printf("But the ciphertext equals the plaintext."
			       "That can't be good.\n");
		}
	}
	fflush(stdout);
	ica_close_adapter(adapter_handle);
	return 0;
}

