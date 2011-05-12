/* This program is released under the Common Public License V1.0
 *
 * You should have received a copy of Common Public License V1.0 along with
 * with this program.
 */

/* Copyright IBM Corp. 2010, 2011 */
#include <fcntl.h>
#include <sys/errno.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h> 
#include "ica_api.h"

#define NR_RANDOM_TESTS 100

void dump_array(unsigned char *ptr, unsigned int size)
{
	unsigned char *ptr_end;
	unsigned char *h;
	int i = 1;

	h = ptr;
	ptr_end = ptr + size;
	while (h < (unsigned char *)ptr_end) {
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

void dump_ctr_data(unsigned char *iv, unsigned int iv_length,
                   unsigned char *key, unsigned int key_length,
                   unsigned char *input_data, unsigned int data_length,
                   unsigned char *output_data)
{
	printf("IV \n");
	dump_array(iv, iv_length);
	printf("Key \n");
	dump_array(key, key_length);
	printf("Input Data\n");
	dump_array(input_data, data_length);
	printf("Output Data\n");
	dump_array(output_data, data_length);
}

int random_des_ctr(int iteration, int silent, unsigned int data_length, unsigned int iv_length)
{
	unsigned int key_length = sizeof(ica_des_key_single_t);
	if (data_length % sizeof(ica_des_vector_t))
		iv_length = sizeof(ica_des_vector_t);

	printf("Test Parameters for iteration = %i\n", iteration);
	printf("key length = %i, data length = %i, iv length = %i\n",
	       key_length, data_length, iv_length);

	unsigned char iv[iv_length];
	unsigned char tmp_iv[iv_length];
	unsigned char key[key_length];
	unsigned char input_data[data_length];
	unsigned char encrypt[data_length];
	unsigned char decrypt[data_length];

	int rc = 0;
	rc = ica_random_number_generate(data_length, input_data);
	if (rc) {
		printf("random number generate returned rc = %i, errno = %i\n", rc, errno);
		return rc;
	}
	rc = ica_random_number_generate(iv_length, iv);
	if (rc) {
		printf("random number generate returned rc = %i, errno = %i\n", rc, errno);
		return rc;
	}

	rc = ica_random_number_generate(key_length, key);
	if (rc) {
		printf("random number generate returned rc = %i, errno = %i\n", rc, errno);
		return rc;
	}
	memcpy(tmp_iv, iv, iv_length);

	rc = ica_des_ctr(input_data, encrypt, data_length, key, tmp_iv,
			 32,1);
	if (rc) {
		printf("ica_des_ctr encrypt failed with rc = %i\n", rc);
		dump_ctr_data(iv, iv_length, key, key_length, input_data,
			      data_length, encrypt);
		return rc;
	}
	if (!silent && !rc) {
		printf("Encrypt:\n");
		dump_ctr_data(iv, iv_length, key, key_length, input_data,
			      data_length, encrypt);
	}

	memcpy(tmp_iv, iv, iv_length);
	rc = ica_des_ctr(encrypt, decrypt, data_length, key, tmp_iv,
			 32, 0);
	if (rc) {
		printf("ica_des_ctr decrypt failed with rc = %i\n", rc);
		dump_ctr_data(iv, iv_length, key, key_length, encrypt,
			      data_length, decrypt);
		return rc;
	}


	if (!silent && !rc) {
		printf("Decrypt:\n");
		dump_ctr_data(iv, iv_length, key, key_length, encrypt,
			      data_length, decrypt);
	}

	if (memcmp(decrypt, input_data, data_length)) {
		printf("Decryption Result does not match the original data!\n");
		printf("Original data:\n");
		dump_array(input_data, data_length);
		printf("Decryption Result:\n");
		dump_array(decrypt, data_length);
		rc++;
	}
	return rc;
}

int main(int argc, char **argv)
{
	unsigned int silent = 0;
	unsigned int endless = 0;
	if (argc > 1) {
		if (strstr(argv[1], "silent"))
			silent = 1;
		if (strstr(argv[1], "endless"))
			endless = 1;
	}
	int rc = 0;
	int error_count = 0;
	int i = 0;
	unsigned int data_length = sizeof(ica_des_key_single_t);
	unsigned int iv_length = sizeof(ica_des_key_single_t);

	if (endless) {
		silent = 1;
		while (1) {
			printf("i = %i\n",i);
			rc = random_des_ctr(i, silent, 320, 320);
			if (rc) {
				printf("kat_des_ctr failed with rc = %i\n",
					rc);
				return rc;
			} else
				printf("kat_des_ctr finished successfuly\n");
			i++;
		}
	} else {
		for (i = 1; i < NR_RANDOM_TESTS; i++) {
			rc = random_des_ctr(i, silent, data_length, iv_length);
                	if (rc) {
				printf("random_des_ctr failed with rc = %i\n",
				       rc);
				error_count++;
			} else
				printf("random_des_ctr finished "
					"successfuly\n");
			if (!(data_length % sizeof(ica_des_key_single_t))) {
       		 /* Always when the full block size is reached use a
		  * counter with the same size as the data */
	        		rc = random_des_ctr(i, silent,
						    data_length, data_length);
		        	if (rc) {
		        	        printf("random_des_ctr failed with "
					       "rc = %i\n", rc);
		        	        error_count++;
		        	} else
					printf("random_des_ctr finished "
						"successfuly\n");
			}
			data_length++;
		}
	}

	if (error_count)
		printf("%i testcases failed\n", error_count);
	else
		printf("All testcases finished successfully\n");

	return rc;
}

