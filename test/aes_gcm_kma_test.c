/* This program is released under the Common Public License V1.0
 *
 * You should have received a copy of Common Public License V1.0 along with
 * with this program.
 */

/* (C) COPYRIGHT International Business Machines Corp. 2017          */
#include <fcntl.h>
#include <sys/errno.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include "ica_api.h"
#include "testcase.h"
#include "aes_gcm_test.h"

int test_gcm_kat(int iteration)
{
	unsigned int aad_length = gcm_kats[iteration].aadlen;
	unsigned int data_length = gcm_kats[iteration].datalen;
	unsigned int t_length = gcm_kats[iteration].taglen;
	unsigned int iv_length = gcm_kats[iteration].ivlen;
	unsigned int key_length = gcm_kats[iteration].keylen;

	unsigned char* iv = (unsigned char*)&(gcm_kats[iteration].iv);
	unsigned char* input_data = (unsigned char*)&(gcm_kats[iteration].data);
	unsigned char* result = (unsigned char*)&(gcm_kats[iteration].result);
	unsigned char* aad = (unsigned char*)&(gcm_kats[iteration].aad);
	unsigned char* key = (unsigned char*)&(gcm_kats[iteration].key);
	unsigned char* t_result = (unsigned char*)&(gcm_kats[iteration].tag);
	unsigned char t[t_length];

	int rc = 0;

	unsigned int vla_length = data_length ? data_length : 1;

	unsigned char encrypt[vla_length];
	unsigned char decrypt[vla_length];

	VV_(printf("Test Parameters for iteration = %i\n", iteration));
	VV_(printf("key length = %i, data length = %i, tag length = %i,"
	    "iv length = %i aad_length = %i\n", key_length, data_length,
	    t_length, iv_length, aad_length));

	/* Allocate context */
	kma_ctx* ctx = ica_aes_gcm_kma_ctx_new();
	if (!ctx) {
		V_(printf("Error: Cannot create gcm context.\n"));
		return TEST_FAIL;
	}

	/* Initialize context for encrypt */
	rc = ica_aes_gcm_kma_init(ICA_ENCRYPT, iv, iv_length, key, key_length, ctx);
	if (rc) {
		V_(printf("Error: Cannot initialize gcm context.\n"));
		return TEST_FAIL;
	}

	/* Update for encrypt */
	rc = ica_aes_gcm_kma_update(input_data, encrypt, data_length, aad, aad_length, 1, 1, ctx);

	if (rc == ENODEV) {
		VV_(printf("ica_aes_gcm returns with ENODEV (%d).\n", rc));
		VV_(printf("Operation is not permitted on this machine. Test skipped!\n"));
		return TEST_SKIP;
	}

	if (rc) {
		V_(printf("ica_aes_gcm_kma encrypt failed with rc = %i\n", rc));
	}

	if (memcmp(result, encrypt, data_length)) {
		V_(printf("Encryption Result does not match the known ciphertext!\n"));
		VV_(printf("Expected data:\n"));
		dump_array(result, data_length);
		VV_(printf("Encryption Result:\n"));
		dump_array(encrypt, data_length);
		rc++;
	}

	rc = ica_aes_gcm_kma_get_tag(t, t_length, ctx);
	if (memcmp(t, t_result, t_length)) {
		V_(printf("Tag result does not match the expected tag!\n"));
		VV_(printf("Expected tag:\n"));
		dump_array(t_result, t_length);
		VV_(printf("Tag Result:\n"));
		dump_array(t, t_length);
		rc++;
	}

	if (rc) {
		VV_(printf("GCM test exited after encryption\n"));
		return TEST_FAIL;
	}

	/* Initialize context for decrypt */
	rc = ica_aes_gcm_kma_init(ICA_DECRYPT, iv, iv_length, key, key_length, ctx);
	if (rc) {
		V_(printf("Error: Cannot initialize gcm context for decrypt. \n"));
		return TEST_FAIL;
	}

	/* Update for decrypt */
	rc = ica_aes_gcm_kma_update(encrypt, decrypt, data_length, aad, aad_length, 1, 1, ctx);

	if (rc == ENODEV) {
		VV_(printf("ica_aes_gcm returns with ENODEV (%d).\n", rc));
		VV_(printf("Operation is not permitted on this machine. Test skipped!\n"));
		return TEST_SKIP;
	}

	if (rc) {
		VV_(printf("ica_aes_gcm_kma decrypt failed with rc = %i\n", rc));
	}

	if (memcmp(decrypt, input_data, data_length)) {
		V_(printf("Decryption Result does not match the original data!\n"));
		VV_(printf("Original data:\n"));
		dump_array(input_data, data_length);
		VV_(printf("Decryption Result:\n"));
		dump_array(decrypt, data_length);
		rc++;
	}

	rc = ica_aes_gcm_kma_verify_tag(t_result, t_length, ctx);
	if (rc == EFAULT) {
		V_(printf("Tag result does not match the expected tag!\n"));
		rc++;
	}

	ica_aes_gcm_kma_ctx_free(ctx);

	if (rc)
		return TEST_FAIL;

	return TEST_SUCC;
}

int test_gcm_kat_update(int iteration)
{
	unsigned int aad_length_tmp;
	unsigned int aad_length = gcm_kats[iteration].aadlen;
	unsigned int data_length = gcm_kats[iteration].datalen;
	unsigned int t_length = gcm_kats[iteration].taglen;
	unsigned int iv_length = gcm_kats[iteration].ivlen;
	unsigned int key_length = gcm_kats[iteration].keylen;
	unsigned int num_chunks =  gcm_kats[iteration].num_chunks;

	unsigned char* iv = (unsigned char*)&(gcm_kats[iteration].iv);
	unsigned char* input_data = (unsigned char*)&(gcm_kats[iteration].data);
	unsigned char* aad = (unsigned char*)&(gcm_kats[iteration].aad);
	unsigned char* key = (unsigned char*)&(gcm_kats[iteration].key);
	unsigned char* result = (unsigned char*)&(gcm_kats[iteration].result);
	unsigned char* t_result = (unsigned char*)&(gcm_kats[iteration].tag);
	unsigned int chunk_len;
	unsigned int offset;
	unsigned char *chunk_data;
	unsigned char t[t_length];
	int rc = 0;
	unsigned int i;

	unsigned int vla_length = data_length ? data_length : 1;

	unsigned char encrypt[vla_length];
	unsigned char decrypt[vla_length];

	VV_(printf("Test Parameters for iteration = %i\n", iteration));
	VV_(printf("key length = %i, data length = %i, tag length = %i,"
		"iv length = %i aad_length = %i\n", key_length, data_length,
		t_length, iv_length, aad_length));

	aad_length_tmp = aad_length;

	/* Allocate context */
	kma_ctx* ctx = ica_aes_gcm_kma_ctx_new();
	if (!ctx) {
		V_(printf("Error: Cannot create gcm context. \n"));
		return TEST_FAIL;
	}

	/* Initialize context for encrypt */
	rc = ica_aes_gcm_kma_init(ICA_ENCRYPT, iv, iv_length, key, key_length, ctx);
	if (rc) {
		V_(printf("Error: Cannot initialize gcm context. \n"));
		return TEST_FAIL;
	}

	/* Encrypt */
	offset = 0;
	if (num_chunks > 0) {

		for (i = 0; i < num_chunks; i++) {

			chunk_len = gcm_kats[iteration].chunks[i];
			chunk_data = input_data + offset;

			/* Encrypt */
			rc = ica_aes_gcm_kma_update(chunk_data,
						    encrypt + offset,
						    chunk_len,
						    aad, aad_length,
						    1, /* end_of_aad */
						    i == num_chunks - 1 ? 1
									: 0,
						    ctx);
			if (rc)
				break;

			/* clear aad_length after first run*/
			aad_length = 0;
			offset += chunk_len;
		}

	} else {

		rc = ica_aes_gcm_kma_update(input_data, encrypt, 0,
				aad, aad_length,
				1, /* end_of_aad */
				1, /* end_of_data */
				ctx);
	}

	if (rc == ENODEV) {
		VV_(printf("ica_aes_gcm returns with ENODEV (%d).\n", rc));
		VV_(printf("Operation is not permitted on this machine. Test skipped!\n"));
		return TEST_SKIP;
	}

	if (rc) {
		V_(printf("ica_aes_gcm_kma encrypt failed with rc = %i\n", rc));
	}

	if (memcmp(result, encrypt, data_length)) {
		V_(printf("Encryption Result does not match the known ciphertext!\n"));
		VV_(printf("Expected data:\n"));
		dump_array(result, data_length);
		VV_(printf("Encryption Result:\n"));
		dump_array(encrypt, data_length);
		rc++;
	}

	rc = ica_aes_gcm_kma_get_tag(t, t_length, ctx);
	if (memcmp(t, t_result, t_length)) {
		V_(printf("Tag result does not match the expected tag!\n"));
		VV_(printf("Expected tag:\n"));
		dump_array(t_result, t_length);
		VV_(printf("Tag Result:\n"));
		dump_array(t, t_length);
		rc++;
	}

	if (rc) {
		VV_(printf("GCM test exited after encryption\n"));
		return TEST_FAIL;
	}

	/* Decrypt */
	aad_length = aad_length_tmp;
	offset = 0;

	/* Initialize context for decrypt */
	rc = ica_aes_gcm_kma_init(ICA_DECRYPT, iv, iv_length, key, key_length, ctx);
	if (rc) {
		V_(printf("Error: Cannot initialize gcm context for decrypt. \n"));
		return TEST_FAIL;
	}

	if (num_chunks > 0) {

		for (i = 0; i < num_chunks; i++) {
			chunk_len = gcm_kats[iteration].chunks[i];
			chunk_data = encrypt + offset;

			rc = ica_aes_gcm_kma_update(chunk_data,
					decrypt+offset, chunk_len,
					aad, aad_length,
					1, /* end_of_aad */
					i == num_chunks-1 ? 1 : 0,
					ctx);

			if (rc)
				break;

			/* clear aad_length after first run*/
			aad_length = 0;
			offset += chunk_len;
		}

	} else {

		rc = ica_aes_gcm_kma_update(input_data, decrypt, 0,
				aad, aad_length,
				1, /* end_of_aad */
				1, /* end_of_data */
				ctx);
	}

	if (rc == ENODEV) {
		VV_(printf("ica_aes_gcm returns with ENODEV (%d).\n", rc));
		VV_(printf("Operation is not permitted on this machine. Test skipped!\n"));
		return TEST_SKIP;
	}

	if (rc) {
		VV_(printf("ica_aes_gcm decrypt failed with rc = %i\n", rc));
	}

	if (memcmp(decrypt, input_data, data_length)) {
		V_(printf("Decryption Result does not match the original data!\n"));
		VV_(printf("Original data:\n"));
		dump_array(input_data, data_length);
		VV_(printf("Decryption Result:\n"));
		dump_array(decrypt, data_length);
		rc++;
	}

	rc = ica_aes_gcm_kma_verify_tag(t_result, t_length, ctx);
	if (rc == EFAULT) {
		V_(printf("Tag result does not match the expected tag!\n"));
		rc++;
	}

	ica_aes_gcm_kma_ctx_free(ctx);

	if (rc)
		return TEST_FAIL;

	return TEST_SUCC;
}

int test_gcm_kat_update_aad(int iteration)
{
	unsigned int aad_length_tmp;
	unsigned int aad_length = gcm_kats[iteration].aadlen;
	unsigned int data_length = gcm_kats[iteration].datalen;
	unsigned int t_length = gcm_kats[iteration].taglen;
	unsigned int iv_length = gcm_kats[iteration].ivlen;
	unsigned int key_length = gcm_kats[iteration].keylen;
	unsigned int num_chunks =  gcm_kats[iteration].num_chunks;

	unsigned char* iv = (unsigned char*)&(gcm_kats[iteration].iv);
	unsigned char* input_data = (unsigned char*)&(gcm_kats[iteration].data);
	unsigned char* result = (unsigned char*)&(gcm_kats[iteration].result);
	unsigned char* aad = (unsigned char*)&(gcm_kats[iteration].aad);
	unsigned char* key = (unsigned char*)&(gcm_kats[iteration].key);
	unsigned char t[t_length];
	unsigned char* t_result = (unsigned char*)&(gcm_kats[iteration].tag);
	unsigned int chunk_len;
	unsigned int data_offset;
	unsigned int aad_offset;
	unsigned char *chunk_data;
	int rc = 0;
	unsigned int i;

	unsigned int vla_length = data_length ? data_length : 1;

	unsigned char encrypt[vla_length];
	unsigned char decrypt[vla_length];

	VV_(printf("Test Parameters for iteration = %i\n", iteration));
	VV_(printf("key length = %i, data length = %i, tag length = %i,"
		"iv length = %i aad_length = %i\n", key_length, data_length,
		t_length, iv_length, aad_length));

	aad_length_tmp = aad_length;

	/* Allocate context */
	kma_ctx* ctx = ica_aes_gcm_kma_ctx_new();
	if (!ctx) {
		V_(printf("Error: Cannot create gcm context. \n"));
		return TEST_FAIL;
	}

	/* Initialize context for encrypt */
	rc = ica_aes_gcm_kma_init(ICA_ENCRYPT, iv, iv_length, key, key_length, ctx);
	if (rc) {
		V_(printf("Error: Cannot initialize gcm context. \n"));
		return TEST_FAIL;
	}

	/* Process 16-byte aad chunks in advance */
	unsigned int aad_chunklen = 0;
	unsigned int aad_restlen = 0;
	aad_offset = 0;
	while (aad_length >= 16) {

		aad_chunklen = aad_length > 16 ? 16 : aad_length;
		aad_restlen = aad_length > 16 ? aad_length - 16 : 0;

		rc = ica_aes_gcm_kma_update(input_data, encrypt, 0,
				aad+aad_offset, aad_chunklen,
				0,  /* end_of_aad */
				0,  /* end_of_data */
				ctx);

		aad_length = aad_restlen;
		aad_offset += aad_chunklen;
	}

	/* Encrypt data if any, and process last aad if any */
	data_offset = 0;
	if (num_chunks > 0) {

		for (i = 0; i < num_chunks; i++) {
			chunk_len = gcm_kats[iteration].chunks[i];
			chunk_data = input_data + data_offset;

			rc = ica_aes_gcm_kma_update(chunk_data,
					encrypt+data_offset, chunk_len,
					aad+aad_offset, aad_length,
					1, /* end_of_aad */
					i == num_chunks-1 ? 1 : 0,
					ctx);

			/* clear aad_length after first run*/
			aad_length = 0;
			data_offset += chunk_len;
		}

	} else {

		rc = ica_aes_gcm_kma_update(input_data, encrypt, 0,
				aad+aad_offset, aad_length,
				1, /* end_of_aad */
				1, /* end_of_data */
				ctx);
	}

	if (rc == ENODEV) {
		VV_(printf("ica_aes_gcm returns with ENODEV (%d).\n", rc));
		VV_(printf("Operation is not permitted on this machine. Test skipped!\n"));
		return TEST_SKIP;
	}

	if (rc) {
		V_(printf("ica_aes_gcm_kma encrypt failed with rc = %i\n", rc));
	}

	if (memcmp(result, encrypt, data_length)) {
		V_(printf("Encryption Result does not match the known ciphertext!\n"));
		VV_(printf("Expected data:\n"));
		dump_array(result, data_length);
		VV_(printf("Encryption Result:\n"));
		dump_array(encrypt, data_length);
		rc++;
	}

	rc = ica_aes_gcm_kma_get_tag(t, t_length, ctx);
	if (memcmp(t, t_result, t_length)) {
		V_(printf("Tag result does not match the expected tag!\n"));
		VV_(printf("Expected tag:\n"));
		dump_array(t_result, t_length);
		VV_(printf("Tag Result:\n"));
		dump_array(t, t_length);
		rc++;
	}

	if (rc) {
		VV_(printf("GCM test exited after encryption\n"));
		return TEST_FAIL;
	}

	/* Decryption */
	aad_length = aad_length_tmp;
	data_offset = 0;

	/* 5. Initialize context for decrypt */
	rc = ica_aes_gcm_kma_init(ICA_DECRYPT, iv, iv_length, key, key_length, ctx);
	if (rc) {
		V_(printf("Error: Cannot initialize gcm context for decrypt. \n"));
		return TEST_FAIL;
	}

	if (num_chunks > 0) {

		for (i = 0; i < num_chunks; i++) {
			chunk_len = gcm_kats[iteration].chunks[i];
			chunk_data = encrypt + data_offset;

			rc = ica_aes_gcm_kma_update(chunk_data, decrypt+data_offset, chunk_len,
					aad, aad_length,
					1, /* end_of_aad */
					i == num_chunks-1 ? 1 : 0,
					ctx);

			/* clear aad_length after first run*/
			aad_length = 0;
			data_offset += chunk_len;
		}

	} else {

		rc = ica_aes_gcm_kma_update(input_data, decrypt, 0,
				aad, aad_length,
				1, /* end_of_aad */
				1, /* end_of_data */
				ctx);
	}

	if (rc == ENODEV) {
		VV_(printf("ica_aes_gcm returns with ENODEV (%d).\n", rc));
		VV_(printf("Operation is not permitted on this machine. Test skipped!\n"));
		return TEST_SKIP;
	}

	if (rc) {
		VV_(printf("ica_aes_gcm decrypt failed with rc = %i\n", rc));
	}

	if (memcmp(decrypt, input_data, data_length)) {
		V_(printf("Decryption Result does not match the original data!\n"));
		VV_(printf("Original data:\n"));
		dump_array(input_data, data_length);
		VV_(printf("Decryption Result:\n"));
		dump_array(decrypt, data_length);
		rc++;
	}

	rc = ica_aes_gcm_kma_verify_tag(t_result, t_length, ctx);
	if (rc == EFAULT) {
		V_(printf("Tag result does not match the expected tag!\n"));
		rc++;
	}

	ica_aes_gcm_kma_ctx_free(ctx);

	if (rc)
		return TEST_FAIL;

	return TEST_SUCC;
}

int test_gcm_kat_update_in_place(int iteration)
{
	unsigned int aad_length_tmp;
	unsigned int aad_length = gcm_kats[iteration].aadlen;
	unsigned int data_length = gcm_kats[iteration].datalen;
	unsigned int t_length = gcm_kats[iteration].taglen;
	unsigned int iv_length = gcm_kats[iteration].ivlen;
	unsigned int key_length = gcm_kats[iteration].keylen;
	unsigned int num_chunks =  gcm_kats[iteration].num_chunks;

	unsigned char* iv = (unsigned char*)&(gcm_kats[iteration].iv);
	unsigned char* input_data = (unsigned char*)&(gcm_kats[iteration].data);
	unsigned char* result = (unsigned char*)&(gcm_kats[iteration].result);
	unsigned char* aad = (unsigned char*)&(gcm_kats[iteration].aad);
	unsigned char* key = (unsigned char*)&(gcm_kats[iteration].key);
	unsigned char* t_result = (unsigned char*)&(gcm_kats[iteration].tag);
	unsigned int chunk_len;
	unsigned int offset;
	unsigned char *chunk_data;
	unsigned char save_input[MAX_ARRAY_SIZE];
	unsigned char t[t_length];
	int rc = 0;
	unsigned int i;

	VV_(printf("Test Parameters for iteration = %i\n", iteration));
	VV_(printf("key length = %i, data length = %i, tag length = %i,"
		"iv length = %i aad_length = %i\n", key_length, data_length,
		t_length, iv_length, aad_length));

	aad_length_tmp = aad_length;

	/* Allocate context */
	kma_ctx* ctx = ica_aes_gcm_kma_ctx_new();
	if (!ctx) {
		V_(printf("Error: Cannot create gcm context. \n"));
		return TEST_FAIL;
	}

	/* Initialize context for encrypt */
	rc = ica_aes_gcm_kma_init(ICA_ENCRYPT, iv, iv_length, key, key_length, ctx);
	if (rc) {
		V_(printf("Error: Cannot initialize gcm context. \n"));
		return TEST_FAIL;
	}

	/* Encrypt */
	memcpy(save_input, input_data, data_length);
	offset = 0;
	if (num_chunks > 0) {

		for (i = 0; i < num_chunks; i++) {

			chunk_len = gcm_kats[iteration].chunks[i];
			chunk_data = input_data + offset;

			/* Encrypt */
			rc = ica_aes_gcm_kma_update(chunk_data, chunk_data, chunk_len,
					aad, aad_length,
					1, /* end_of_aad */
					i == num_chunks-1 ? 1 : 0,
					ctx);

			/* clear aad_length after first run*/
			aad_length = 0;
			offset += chunk_len;
		}

	} else {

		rc = ica_aes_gcm_kma_update(input_data, input_data, 0,
				aad, aad_length,
				1, /* end_of_aad */
				1, /* end_of_data */
				ctx);
	}

	if (rc == ENODEV) {
		VV_(printf("ica_aes_gcm returns with ENODEV (%d).\n", rc));
		VV_(printf("Operation is not permitted on this machine. Test skipped!\n"));
		return TEST_SKIP;
	}

	if (rc) {
		V_(printf("ica_aes_gcm_kma encrypt failed with rc = %i\n", rc));
	}

	if (memcmp(result, input_data, data_length)) {
		V_(printf("Encryption Result does not match the known ciphertext!\n"));
		VV_(printf("Expected data:\n"));
		dump_array(result, data_length);
		VV_(printf("Encryption Result:\n"));
		dump_array(input_data, data_length);
		rc++;
	}

	rc = ica_aes_gcm_kma_get_tag(t, t_length, ctx);
	if (memcmp(t, t_result, t_length)) {
		V_(printf("Tag result does not match the expected tag!\n"));
		VV_(printf("Expected tag:\n"));
		dump_array(t_result, t_length);
		VV_(printf("Tag Result:\n"));
		dump_array(t, t_length);
		rc++;
	}

	if (rc) {
		VV_(printf("GCM test exited after encryption\n"));
		return TEST_FAIL;
	}

	/* Decryption */
	aad_length = aad_length_tmp;
	offset = 0;

	/* 4. Initialize context for decrypt */
	rc = ica_aes_gcm_kma_init(ICA_DECRYPT, iv, iv_length, key, key_length, ctx);
	if (rc) {
		V_(printf("Error: Cannot initialize gcm context for decrypt. \n"));
		return TEST_FAIL;
	}

	if (num_chunks > 0) {

		for (i = 0; i < num_chunks; i++) {
			chunk_len = gcm_kats[iteration].chunks[i];
			chunk_data = input_data + offset;

			rc = ica_aes_gcm_kma_update(chunk_data, chunk_data , chunk_len,
					aad, aad_length,
					1, /* end_of_aad */
					i == num_chunks-1 ? 1 : 0,
					ctx);

			/* clear aad_length after first run*/
			aad_length = 0;
			offset += chunk_len;
		}

	} else {

		rc = ica_aes_gcm_kma_update(input_data, input_data, 0,
				aad, aad_length,
				1, /* end_of_aad */
				1, /* end_of_data */
				ctx);
	}

	if (rc == ENODEV) {
		VV_(printf("ica_aes_gcm returns with ENODEV (%d).\n", rc));
		VV_(printf("Operation is not permitted on this machine. Test skipped!\n"));
		return TEST_SKIP;
	}

	if (rc) {
		VV_(printf("ica_aes_gcm decrypt failed with rc = %i\n", rc));
	}

	if (memcmp(save_input, input_data, data_length)) {
		V_(printf("Decryption Result does not match the original data!\n"));
		VV_(printf("Original data:\n"));
		dump_array(save_input, data_length);
		VV_(printf("Decryption Result:\n"));
		dump_array(input_data, data_length);
		rc++;
	}

	rc = ica_aes_gcm_kma_verify_tag(t_result, t_length, ctx);
	if (rc == EFAULT) {
		V_(printf("Tag result does not match the expected tag!\n"));
		rc++;
	}

	ica_aes_gcm_kma_ctx_free(ctx);

	if (rc)
		return TEST_FAIL;

	return TEST_SUCC;
}

/*
 * Performs GCM tests.
 */
int main(int argc, char **argv)
{
	int rc = 0;
	int error_count = 0;
	unsigned int iteration;

	set_verbosity(argc, argv);

	for(iteration = 0; iteration < NUM_GCM_TESTS; iteration++)	{

		rc = test_gcm_kat(iteration);
		if (rc) {
			V_(printf("test_gcm_kat %i failed with rc = %i\n", iteration, rc));
			error_count++;
		}

		rc = test_gcm_kat_update(iteration);
		if (rc) {
			V_(printf("test_gcm_kat_update %i failed with rc = %i\n", iteration, rc));
			error_count++;
		}

		rc = test_gcm_kat_update_aad(iteration);
		if (rc) {
			V_(printf("test_gcm_kat_update_aad %i failed with rc = %i\n", iteration, rc));
			error_count++;
		}

		rc = test_gcm_kat_update_in_place(iteration);
		if (rc) {
			V_(printf("test_gcm_kat_update_in_place %i failed with rc = %i\n", iteration, rc));
			error_count++;
		}
	}

	if (error_count) {
		printf("%i of %li AES-GCM-KMA tests failed.\n", error_count, NUM_GCM_TESTS*4);
		return TEST_FAIL;
	}

	printf("All AES-GCM-KMA tests passed.\n");
	return TEST_SUCC;
}
