/* This program is released under the Common Public License V1.0
 *
 * You should have received a copy of Common Public License V1.0 along with
 * with this program.
 */

/* (C) COPYRIGHT International Business Machines Corp. 2011          */
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
	unsigned char t[t_length];
	unsigned char* t_result = (unsigned char*)&(gcm_kats[iteration].tag);

	int rc = 0;
	unsigned int vla_length = data_length ? data_length : 1;

	unsigned char encrypt[vla_length];
	unsigned char decrypt[vla_length];

	VV_(printf("Test Parameters for iteration = %i\n", iteration));
	VV_(printf("key length = %i, data length = %i, tag length = %i,"
	    "iv length = %i aad_length = %i\n", key_length, data_length,
	    t_length, iv_length, aad_length));

	rc = ica_aes_gcm(input_data, data_length,
			 encrypt,
			 iv, iv_length,
			 aad, aad_length,
			 t, t_length,
			 key, key_length,
			 ICA_ENCRYPT);
	if (rc == EPERM) {
		VV_(printf("ica_aes_gcm returns with EPERM (%d).\n", rc));
		VV_(printf("Operation is not permitted on this machine. Test skipped!\n"));
		return TEST_SKIP;
	}
	if (rc) {
		V_(printf("ica_aes_gcm encrypt failed with rc = %i\n", rc));
		dump_gcm_data(iv, iv_length, aad, aad_length, key, key_length,
			      input_data, data_length, encrypt, t, t_length);
	}
	if (!rc) {
		VV_(printf("Encrypt:\n"));
		dump_gcm_data(iv, iv_length, aad, aad_length, key, key_length,
			      input_data, data_length, encrypt, t,
			      t_length);
	}

	if (memcmp(result, encrypt, data_length)) {
		V_(printf("Encryption Result does not match the known ciphertext!\n"));
		VV_(printf("Expected data:\n"));
		dump_array(result, data_length);
		VV_(printf("Encryption Result:\n"));
		dump_array(encrypt, data_length);
		rc++;
	}
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
	rc = ica_aes_gcm(decrypt, data_length,
			 encrypt,
			 iv, iv_length,
			 aad, aad_length,
			 t, t_length,
			 key, key_length,
			 ICA_DECRYPT);
	if (rc == EPERM) {
		VV_(printf("ica_aes_gcm returns with EPERM (%d).\n", rc));
		VV_(printf("Operation is not permitted on this machine. Test skipped!\n"));
		return TEST_SKIP;
	}
	if (rc) {
		VV_(printf("ica_aes_gcm decrypt failed with rc = %i\n", rc));
		dump_gcm_data(iv, iv_length, aad, aad_length, key, key_length,
			      encrypt, data_length, decrypt, t,
			      t_length);
	}


	if (!rc) {
		VV_(printf("Decrypt:\n"));
		dump_gcm_data(iv, iv_length, aad, aad_length, key, key_length,
			      encrypt, data_length, decrypt, t,
			      t_length);
	}

	if (memcmp(decrypt, input_data, data_length)) {
		V_(printf("Decryption Result does not match the original data!\n"));
		VV_(printf("Original data:\n"));
		dump_array(input_data, data_length);
		VV_(printf("Decryption Result:\n"));
		dump_array(decrypt, data_length);
		rc++;
	}
	if (memcmp(t, t_result, t_length)) {
		V_(printf("Tag result does not match the expected tag!\n"));
		VV_(printf("Expected tag:\n"));
		dump_array(t_result, t_length);
		VV_(printf("Tag Result:\n"));
		dump_array(t, t_length);
		rc++;
	}

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
	unsigned char* result = (unsigned char*)&(gcm_kats[iteration].result);
	unsigned char* aad = (unsigned char*)&(gcm_kats[iteration].aad);
	unsigned char* key = (unsigned char*)&(gcm_kats[iteration].key);
	unsigned char t[t_length];
	unsigned char* t_result = (unsigned char*)&(gcm_kats[iteration].tag);
	unsigned int chunk_len;
	unsigned int offset;
	unsigned char *chunk_data;
	unsigned char icb[AES_BLOCK_SIZE];
	unsigned char ucb[AES_BLOCK_SIZE];
	unsigned char subkey[AES_BLOCK_SIZE];
	unsigned char running_tag[AES_BLOCK_SIZE];
	unsigned int  sum_A_len;
	unsigned int  sum_C_len;
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
	memset(running_tag, 0, AES_BLOCK_SIZE);
	rc = ica_aes_gcm_initialize(iv, iv_length, key, key_length,
								icb, ucb, subkey, ICA_ENCRYPT);

	if (num_chunks == 0 && aad_length > 0) {
		rc = ica_aes_gcm_intermediate(input_data, 0, encrypt,
								  ucb, aad, aad_length,
								  running_tag, AES_BLOCK_SIZE,
								  key, key_length, subkey, ICA_ENCRYPT);
	}

	offset = 0;
	for (i = 0; i < num_chunks; i++) {
		chunk_len = gcm_kats[iteration].chunks[i];
		chunk_data = input_data + offset;

		rc = ica_aes_gcm_intermediate(chunk_data, chunk_len, encrypt + offset,
									  ucb, aad, aad_length,
									  running_tag, AES_BLOCK_SIZE,
									  key, key_length, subkey, ICA_ENCRYPT);
		/* clear aad_length after first run*/
		aad_length = 0;
		offset += chunk_len;
	}
	sum_A_len = aad_length_tmp;
	sum_C_len = offset;
	rc = ica_aes_gcm_last(icb, sum_A_len, sum_C_len, running_tag,
						  t, t_length, key, key_length, subkey, ICA_ENCRYPT);

	if (rc == EPERM) {
		VV_(printf("ica_aes_gcm returns with EPERM (%d).\n", rc));
		VV_(printf("Operation is not permitted on this machine. Test skipped!\n"));
		return TEST_SKIP;
	}
	if (rc) {
		VV_(printf("ica_aes_gcm encrypt failed with rc = %i\n", rc));
		dump_gcm_data(iv, iv_length, aad, aad_length, key, key_length,
			      input_data, data_length, encrypt, t, t_length);
	}
	if (!rc) {
		VV_(printf("Encrypt:\n"));
		dump_gcm_data(iv, iv_length, aad, aad_length, key, key_length,
			      input_data, data_length, encrypt, running_tag,
			      t_length);
	}

	if (memcmp(result, encrypt, data_length)) {
		V_(printf("Encryption Result does not match the known ciphertext!\n"));
		VV_(printf("Expected data:\n"));
		dump_array(result, data_length);
		VV_(printf("Encryption Result:\n"));
		dump_array(encrypt, data_length);
		rc++;
	}
	if (memcmp(running_tag, t_result, t_length)) {
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

	aad_length = aad_length_tmp;
	memset(running_tag, 0, AES_BLOCK_SIZE);
	rc = ica_aes_gcm_initialize(iv, iv_length, key, key_length,
								icb, ucb, subkey, ICA_DECRYPT);

	if (num_chunks == 0 && aad_length > 0) {
		rc = ica_aes_gcm_intermediate(input_data, 0, encrypt,
								  ucb, aad, aad_length,
								  running_tag, AES_BLOCK_SIZE,
								  key, key_length, subkey, ICA_DECRYPT);
	}

	offset = 0;
	for (i = 0; i < num_chunks; i++) {
		chunk_len = gcm_kats[iteration].chunks[i];
		chunk_data = encrypt + offset;

		rc = ica_aes_gcm_intermediate(decrypt + offset, chunk_len, chunk_data,
									  ucb, aad, aad_length,
									  running_tag, AES_BLOCK_SIZE,
									  key, key_length, subkey, ICA_DECRYPT);

		/* clear aad_length after first run*/
		aad_length = 0;
		offset += chunk_len;
	}
	sum_A_len = aad_length_tmp;
	sum_C_len = offset;
	rc = ica_aes_gcm_last(icb, sum_A_len, sum_C_len, running_tag,
						  t_result, t_length, key, key_length, subkey, ICA_DECRYPT);


	if (rc == EPERM) {
		VV_(printf("ica_aes_gcm returns with EPERM (%d).\n", rc));
		VV_(printf("Operation is not permitted on this machine. Test skipped!\n"));
		return TEST_SKIP;
	}
	if (rc) {
		VV_(printf("ica_aes_gcm decrypt failed with rc = %i\n", rc));
		dump_gcm_data(iv, iv_length, aad, aad_length, key, key_length,
			      encrypt, data_length, decrypt, running_tag,
			      t_length);
	}


	if (!rc) {
		VV_(printf("Decrypt:\n"));
		dump_gcm_data(iv, iv_length, aad, aad_length, key, key_length,
			      encrypt, data_length, decrypt, running_tag,
			      t_length);
	}

	if (memcmp(decrypt, input_data, data_length)) {
		V_(printf("Decryption Result does not match the original data!\n"));
		VV_(printf("Original data:\n"));
		dump_array(input_data, data_length);
		VV_(printf("Decryption Result:\n"));
		dump_array(decrypt, data_length);
		rc++;
	}
	if (memcmp(running_tag, t_result, t_length)) {
		V_(printf("Tag result does not match the expected tag!\n"));
		VV_(printf("Expected tag:\n"));
		dump_array(t_result, t_length);
		VV_(printf("Tag Result:\n"));
		dump_array(running_tag, t_length);
		rc++;
	}

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
	unsigned int offset;
	unsigned char *chunk_data;
	unsigned char icb[AES_BLOCK_SIZE];
	unsigned char ucb[AES_BLOCK_SIZE];
	unsigned char subkey[AES_BLOCK_SIZE];
	unsigned char running_tag[AES_BLOCK_SIZE];
	unsigned int  sum_A_len;
	unsigned int  sum_C_len;
	unsigned int aad_offset;
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
	memset(running_tag, 0, AES_BLOCK_SIZE);
	rc = ica_aes_gcm_initialize(iv, iv_length, key, key_length,
								icb, ucb, subkey, ICA_ENCRYPT);

	/* 1. Process 16-byte aad chunks in advance */
	unsigned int aad_chunklen = 0;
	unsigned int aad_restlen = 0;
	aad_offset = 0;
	while (aad_length >= 16) {

		aad_chunklen = aad_length > 16 ? 16 : aad_length;
		aad_restlen = aad_length > 16 ? aad_length - 16 : 0;

		rc = ica_aes_gcm_intermediate(input_data, 0, encrypt,
								  ucb, aad+aad_offset, aad_chunklen,
								  running_tag, AES_BLOCK_SIZE,
								  key, key_length, subkey, ICA_ENCRYPT);

		aad_length = aad_restlen;
		aad_offset += aad_chunklen;
	}

	/* 2. Process rest of aad if no data available */
	if (num_chunks == 0 && aad_length > 0) {
		rc = ica_aes_gcm_intermediate(input_data, 0, encrypt,
								  ucb, aad+aad_offset, aad_length,
								  running_tag, AES_BLOCK_SIZE,
								  key, key_length, subkey, ICA_ENCRYPT);
	}

	/* 3. Process rest of aad and data */
	offset = 0;
	for (i = 0; i < num_chunks; i++) {

		chunk_len = gcm_kats[iteration].chunks[i];
		chunk_data = input_data + offset;

		rc = ica_aes_gcm_intermediate(chunk_data, chunk_len, encrypt + offset,
									  ucb, aad+aad_offset, aad_length,
									  running_tag, AES_BLOCK_SIZE,
									  key, key_length, subkey, ICA_ENCRYPT);
		/* clear aad_length after first run*/
		aad_length = 0;
		offset += chunk_len;
	}
	sum_A_len = aad_length_tmp;
	sum_C_len = offset;
	rc = ica_aes_gcm_last(icb, sum_A_len, sum_C_len, running_tag,
						  t, t_length, key, key_length, subkey, ICA_ENCRYPT);

	if (rc == EPERM) {
		VV_(printf("ica_aes_gcm returns with EPERM (%d).\n", rc));
		VV_(printf("Operation is not permitted on this machine. Test skipped!\n"));
		return TEST_SKIP;
	}
	if (rc) {
		VV_(printf("ica_aes_gcm encrypt failed with rc = %i\n", rc));
		dump_gcm_data(iv, iv_length, aad, aad_length, key, key_length,
			      input_data, data_length, encrypt, t, t_length);
	}
	if (!rc) {
		VV_(printf("Encrypt:\n"));
		dump_gcm_data(iv, iv_length, aad, aad_length, key, key_length,
			      input_data, data_length, encrypt, running_tag,
			      t_length);
	}

	if (memcmp(result, encrypt, data_length)) {
		V_(printf("Encryption Result does not match the known ciphertext!\n"));
		VV_(printf("Expected data:\n"));
		dump_array(result, data_length);
		VV_(printf("Encryption Result:\n"));
		dump_array(encrypt, data_length);
		rc++;
	}
	if (memcmp(running_tag, t_result, t_length)) {
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
	memset(running_tag, 0, AES_BLOCK_SIZE);
	rc = ica_aes_gcm_initialize(iv, iv_length, key, key_length,
								icb, ucb, subkey, ICA_DECRYPT);

	if (num_chunks == 0 && aad_length > 0) {
		rc = ica_aes_gcm_intermediate(input_data, 0, encrypt,
								  ucb, aad, aad_length,
								  running_tag, AES_BLOCK_SIZE,
								  key, key_length, subkey, ICA_DECRYPT);
	}

	offset = 0;
	for (i = 0; i < num_chunks; i++) {
		chunk_len = gcm_kats[iteration].chunks[i];
		chunk_data = encrypt + offset;

		rc = ica_aes_gcm_intermediate(decrypt + offset, chunk_len, chunk_data,
									  ucb, aad, aad_length,
									  running_tag, AES_BLOCK_SIZE,
									  key, key_length, subkey, ICA_DECRYPT);

		/* clear aad_length after first run*/
		aad_length = 0;
		offset += chunk_len;
	}
	sum_A_len = aad_length_tmp;
	sum_C_len = offset;
	rc = ica_aes_gcm_last(icb, sum_A_len, sum_C_len, running_tag,
						  t_result, t_length, key, key_length, subkey, ICA_DECRYPT);


	if (rc == EPERM) {
		VV_(printf("ica_aes_gcm returns with EPERM (%d).\n", rc));
		VV_(printf("Operation is not permitted on this machine. Test skipped!\n"));
		return TEST_SKIP;
	}
	if (rc) {
		VV_(printf("ica_aes_gcm decrypt failed with rc = %i\n", rc));
		dump_gcm_data(iv, iv_length, aad, aad_length, key, key_length,
			      encrypt, data_length, decrypt, running_tag,
			      t_length);
	}


	if (!rc) {
		VV_(printf("Decrypt:\n"));
		dump_gcm_data(iv, iv_length, aad, aad_length, key, key_length,
			      encrypt, data_length, decrypt, running_tag,
			      t_length);
	}

	if (memcmp(decrypt, input_data, data_length)) {
		V_(printf("Decryption Result does not match the original data!\n"));
		VV_(printf("Original data:\n"));
		dump_array(input_data, data_length);
		VV_(printf("Decryption Result:\n"));
		dump_array(decrypt, data_length);
		rc++;
	}
	if (memcmp(running_tag, t_result, t_length)) {
		V_(printf("Tag result does not match the expected tag!\n"));
		VV_(printf("Expected tag:\n"));
		dump_array(t_result, t_length);
		VV_(printf("Tag Result:\n"));
		dump_array(running_tag, t_length);
		rc++;
	}

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
	unsigned char t[t_length];
	unsigned char* t_result = (unsigned char*)&(gcm_kats[iteration].tag);
	unsigned int chunk_len;
	unsigned int offset;
	unsigned char *chunk_data;
	unsigned char icb[AES_BLOCK_SIZE];
	unsigned char ucb[AES_BLOCK_SIZE];
	unsigned char subkey[AES_BLOCK_SIZE];
	unsigned char running_tag[AES_BLOCK_SIZE];
	unsigned int  sum_A_len;
	unsigned int  sum_C_len;
	unsigned char save_input[MAX_ARRAY_SIZE];
	int rc = 0;
	unsigned int i;

	VV_(printf("Test Parameters for iteration = %i\n", iteration));
	VV_(printf("key length = %i, data length = %i, tag length = %i,"
		"iv length = %i aad_length = %i\n", key_length, data_length,
		t_length, iv_length, aad_length));

	aad_length_tmp = aad_length;
	memset(running_tag, 0, AES_BLOCK_SIZE);
	rc = ica_aes_gcm_initialize(iv, iv_length, key, key_length,
								icb, ucb, subkey, ICA_ENCRYPT);

	memcpy(save_input, input_data, data_length);
	if (num_chunks == 0 && aad_length > 0) {
		rc = ica_aes_gcm_intermediate(input_data, 0, input_data,
								  ucb, aad, aad_length,
								  running_tag, AES_BLOCK_SIZE,
								  key, key_length, subkey, ICA_ENCRYPT);
	}

	offset = 0;
	for (i = 0; i < num_chunks; i++) {
		chunk_len = gcm_kats[iteration].chunks[i];
		chunk_data = input_data + offset;

		rc = ica_aes_gcm_intermediate(chunk_data, chunk_len, chunk_data,
									  ucb, aad, aad_length,
									  running_tag, AES_BLOCK_SIZE,
									  key, key_length, subkey, ICA_ENCRYPT);
		/* clear aad_length after first run*/
		aad_length = 0;
		offset += chunk_len;
	}
	sum_A_len = aad_length_tmp;
	sum_C_len = offset;
	rc = ica_aes_gcm_last(icb, sum_A_len, sum_C_len, running_tag,
						  t, t_length, key, key_length, subkey, ICA_ENCRYPT);

	if (rc == EPERM) {
		VV_(printf("ica_aes_gcm returns with EPERM (%d).\n", rc));
		VV_(printf("Operation is not permitted on this machine. Test skipped!\n"));
		return TEST_SKIP;
	}
	if (rc) {
		VV_(printf("ica_aes_gcm encrypt failed with rc = %i\n", rc));
		dump_gcm_data(iv, iv_length, aad, aad_length, key, key_length,
			      input_data, data_length, input_data, t, t_length);
	}
	if (!rc) {
		VV_(printf("Encrypt:\n"));
		dump_gcm_data(iv, iv_length, aad, aad_length, key, key_length,
			      save_input, data_length, input_data, running_tag,
			      t_length);
	}


	if (memcmp(result, input_data, data_length)) {
		V_(printf("Encryption Result does not match the known ciphertext!\n"));
		VV_(printf("Expected data:\n"));
		dump_array(result, data_length);
		VV_(printf("Encryption Result:\n"));
		dump_array(input_data, data_length);
		rc++;
	}
	if (memcmp(running_tag, t_result, t_length)) {
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

	aad_length = aad_length_tmp;
	memset(running_tag, 0, AES_BLOCK_SIZE);
	rc = ica_aes_gcm_initialize(iv, iv_length, key, key_length,
								icb, ucb, subkey, ICA_DECRYPT);

	if (num_chunks == 0 && aad_length > 0) {
		rc = ica_aes_gcm_intermediate(input_data, 0, input_data,
								  ucb, aad, aad_length,
								  running_tag, AES_BLOCK_SIZE,
								  key, key_length, subkey, ICA_DECRYPT);
	}

	offset = 0;
	for (i = 0; i < num_chunks; i++) {
		chunk_len = gcm_kats[iteration].chunks[i];
		chunk_data = input_data + offset;

		rc = ica_aes_gcm_intermediate(chunk_data, chunk_len, chunk_data,
									  ucb, aad, aad_length,
									  running_tag, AES_BLOCK_SIZE,
									  key, key_length, subkey, ICA_DECRYPT);

		/* clear aad_length after first run*/
		aad_length = 0;
		offset += chunk_len;
	}
	sum_A_len = aad_length_tmp;
	sum_C_len = offset;
	rc = ica_aes_gcm_last(icb, sum_A_len, sum_C_len, running_tag,
						  t_result, t_length, key, key_length, subkey, ICA_DECRYPT);


	if (rc == EPERM) {
		VV_(printf("ica_aes_gcm returns with EPERM (%d).\n", rc));
		VV_(printf("Operation is not permitted on this machine. Test skipped!\n"));
		return TEST_SKIP;
	}
	if (rc) {
		VV_(printf("ica_aes_gcm decrypt failed with rc = %i\n", rc));
		dump_gcm_data(iv, iv_length, aad, aad_length, key, key_length,
			      input_data, data_length, input_data, running_tag,
			      t_length);
	}


	if (!rc) {
		VV_(printf("Decrypt:\n"));
		dump_gcm_data(iv, iv_length, aad, aad_length, key, key_length,
			      input_data, data_length, save_input, running_tag,
			      t_length);
	}

	if (memcmp(save_input, input_data, data_length)) {
		V_(printf("Decryption Result does not match the original data!\n"));
		VV_(printf("Original data:\n"));
		dump_array(save_input, data_length);
		VV_(printf("Decryption Result:\n"));
		dump_array(input_data, data_length);
		rc++;
	}
	if (memcmp(running_tag, t_result, t_length)) {
		V_(printf("Tag result does not match the expected tag!\n"));
		VV_(printf("Expected tag:\n"));
		dump_array(t_result, t_length);
		VV_(printf("Tag Result:\n"));
		dump_array(running_tag, t_length);
		rc++;
	}

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
		printf("%i of %li AES-GCM tests failed.\n", error_count, NUM_GCM_TESTS*4);
		return TEST_FAIL;
	}

	printf("All AES-GCM tests passed.\n");
	return TEST_SUCC;
}
