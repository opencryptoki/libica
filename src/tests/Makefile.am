noinst_PROGRAMS=libica_3des_test \
		libica_aes128_test \
		libica_aes192_test \
		libica_aes256_test \
		libica_des_test \
		libica_keygen_test \
		libica_rng_test2 \
		libica_rng_test \
		libica_rsa_test \
		libica_sha1_test \
		libica_sha256_test \
		test_mech_list \
		ica-encrypt \
		ica-decrypt \
		ica-digest

AM_CFLAGS=-g -O0 -Wall -I. -I../../include
AM_LDFLAGS=-L../ -lica

libica_3des_test_SOURCES=libica_3des_test.c
libica_aes128_test_SOURCES=libica_aes128_test.c
libica_aes192_test_SOURCES=libica_aes192_test.c
libica_aes256_test_SOURCES=libica_aes256_test.c
libica_des_test_SOURCES=libica_des_test.c
libica_keygen_test_SOURCES=libica_keygen_test.c
libica_rng_test2_SOURCES=libica_rng_test2.c
libica_rng_test_SOURCES=libica_rng_test.c
libica_rsa_test_SOURCES=libica_rsa_test.c
libica_sha1_test_SOURCES=libica_sha1_test.c
libica_sha256_test_SOURCES=libica_sha256_test.c
test_mech_list_SOURCES=test_mech_list.c ../icalinux.c
ica_encrypt_SOURCES=ica-encrypt.c
ica_decrypt_SOURCES=ica-decrypt.c
ica_digest_SOURCES=ica-digest.c

TESTS=libica_3des_test \
      libica_aes128_test \
      libica_aes192_test \
      libica_aes256_test \
      libica_des_test \
      libica_keygen_test \
      libica_rng_test2 \
      libica_rng_test \
      libica_rsa_test \
      libica_sha1_test \
      libica_sha256_test \
      test_mech_list \
      ica-encrypt \
      ica-decrypt \
      ica-digest
