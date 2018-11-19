TESTS = \
fips_test \
icastats_test \
get_functionlist_test \
get_version_test \
rng_test \
drbg_test \
drbg_birthdays_test.pl \
des_test \
des_ecb_test \
des_cbc_test \
des_ctr_test \
des_cfb_test \
des_ofb_test \
tdes_test \
tdes_ecb_test \
tdes_cbc_test \
tdes_ctr_test \
tdes_cfb_test \
tdes_ofb_test \
aes_128_test \
aes_192_test \
aes_256_test \
aes_ecb_test \
aes_cbc_test \
aes_ctr_test \
aes_cfb_test \
aes_ofb_test \
aes_xts_test \
aes_gcm_test \
aes_gcm_kma_test \
cbccs_test \
ccm_test \
cmac_test \
sha2_test.sh \
sha3_test.sh \
sha1_test \
sha256_test \
sha3_224_test \
sha3_256_test \
sha3_384_test \
sha3_512_test \
shake_128_test \
shake_256_test \
rsa_keygen1024_test.sh \
rsa_keygen2048_test.sh \
rsa_keygen3072_test.sh \
rsa_keygen4096_test.sh \
rsa_key_check_test \
rsa_test \
ec_keygen1_test.sh \
ecdh1_test.sh \
ecdsa1_test.sh \
ec_keygen2_test.sh \
ecdh2_test.sh \
ecdsa2_test.sh \
mp_test

if ICA_INTERNAL_TESTS
TESTS += \
${top_builddir}/src/internal_tests/ec_internal_test
endif

TEST_EXTENSIONS = .sh .pl
TESTS_ENVIRONMENT = export LD_LIBRARY_PATH=${builddir}/../src/.libs/ \
			   PATH=${builddir}/../src/:$$PATH \
			   LIBICA_TESTDATA=${srcdir}/testdata/;
AM_CFLAGS = @FLAGS@ -I${srcdir}/../include/ -I${srcdir}/../src/include/
LDADD = @LIBS@ ${top_builddir}/src/.libs/libica.so -lcrypto -lpthread

check_PROGRAMS = fips_test icastats_test get_functionlist_test \
get_version_test rng_test drbg_test drbg_birthdays_test des_test \
des_ecb_test des_cbc_test des_ctr_test des_cfb_test des_ofb_test \
tdes_test tdes_ecb_test tdes_cbc_test tdes_ctr_test tdes_cfb_test \
tdes_ofb_test aes_128_test aes_192_test aes_256_test aes_ecb_test \
aes_cbc_test aes_ctr_test aes_cfb_test aes_ofb_test aes_xts_test \
aes_gcm_test aes_gcm_kma_test cbccs_test ccm_test cmac_test sha_test \
sha1_test sha256_test sha3_224_test sha3_256_test sha3_384_test \
sha3_512_test shake_128_test shake_256_test rsa_keygen_test \
rsa_key_check_test rsa_test ec_keygen_test ecdh_test ecdsa_test mp_test

EXTRA_DIST = testdata testcase.h rsa_test.h aes_gcm_test.h ecdsa1_test.sh \
sha2_test.sh ecdh1_test.sh ecdsa2_test.sh ecdh2_test.sh \
drbg_birthdays_test.pl sha3_test.sh ec_keygen1_test.sh ec_keygen2_test.sh \
rsa_keygen2048_test.sh rsa_keygen1024_test.sh rsa_keygen4096_test.sh \
rsa_keygen3072_test.sh rsa_keygen_test.sh
