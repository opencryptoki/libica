#ifndef SHA_TESTS_H
#define SHA_TESTS_H

#include "queue_t.h"

int sha1_old_api_test(test_t * test);
int sha1_new_api_test(test_t * test);

int sha224_old_api_test(test_t * test);
int sha224_new_api_test(test_t * test);

int sha256_old_api_test(test_t * test);
int sha256_new_api_test(test_t * test);

int sha384_old_api_test(test_t * test);
int sha384_new_api_test(test_t * test);

int sha512_old_api_test(test_t * test);
int sha512_new_api_test(test_t * test);

int sha3_224_api_test(test_t * test);
int sha3_256_api_test(test_t * test);
int sha3_384_api_test(test_t * test);
int sha3_512_api_test(test_t * test);

int silent;
#endif
