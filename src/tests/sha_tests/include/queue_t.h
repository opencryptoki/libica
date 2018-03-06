#ifndef QUEUE_T_H
#define QUEUE_T_H

#define NO_TYPE_SET 0
#define NO_LENGTH_SET 0

/* type: NO_TYPE_SET, SHA1, SHA224, SHA256, SHA384, SHA512 
 * msg_digest_length: SHA1_HASH_LENGTH, SHA224_HASH_LENGHT, SHA256_HASH_LENGTH, SHA384_HASH_LENGTH, SHA512_HASH_LENGTH
 * */
typedef struct test_t {
	unsigned int type;
	unsigned char *msg;
	unsigned int msg_length;
	unsigned char *msg_digest;
	unsigned int msg_digest_length;
	struct test_t *next;
} test_t;

test_t new_test_t(void);

typedef struct queue_t {
	unsigned int size;
	unsigned int passed;
	unsigned int failed;
	test_t *head;
	test_t *tail;
} queue_t;

queue_t new_queue_t(void);

void push(queue_t * queue, test_t test);

#endif
