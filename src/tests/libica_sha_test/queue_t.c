#include <stdlib.h>
#include <string.h>
#include "queue_t.h"
#include "critical_error.h"

test_t new_test_t(void)
{
	test_t test;

	test.type = NO_TYPE_SET;
	test.msg = NULL;
	test.msg_length = 0;
	test.msg_digest = NULL;
	test.msg_digest_length = 0;
	test.next = NULL;

	return test;
}

queue_t new_queue_t(void)
{
	queue_t queue;

	queue.size = 0;
	queue.passed = 0;
	queue.failed = 0;
	queue.head = NULL;
	queue.tail = NULL;

	return queue;
}

void push(queue_t * queue, test_t test)
{
	test_t *new_test;

	if ((new_test = (test_t *) malloc(sizeof(test_t))) == NULL)
		CRITICAL_ERROR("out of memory.");

	new_test->type = test.type;
	new_test->msg_length = test.msg_length;
	new_test->msg_digest_length = test.msg_digest_length;

	new_test->msg = (unsigned char *)malloc((size_t) test.msg_length);
	memcpy(new_test->msg, test.msg, (size_t) test.msg_length);

	new_test->msg_digest =
	    (unsigned char *)malloc((size_t) test.msg_digest_length);
	memcpy(new_test->msg_digest, test.msg_digest,
	       (size_t) test.msg_digest_length);

	new_test->next = NULL;

	if (queue->head == NULL)
		queue->head = new_test;
	else
		queue->tail->next = new_test;
	queue->tail = new_test;
	queue->size++;
}
