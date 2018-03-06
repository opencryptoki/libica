#ifndef READ_RSP_H
#define READ_RSP_H

#include <stdio.h>
#include "queue_t.h"

#define BUFFER_SIZE 32768

extern queue_t queue;

/* read test data from .rsp file into queue */
int read_test_data(FILE * test_data, int sha3_flag);

#endif
