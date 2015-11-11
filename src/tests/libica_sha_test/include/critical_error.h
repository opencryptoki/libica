#ifndef CRITICAL_ERROR_H
#define CRITICAL_ERROR_H

#include <stdio.h>
#include <stdlib.h>

/* terminate on critical error */
#define CRITICAL_ERROR(msg) \
do { \
        fprintf(stderr, "critical error in %s: " msg "\n",__func__); \
        exit(EXIT_FAILURE); \
} while(0)

#endif
