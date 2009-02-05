/* This program is released under the Common Public License V1.0
 *
 * You should have received a copy of Common Public License V1.0 along with
 * with this program.
 */

/**
 * Authors: Felix Beck <felix.beck@de.ibm.com>
 *	    Christian Maaser <cmaaser@de.ibm.com>
 *
 * Copyright IBM Corp. 2009
 */

#ifndef INIT_H
#define INIT_H

#include <signal.h>
#include <setjmp.h>

#define EXCEPTION_RV    20

int begin_sigill_section(struct sigaction *oldact, sigset_t * oldset);
void end_sigill_section(struct sigaction *oldact, sigset_t * oldset);

#endif

