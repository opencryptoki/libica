/* This program is released under the Common Public License V1.0
 *
 * You should have received a copy of Common Public License V1.0 along with
 * with this program.
 *
 * Copyright IBM Corp. 2018
 */

#ifndef RNG_H
# define RNG_H

/*
 * libica's rng for library-internal stuff. Cannot be queried by applications
 * directly via the api.
 */
void rng_init(void);
int rng_gen(unsigned char *buf, size_t buflen);
void rng_fini(void);

#endif
