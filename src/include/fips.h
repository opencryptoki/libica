/*
 * This program is released under the Common Public License V1.0
 *
 * You should have received a copy of Common Public License V1.0 along with
 * with this program.
 *
 * Author(s): Patrick Steuer <patrick.steuer@de.ibm.com>
 *
 * Copyright IBM Corp. 2015
 */

#ifdef ICA_FIPS
#ifndef FIPS_H
#define FIPS_H

#define FIPS_FLAG "/proc/sys/crypto/fips_enabled"

extern int fips;			/* module status */

/*
 * Initialize global fips var to 1 resp. 0 when FIPS_FLAG is 1 resp. 0 (or not
 * present).
 */
void fips_init(void);

/*
 * Powerup tests: crypto algorithm test, SW/FW integrity test (not implemented
 * yet), critical function test (no critical functions). The tests set the
 * corresponding status flags.
 */
void fips_powerup_tests(void);

/*
 * Returns 1 if the algorithm identified by @id is FIPS approved.
 * Returns 0 otherwise.
 */
int fips_approved(int id);

#endif /* FIPS_H */
#endif /* ICA_FIPS */
