#include <openssl/crypto.h>
#include <openssl/opensslv.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <openssl/opensslconf.h>
#ifdef OPENSSL_FIPS
#include <openssl/fips.h>
#endif /* OPENSSL_FIPS */

#include "ica_api.h"
#include "testcase.h"

#define FIPS_FLAG "/proc/sys/crypto/fips_enabled"

#ifdef ICA_FIPS
static int test_gcm_iv_usage(void)
{
	libica_fips_indicator_element *fips_list = NULL;
	int rc, i, fips_len, allow, errno_expected, rc_expected;
	unsigned int approved_expected, override_expected;

	/* Check fips indicator when allowing an external iv in fips mode */
	for (allow = 0; allow < 2; allow++) {

		approved_expected = allow == 1 ? 0 : 1;
		override_expected = allow == 1 ? 1 : 0;

		ica_allow_external_gcm_iv_in_fips_mode(allow);

		/* Get fips indicator list */
		if (ica_get_fips_indicator(NULL, (unsigned int *)&fips_len) != 0) {
			printf("get_fips_indicator failed\n");
			rc = EXIT_FAILURE;
			goto done;
		}

		fips_list = malloc(sizeof(libica_fips_indicator_element)*fips_len);
		if (!fips_list) {
			printf("malloc fips_indicator list failed\n");
			rc = EXIT_FAILURE;
			goto done;
		}

		if (ica_get_fips_indicator(fips_list, (unsigned int *)&fips_len) != 0) {
			printf("ica_get_fips_indicator failed\n");
			free(fips_list);
			rc = EXIT_FAILURE;
			goto done;
		}

		for (i = 0; i < fips_len; i++) {
			if (fips_list[i].mech_mode_id == AES_GCM ||
				fips_list[i].mech_mode_id == AES_GCM_KMA) {
				if (fips_list[i].fips_approved != approved_expected ||
					fips_list[i].fips_override != override_expected) {
					printf("fips approved/override values not as expected for algo id %d and allow = %d:\n",
						fips_list[i].mech_mode_id, allow);
					printf("  fips approved = %d, expected %d\n",
						fips_list[i].fips_approved, approved_expected);
					printf("  fips override = %d, expected %d\n",
						fips_list[i].fips_override, override_expected);
					rc = EXIT_FAILURE;
					free(fips_list);
					goto done;
				}
			}
		}

		free(fips_list);
	}

	/* Check API behavior when allowing an external iv in fips mode */
	for (allow = 0; allow < 2; allow++) {
		unsigned char iv[12], key[16], icb[16], ucb[16], subkey[16];
		unsigned char aad[16], t[16], msg[64], encmsg[64], running_tag[16];

		ica_allow_external_gcm_iv_in_fips_mode(allow);

		rc_expected = allow == 1 ? 0 : EPERM;
		errno_expected = allow == 1 ? EPERM : 0;

		/*
		 * Old API encrypt.
		 * Note: ica_aes_gcm() is unconditionally blocked in fips mode,
		 *       so no need for testing this.
		 */
		memset(running_tag, 0, sizeof(running_tag));

		rc = ica_aes_gcm_initialize(iv, sizeof(iv), key, sizeof(key),
				icb, ucb, subkey, ICA_ENCRYPT);
		if (rc != rc_expected || errno != errno_expected) {
			printf("rc/errno not as expected from ica_aes_gcm_initialize (encrypt, allow=%d)\n",
				allow);
			printf("  rc = %d, expected %d\n", rc, rc_expected);
			printf("  errno = %d, expected %d\n", errno, errno_expected);
			rc = EXIT_FAILURE;
			goto done;
		}

		rc = ica_aes_gcm_intermediate(msg, sizeof(msg), encmsg, ucb,
				aad, sizeof(aad), running_tag, 16, key, sizeof(key),
				subkey, ICA_ENCRYPT);
		if (rc != rc_expected || errno != errno_expected) {
			printf("rc/errno not as expected from ica_aes_gcm_intermediate (encrypt, allow=%d)\n",
				allow);
			printf("  rc = %d, expected %d\n", rc, rc_expected);
			printf("  errno = %d, expected %d\n", errno, errno_expected);
			rc = EXIT_FAILURE;
			goto done;
		}

		rc = ica_aes_gcm_last(icb, sizeof(aad), sizeof(msg), running_tag,
				t, sizeof(t), key, sizeof(key), subkey, ICA_ENCRYPT);
		if (rc != rc_expected || errno != errno_expected) {
			printf("rc/errno not as expected from ica_aes_gcm_last (encrypt, allow=%d)\n",
				allow);
			printf("  rc = %d, expected %d\n", rc, rc_expected);
			printf("  errno = %d, expected %d\n", errno, errno_expected);
			rc = EXIT_FAILURE;
			goto done;
		}

		/* Old API decrypt. */
		rc_expected = 0; /* ext. iv always allowed for decrypt */
		errno_expected = 0;

		memcpy(t, running_tag, sizeof(t)); /* save running tag for later */
		memset(running_tag, 0, sizeof(running_tag));

		rc = ica_aes_gcm_initialize(iv, sizeof(iv), key, sizeof(key),
				icb, ucb, subkey, ICA_DECRYPT);
		if (rc != rc_expected || errno != errno_expected) {
			printf("rc/errno not as expected from ica_aes_gcm_initialize (decrypt, allow=%d)\n",
				allow);
			printf("  rc = %d, expected %d\n", rc, rc_expected);
			printf("  errno = %d, expected %d\n", errno, errno_expected);
			rc = EXIT_FAILURE;
			goto done;
		}

		rc = ica_aes_gcm_intermediate(msg, sizeof(msg), encmsg, ucb,
				aad, sizeof(aad), running_tag, 16, key, sizeof(key),
				subkey, ICA_DECRYPT);
		if (rc != rc_expected || errno != errno_expected) {
			printf("rc/errno not as expected from ica_aes_gcm_intermediate (decrypt, allow=%d)\n",
				allow);
			printf("  rc = %d, expected %d\n", rc, rc_expected);
			printf("  errno = %d, expected %d\n", errno, errno_expected);
			rc = EXIT_FAILURE;
			goto done;
		}

		/*
		 * Verifying the tag fails with EFAULT if encrypt wasn't allowed
		 * before, because of allow = 0.
		 */
		rc_expected = allow == 0 ? EFAULT : 0;

		rc = ica_aes_gcm_last(icb, sizeof(aad), sizeof(msg), running_tag,
				t, sizeof(t), key, sizeof(key), subkey, ICA_DECRYPT);
		if (rc != rc_expected || errno != errno_expected) {
			printf("rc/errno not as expected from ica_aes_gcm_last (decrypt, allow=%d)\n",
				allow);
			printf("  rc = %d, expected %d\n", rc, rc_expected);
			printf("  errno = %d, expected %d\n", errno, errno_expected);
			rc = EXIT_FAILURE;
			goto done;
		}

		/* New API encrypt. */
		rc_expected = allow == 1 ? 0 : EPERM;
		errno_expected = allow == 1 ? EPERM : 0;

		kma_ctx* ctx = ica_aes_gcm_kma_ctx_new();
		if (!ctx) {
			printf("Could not allocate KMA context\n");
			rc = EXIT_FAILURE;
			goto done;
		}

		rc = ica_aes_gcm_kma_init(ICA_ENCRYPT, iv, sizeof(iv),
				key, sizeof(key), ctx);
		if (rc != rc_expected || errno != errno_expected) {
			printf("rc/errno not as expected from ica_aes_gcm_kma_init (encrypt, allow=%d)\n",
				allow);
			printf("  rc = %d, expected %d\n", rc, rc_expected);
			printf("  errno = %d, expected %d\n", errno, errno_expected);
			ica_aes_gcm_kma_ctx_free(ctx);
			rc = EXIT_FAILURE;
			goto done;
		}

		/*
		 * If the preceding init failed, the ctx is not correctly initialized
		 * and calling the update, get_tag, etc. functions makes no sense.
		 * However, applications can do this and the API must return the
		 * expected rc and errno values.
		 */

		rc = ica_aes_gcm_kma_update(msg, encmsg, sizeof(msg),
				aad, sizeof(aad), 1, 1, ctx);
		if (rc != rc_expected || errno != errno_expected) {
			printf("rc/errno not as expected from ica_aes_gcm_kma_update (encrypt, allow=%d)\n",
				allow);
			printf("  rc = %d, expected %d\n", rc, rc_expected);
			printf("  errno = %d, expected %d\n", errno, errno_expected);
			ica_aes_gcm_kma_ctx_free(ctx);
			rc = EXIT_FAILURE;
			goto done;
		}

		rc = ica_aes_gcm_kma_get_tag(t, sizeof(t), ctx);
		if (rc != rc_expected || errno != errno_expected) {
			printf("rc/errno not as expected from ica_aes_gcm_kma_get_tag (encrypt, allow=%d)\n",
				allow);
			printf("  rc = %d, expected %d\n", rc, rc_expected);
			printf("  errno = %d, expected %d\n", errno, errno_expected);
			ica_aes_gcm_kma_ctx_free(ctx);
			rc = EXIT_FAILURE;
			goto done;
		}

		/* New API decrypt. */
		rc_expected = 0; /* ext. iv always allowed for decrypt */
		errno_expected = 0;

		rc = ica_aes_gcm_kma_init(ICA_DECRYPT, iv, sizeof(iv),
				key, sizeof(key), ctx);
		if (rc != rc_expected || errno != errno_expected) {
			printf("rc/errno not as expected from ica_aes_gcm_kma_init (decrypt, allow=%d)\n",
				allow);
			printf("  rc = %d, expected %d\n", rc, rc_expected);
			printf("  errno = %d, expected %d\n", errno, errno_expected);
			ica_aes_gcm_kma_ctx_free(ctx);
			rc = EXIT_FAILURE;
			goto done;
		}

		rc = ica_aes_gcm_kma_update(encmsg, msg, sizeof(msg),
				aad, sizeof(aad), 1, 1, ctx);
		if (rc != rc_expected || errno != errno_expected) {
			printf("rc/errno not as expected from ica_aes_gcm_kma_update (decrypt, allow=%d)\n",
				allow);
			printf("  rc = %d, expected %d\n", rc, rc_expected);
			printf("  errno = %d, expected %d\n", errno, errno_expected);
			ica_aes_gcm_kma_ctx_free(ctx);
			rc = EXIT_FAILURE;
			goto done;
		}

		/*
		 * verify_tag fails with EFAULT if encrypt wasn't allowed before,
		 * because of allow = 0.
		 */
		rc_expected = allow == 0 ? EFAULT : 0;

		rc = ica_aes_gcm_kma_verify_tag(t, sizeof(t), ctx);
		if (rc != rc_expected || errno != errno_expected) {
			printf("rc/errno not as expected from ica_aes_gcm_kma_verify_tag (decrypt, allow=%d)\n",
				allow);
			printf("  rc = %d, expected %d\n", rc, rc_expected);
			printf("  errno = %d, expected %d\n", errno, errno_expected);
			ica_aes_gcm_kma_ctx_free(ctx);
			rc = EXIT_FAILURE;
			goto done;
		}

		ica_aes_gcm_kma_ctx_free(ctx);
	}

	rc = 0;

done:
	return rc;
}
#endif /* ICA_FIPS */

int
main(void)
{
	FILE *fd;
	int fips, rv;
	char fips_flag;

	printf("Kernel FIPS flag (%s) is ", FIPS_FLAG);
	if ((fd = fopen(FIPS_FLAG, "r")) != NULL) {
		if (fread(&fips_flag, sizeof(fips_flag), 1, fd) == 1) {
			fips_flag -= '0';
			printf("%d.", fips_flag);
		} else {
			printf("not readable.");
		}
		fclose(fd);
	}
	else {
		fips_flag = 0;
		printf("not present.");
	}
	printf("\nKernel %s in FIPS mode.\n", fips_flag ?
	    "runs" : "doesn't run");

	printf("Libica has ");
#ifdef ICA_FIPS
	fips = ica_fips_status();
#else
	fips = 0;
	printf("no ");
#endif /* ICA_FIPS */
	printf("built-in FIPS support.\nLibica %s in FIPS mode.\n",
	    fips & ICA_FIPS_MODE ? "runs" : "doesn't run");

	rv = EXIT_SUCCESS;
#ifdef ICA_FIPS
	if ((fips & ICA_FIPS_MODE) != fips_flag) {
		/* Check if the fips_flag is turned on via env variable. In this case
		 * skip the test. */
		char *fips_override = getenv("LIBICA_FIPS_FLAG");
		if ((fips_override != NULL) && (atoi(fips_override) == 1)) {
			printf("Skip test: kernel is not in fips mode, but libica fips flag is set via env variable.\n");
			return TEST_SKIP;
		}
		printf("This shouldn't happen.\n");
		rv = EXIT_FAILURE;
	}
	if (fips & ICA_FIPS_CRYPTOALG) {
		printf("Libica FIPS powerup test failed.\n");
		rv = EXIT_FAILURE;
	}
	if (fips & ICA_FIPS_INTEGRITY) {
		printf("Libica FIPS integrity check failed.\n");
		rv = EXIT_FAILURE;
	}
	if (fips & ICA_FIPS_MODE) {
		if (test_gcm_iv_usage()) {
			printf("Libica FIPS gcm iv usage check failed.\n");
			rv = EXIT_FAILURE;
		}
	}
#endif /* ICA_FIPS */

	printf("OpenSSL version is '%s'.\n", OPENSSL_VERSION_TEXT);
	printf("OpenSSL %s in FIPS mode.\n\n", fips ?
	    "runs" : "doesn't run");

	if (rv)
		return TEST_FAIL;

	return TEST_SUCC;
}
