/* This program is released under the Common Public License V1.0
 *
 * You should have received a copy of Common Public License V1.0 along with
 * with this program.
 */

/*
 * Fork safety test: DRBG state is copied by fork(). Parent and child must not
 * return identical output afterwards.
 */
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "ica_api.h"
#include "testcase.h"

#define RND_LEN 32

typedef int (*gen_fn)(unsigned char *buf, size_t len);

static int gen_random_number(unsigned char *buf, size_t len)
{
	return ica_random_number_generate(len, buf);
}

static ica_drbg_t *user_sh;

static int gen_user_drbg(unsigned char *buf, size_t len)
{
	return ica_drbg_generate(user_sh, 256, false, NULL, 0, buf, len);
}

/*
 * Key generation draws its randomness from the library internal DRBG
 * instance (rng_gen()/rng_sh), which is separate from the global instance
 * behind ica_random_number_generate(). The X25519 private key is 32 bytes,
 * the same as RND_LEN.
 */
static int gen_x25519_key(unsigned char *buf, size_t len)
{
	unsigned char priv[32], pub[32];
	ICA_X25519_CTX *ctx = NULL;
	int rc = -1;

	(void)len;

	if (ica_x25519_ctx_new(&ctx) != 0)
		return -1;
	if (ica_x25519_key_gen(ctx) == 0 &&
	    ica_x25519_key_get(ctx, priv, pub) == 0) {
		memcpy(buf, priv, sizeof(priv));
		rc = 0;
	}
	memset(priv, 0, sizeof(priv));
	ica_x25519_ctx_del(&ctx);

	return rc;
}

/*
 * Fork, generate in both processes, and compare. Returns TEST_SUCC if the
 * outputs differ.
 */
static int check_fork(const char *name, gen_fn gen)
{
	unsigned char parent_buf[RND_LEN], child_buf[RND_LEN];
	int fds[2], status;
	pid_t pid;
	ssize_t n;

	/* Use the generator before fork so that the state is not fresh. */
	if (gen(parent_buf, sizeof(parent_buf)) != 0) {
		printf("%s: generate failed before fork.\n", name);
		return TEST_FAIL;
	}

	if (pipe(fds) != 0)
		return TEST_FAIL;

	pid = fork();
	if (pid < 0)
		return TEST_FAIL;

	if (pid == 0) {
		close(fds[0]);
		if (gen(child_buf, sizeof(child_buf)) != 0)
			_exit(2);
		if (write(fds[1], child_buf, sizeof(child_buf)) !=
		    (ssize_t)sizeof(child_buf))
			_exit(3);
		_exit(0);
	}

	close(fds[1]);
	if (gen(parent_buf, sizeof(parent_buf)) != 0) {
		printf("%s: generate failed in parent.\n", name);
		return TEST_FAIL;
	}

	n = read(fds[0], child_buf, sizeof(child_buf));
	close(fds[0]);
	waitpid(pid, &status, 0);

	if (n != (ssize_t)sizeof(child_buf) || !WIFEXITED(status) ||
	    WEXITSTATUS(status) != 0) {
		printf("%s: child failed.\n", name);
		return TEST_FAIL;
	}

	if (memcmp(parent_buf, child_buf, RND_LEN) == 0) {
		printf("%s: parent and child produced identical output!\n",
		       name);
		dump_array(parent_buf, sizeof(parent_buf));
		return TEST_FAIL;
	}

	V_(printf("%s: parent and child output differ.\n", name));
	return TEST_SUCC;
}

int main(int argc, char **argv)
{
#ifdef NO_CPACF
	UNUSED(argc);
	UNUSED(argv);
	printf("Skipping DRBG fork test, because CPACF support disabled via config option.\n");
	return TEST_SKIP;
#else
	int rc, ret = TEST_SUCC;
	unsigned char probe[RND_LEN];

	set_verbosity(argc, argv);

	rc = ica_random_number_generate(sizeof(probe), probe);
	if (rc == ENODEV || rc == EPERM || rc == EACCES) {
		printf("Skipping DRBG fork test, RNG not available (rc=%d).\n",
		       rc);
		return TEST_SKIP;
	}

	/* Global DRBG behind ica_random_number_generate(). */
	if (check_fork("ica_random_number_generate", gen_random_number))
		ret = TEST_FAIL;

	/* Internal DRBG instance used for ECC key generation (MSA9). */
	if (gen_x25519_key(probe, sizeof(probe)) != 0) {
		printf("X25519 key generation not available, skipping.\n");
	} else if (check_fork("ica_x25519_key_gen", gen_x25519_key)) {
		ret = TEST_FAIL;
	}

	/* Instance created through the public DRBG API. */
	rc = ica_drbg_instantiate(&user_sh, 256, false, ICA_DRBG_SHA512,
				  (unsigned char *)"fork test", 9);
	if (rc != 0) {
		printf("ica_drbg_instantiate failed (rc=%d), skipping user DRBG check.\n",
		       rc);
	} else {
		if (check_fork("ica_drbg_generate", gen_user_drbg))
			ret = TEST_FAIL;
		ica_drbg_uninstantiate(&user_sh);
	}

	return ret;
#endif /* NO_CPACF */
}
