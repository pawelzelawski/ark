#include <stddef.h>
#include <stdint.h>

#include "sha256.h"

int test_sha256_stub(void)
{
	ark_sha256_ctx_t ctx;
	uint8_t digest_stream[32];
	uint8_t digest_single[32];
	const uint8_t msg[] = {'a', 'b', 'c'};
	size_t i;

	ark_sha256_init(&ctx);
	ark_sha256_update(&ctx, msg, sizeof(msg));
	ark_sha256_final(&ctx, digest_stream);
	ark_sha256(msg, sizeof(msg), digest_single);

	for (i = 0; i < sizeof(digest_stream); i++) {
		if (digest_stream[i] != digest_single[i])
			return (1);
	}

	return (0);
}
