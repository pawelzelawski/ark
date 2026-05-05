#ifndef ARK_SHA256_H
#define ARK_SHA256_H

#include <stddef.h>
#include <stdint.h>

typedef struct ark_sha256_ctx ark_sha256_ctx_t;

void	ark_sha256_init(ark_sha256_ctx_t *ctx);
void	ark_sha256_update(ark_sha256_ctx_t *ctx, const uint8_t *data, size_t len);
void	ark_sha256_final(ark_sha256_ctx_t *ctx, uint8_t digest[32]);
void	ark_sha256(const uint8_t *data, size_t len, uint8_t digest[32]);

#endif /* ARK_SHA256_H */

