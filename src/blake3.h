#ifndef ARK_BLAKE3_H
#define ARK_BLAKE3_H

#include <stddef.h>
#include <stdint.h>

typedef struct ark_blake3_ctx ark_blake3_ctx_t;

void ark_blake3_init(ark_blake3_ctx_t *ctx);
void ark_blake3_update(ark_blake3_ctx_t *ctx, const uint8_t *data, size_t len);
void ark_blake3_final(ark_blake3_ctx_t *ctx, uint8_t digest[32]);
void ark_blake3(const uint8_t *data, size_t len, uint8_t digest[32]);

#endif /* ARK_BLAKE3_H */
