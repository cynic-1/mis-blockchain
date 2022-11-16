#ifndef _TCM_HMAC_H_
#define _TCM_HMAC_H_

#include "tcm_structures.h"
#include "tcmalg.h"

#define HMAC_PAD_LENGTH 64
#define SCH_DIGEST_LENGTH 32

static inline void store32(unsigned char *const buffer,
                           int offset,
                           uint32_t value)
{
    int i;
    for (i = 3; i >= 0; i--) {
        buffer[offset+i] = (value & 0xff);
        value >>= 8;
    }
}

static inline void store16(unsigned char *const buffer,
                           int offset,
                           uint16_t value)
{
    int i;
    for (i = 1; i >= 0; i--) {
        buffer[offset+i] = (value & 0xff);
        value >>= 8;
    }
}

typedef struct tdtcm_hmac_ctx_t{
   sch_context ctx;
   BYTE k_opad[HMAC_PAD_LENGTH];
} tcm_hmac_ctx_t;

void tcm_hmac_init(tcm_hmac_ctx_t *ctx,  uint8_t *key, size_t key_len);
void tcm_hmac_update(tcm_hmac_ctx_t *ctx, uint8_t *data, size_t length);
void tcm_hmac_final(tcm_hmac_ctx_t *ctx, uint8_t *digest);

void tcm_sch_init( sch_context *ctx );	
void tcm_sch_update( sch_context *ctx, uint8 *input, uint32 length );
void tcm_sch_final( sch_context *ctx, uint8 digest[32] );

#endif
