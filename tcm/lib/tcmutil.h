#ifndef TCMUTIL_H
#define TCMUTIL_H

#include <stdint.h>
#include <tcm_structures.h>
#include <ap.h>

//#define DEBUG_BUILDBUFF

struct tcm_buffer;

int      TSS_buildbuff(char *format,struct tcm_buffer *, ...);
uint32_t TCM_Transmit(struct tcm_buffer *,const char *msg);

int      TSS_tcmgennonce(unsigned char *nonce);
uint32_t TSS_SCHFile(const char *filename, unsigned char *buffer);

uint32_t tcm_buffer_load32 (const struct tcm_buffer *tb, uint32_t offset, uint32_t *val);
uint32_t tcm_buffer_load32N(const struct tcm_buffer *tb, uint32_t offset, uint32_t *val);
uint32_t tcm_buffer_load16 (const struct tcm_buffer *tb, uint32_t offset, uint16_t *val);
uint32_t tcm_buffer_load16N(const struct tcm_buffer *tb, uint32_t offset, uint16_t *val);
uint32_t tcm_buffer_store32(struct tcm_buffer *tb, uint32_t val);
uint32_t tcm_buffer_store(struct tcm_buffer *dest, struct tcm_buffer *src, uint32_t soff, uint32_t slen);

int      TCM_setlog(int flag);
char    *TCM_GetErrMsg(uint32_t code);
#endif
