#ifndef TCMAP_H
#define TCMAP_H
#include "tcm_structures.h"

typedef struct apsess
   {
   uint32_t      handle;
   uint32_t      nonce;
   uint8_t       entitytype;   
   unsigned char tcmnonce[TCM_NONCE_SIZE];
   unsigned char callernonce[TCM_NONCE_SIZE];
   unsigned char sharedsecret[TCM_HASH_SIZE];
   unsigned char authdata[TCM_AUTHDATA_SIZE];
   } apsess;

void TCM_CreateEncAuth(apsess *sess, unsigned char *in, unsigned char *out);
uint32_t TSS_APopen(apsess *sess, unsigned char *key, uint16_t etype, uint32_t evalue);
uint32_t TSS_APclose(apsess *sess);

/* apcreate中使用计算authdata的方法
 * 直接进行hmac
 */
uint32_t compute_authdata1(unsigned char *key, uint32_t ordinal, apsess *sess);

/* apclose中使用计算authdata的方法
 * 先对ordinal进行hash后，再进行hmac
 */
uint32_t compute_authdata2(uint32_t ordinal, struct tcm_buffer * params, apsess *sess);

#endif
