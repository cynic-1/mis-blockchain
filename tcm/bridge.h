#ifndef _BRIDGE_H_
#define _BRIDGE_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#ifdef TCM_POSIX
#include <netinet/in.h>
#endif
#ifdef TCM_WINDOWS
#include <winsock2.h>
#endif
#include "tcm.h"
#include "tcmutil.h"
#include "tcmfunc.h"

#ifdef __cplusplus
extern "C" {
#endif

int ForceClear();
int init(uint8_t mode);
int CreateAsymmKey(uint32_t *key_index);
int GetPubkey(uint32_t pubkey_index, uint8_t *pubkey, uint32_t *pubkeyLen);
int Sign(uint8_t *sign_data,uint32_t sign_len,uint8_t *sign_value,uint32_t *value_len,uint32_t prikey_index);
int Verify(uint8_t *sign_data,uint32_t sign_len,uint8_t *sign_value,uint32_t value_len,uint8_t *pubkey,uint32_t pubkeyLen);

#ifdef __cplusplus
}
#endif

#endif 
