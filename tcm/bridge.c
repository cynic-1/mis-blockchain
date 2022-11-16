#include "bridge.h"

int ForceClear() {
    return TCM_ForceClear();
}

int init(uint8_t mode) {
    TCM_setlog(0);
    return Tspi_Init(mode);
}

int CreateAsymmKey(uint32_t *key_index) {
    return Tspi_CreateAsymmKey(key_index);
}

int GetPubkey(uint32_t pubkey_index, uint8_t *pubkey, uint32_t *pubkeyLen) {
    return Tspi_GetPubkey(pubkey_index, pubkey, pubkeyLen);
}

int Sign(uint8_t *sign_data,uint32_t sign_len,uint8_t *sign_value,uint32_t *value_len,uint32_t prikey_index) {
    /*
    int Tspi_Signature(uint8_t *sign_data,uint32_t sign_len,uint8_t *sign_value,uint32_t value_len,uint32_t prikey_index)
	*/
    return Tspi_Signature(sign_data, sign_len, sign_value, value_len, prikey_index);
}

int Verify(uint8_t *sign_data,uint32_t sign_len,uint8_t *sign_value,uint32_t value_len,uint8_t *pubkey,uint32_t pubkeyLen) {
    return Tspi_Verify(sign_data, sign_len, sign_value, value_len, pubkey, pubkeyLen);
}
