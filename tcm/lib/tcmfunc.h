#ifndef TCMFUNC_H
#define TCMFUNC_H

#include <stdint.h>
#include "tcm_structures.h"
#include "tcmkeys.h"
#include "ap.h"

/* Admin startup */
uint32_t TCM_Startup();

/* Admin opt-in */
uint32_t TCM_PhysicalEnable(void);
uint32_t TCM_PhysicalSetDeactivated(TCM_BOOL state);
  
/* Admin ownership */
uint32_t TCM_TakeOwnership(	TCM_STORE_PUBKEY *pubEK, unsigned char *ownerauth, unsigned char *smkauth);
uint32_t TCM_OwnerClear(unsigned char *ownerauth, uint16_t entitytype, uint32_t entityvalue);
uint32_t TCM_ForceClear(void);

/* Capbility commands */
uint32_t TCM_GetCapability(uint32_t type, uint32_t subtype_length, uint8_t* subtype);

/* Key management commands */
uint32_t TCM_ReadPubek(TCM_PUBKEY *k);

uint32_t TCM_GetPubKey(uint32_t keyhandle, unsigned char *keyauth,	TCM_PUBKEY *pk);
uint32_t TCM_GetPubKey_internal(apsess *sess, uint32_t keyhandle, TCM_PUBKEY *tcmdata);
uint32_t TCM_CreateWrapKey(uint32_t keyhandle, unsigned char *parauth, unsigned char *newauth, 	unsigned char *migauth,
	TCM_KEY *keyparms, 	TCM_KEY *key, unsigned char *keyblob, unsigned int  *bloblen);
uint32_t TCM_LoadKey(uint32_t keyhandle, unsigned char *keyauth, TCM_KEY *keyparms, uint32_t *newhandle);
uint32_t TCM_LoadKey_internal(apsess* sess, uint32_t keyhandle, TCM_KEY *keyparms, uint32_t *newhandle);
uint32_t TCM_FlushSpecific(uint32_t resourceHandle, uint32_t resourceType);

uint32_t TCM_EvictKey(uint32_t keyhandle);

/* Crypto commands */
uint32_t TCM_Sign(uint32_t keyhandle, unsigned char *keyauth, unsigned char *data, uint32_t datalen, 
	unsigned char *sig, uint32_t *siglen);

/* PCR commands */
uint32_t TCM_Extend(uint32_t pcrIndex, unsigned char * event, unsigned char * outDigest);
uint32_t TCM_PcrRead(uint32_t pcrIndex, unsigned  char *pcrvalue);
uint32_t TCM_PcrReset(uint32_t pcrIndex);
uint32_t TCM_PcrExtend(uint32_t pcrIndex, unsigned char *pcrvalue);

/* Other commands */
uint32_t TCM_ReadFile(const char * filename, unsigned char ** buffer, uint32_t * buffersize);

uint32_t TCM_WriteFile(const char * filename, unsigned char * buffer, uint32_t buffersize);

/* THE COMMANDS BELOW ARE NOT TESTED, NOT SUGGESTED TO USE */

/* Crypto commands */
uint32_t TCM_Verify(TCM_PUBKEY *key, unsigned char *signedData, uint32_t signedDataSize, unsigned char *signatureValue, uint32_t signatureValueSize,
	unsigned char *ownerAuth, unsigned char *verifyResult);
uint32_t TCM_EccEncrypt(TCM_PUBKEY * key,
	unsigned char * areaToEnc, uint32_t areaToEncSize,
	unsigned char *ownerAuth,
	unsigned char *enc, uint32_t *encSize);

uint32_t TCM_EccDecrypt(uint32_t keyhandle, unsigned char *keyauth,
	unsigned char *data, uint32_t datalen, 
	unsigned char *blob, uint32_t *bloblen);

uint32_t TCM_SMS4Encrypt(uint32_t keyhandle, unsigned char *keyauth,
	unsigned char *data, uint32_t datalen, 
	unsigned char *IV, unsigned char *blob, uint32_t *bloblen);

uint32_t TCM_SMS4Decrypt(uint32_t keyhandle, unsigned char *keyauth, unsigned char *IV,
	unsigned char *data, uint32_t datalen, 
	unsigned char *blob, uint32_t *bloblen);

/* Other commands */
uint32_t TCM_GetKeyHandle(UINT32 *respSize, BYTE *resp);
uint32_t TCM_GetRandom(UINT32 len, BYTE *data);

/* NV commands */
uint32_t TCM_NV_DefineSpace(unsigned char index,BYTE nvSize[],BYTE attribute[]);
uint32_t TCM_NV_WriteValue(unsigned char index, BYTE offset[], BYTE *nvSize,unsigned char *buffer_Data);
uint32_t TCM_NV_ReadValue(unsigned char index, BYTE offset[], BYTE *nvSize, unsigned char * buffer_Data);

/*TCM SCH(SM3) commands */
uint32_t TCM_SCHStart(uint32_t* max);
uint32_t TCM_SCHUpdate(unsigned char * data,uint32_t len);
uint32_t TCM_SCHComplete(unsigned char * data,uint32_t len,unsigned char * digest);


/* Interface for 706 */
#define USERS_MAX 12
#define KEYS_MAX 12
typedef struct _TCM_USERS{  //One User 64 Bytes
    uint32_t index;
    char user_name[16];
    uint32_t name_len;
    uint32_t pin_type;
    uint8_t pin[32];
    uint32_t pin_len;
}TCM_USER;
typedef struct _ALL_USERS{  //800 Bytes MAX
    uint32_t count;
    TCM_USER user[USERS_MAX];
}TCM_ALL_USERS;

typedef struct _TCM_KEY_Store{
    uint32_t count;
    uint32_t index;
    uint32_t keyLength;
    unsigned char keyBlob[700];
}TCM_STORED_KEY;

int Tspi_Init(uint8_t mode);  //mode:  1:firtly use; 2:later use
//1. User Password Management
int Tspi_AddUser(char *user_name,uint32_t name_len,uint32_t pin_type, uint8_t *pin,uint32_t pin_len);
int Tspi_DelPin(char *user_name,uint32_t name_len,uint8_t *pin,uint32_t pinlen);
int Tspi_ModifyPin(char *user_name,uint32_t name_len,uint8_t *old_pin,uint32_t old_len,uint8_t * *new_pin,uint32_t new_len);
int Tspi_Login(char *user_name,uint32_t name_len,uint8_t *pin,uint32_t pin_len);
//2. Key Management
int Tspi_CreateSymmKey(uint32_t *key_index);
int Tspi_ExportKey(uint32_t *key_index, uint8_t *key);
int Tspi_DestroyKey(uint32_t *key_index);
//3. Crypto Service Interface
int Tspi_GetRandom(UINT32 len,BYTE *data);
int Tspi_Hash (uint8_t *in_data,uint32_t indata_len,uint8_t *out_data,uint32_t out_datalen);
//SM2 Key only for sign. SM2 Private key and Public key are same index. The index is the NV index.
int Tspi_CreateAsymmKey(uint32_t *key_index);   
//Tspi_DestroyKey could destroy Asymmkey also
//int Tspi_DestroyKey(uint32_t *key_index);						
int Tspi_Signature(uint8_t *sign_data,uint32_t sign_len,uint8_t *sign_value,uint32_t *value_len,uint32_t prikey_index);
int Tspi_ECC_Verification(uint8_t *sign_data,uint32_t sign_len,uint8_t *sign_value,uint32_t value_len,uint32_t pubkey_index);
//4. PCR Management
int Tspi_GetPcrValue (UINT32 PcrIndex,BYTE *PcrValue);
int Tspi_SetPcrValue (UINT32 PcrIndex,BYTE *PcrValue);
int Tspi_DelPcrValue (UINT32 PcrIndex);
/* Interface 706 end */
//uint32_t Unpack32(uint8_t * src);
void Value2Array(char *dest, unsigned int src, int size);
//void Pack32(BYTE* dst, int val);

//byj add
int Tspi_GetPubkey(uint32_t pubkey_index, uint8_t *pubkey, uint32_t *pubkeyLen);
int Tspi_Verify(uint8_t *sign_data,uint32_t sign_len,uint8_t *sign_value,uint32_t value_len,uint8_t *pubkey,uint32_t pubkeyLen);

#endif
