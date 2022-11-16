#ifndef _TCM_MARSHALLING_H_
#define _TCM_MARSHALLING_H_

//#include "tcm_emulator.h"
#include "tcm_structures.h"
#include <memory.h>
//#include "tpm_emulator_config.h"

/*
 * The following functions perform the data marshalling of all
 * TCM structures which are used
 * either as an input or an output parameter by one of the
 * TCM commands
 */

/**
 * tcm_marshal_TYPE - marshals a value of type TYPE
 * @ptr: target buffer to store the marshalled value into
 * @length: length of the target buffer
 * @v: value to marshal
 * Returns: 0 on success, -1 otherwise
 *
 * Description: Performs the data marshalling for values of type TYPE.
 * On success 0 is returned and the values of ptr as well as length are
 * updated (i.e., ptr := ptr + sizeof(marshalled value) and length :=
 * length - sizeof(marshalled value)). In case of an error, -1 is
 * returned and the values of ptr and length are undefined.
 */

/**
 * tcm_unmarshal_TYPE - unmarshals a value of type TYPE
 * @ptr: source buffer containing the marshalled value
 * @length: length of the source buffer
 * @v: variable to store the unmarshalled value into
 * Returns: 0 on success, -1 otherwise
 *
 * Description: Performs the data unmarshalling for values of type TYPE.
 * On success 0 is returned and the values of ptr as well as length are
 * updated (i.e., ptr := ptr + sizeof(marshalled value) and length :=
 * length - sizeof(marshalled value)). In case of an error, -1 is
 * returned and the values of ptr and length are undefined.
 */

static inline int tcm_marshal_BYTE(BYTE **ptr, UINT32 *length, BYTE v)
{
  if (*length < 1) return -1;
  **ptr = v;
  *ptr += 1; *length -= 1;
  return 0;
}

static inline int tcm_unmarshal_BYTE(BYTE **ptr, UINT32 *length, BYTE *v)
{
  if (*length < 1) return -1;
  *v = **ptr;
  *ptr += 1; *length -= 1;
  return 0;
}

static inline int tcm_marshal_UINT16(BYTE **ptr, UINT32 *length, UINT16 v)
{
  if (*length < 2) return -1;
#ifndef TCM_MEMORY_ALIGNMENT_MANDATORY  
  **(UINT16**)ptr = CPU_TO_BE16(v);
#else  
  (*ptr)[0] = (v >> 8) & 0xff; 
  (*ptr)[1] = v & 0xff;
#endif  
  *ptr += 2; *length -= 2;
  return 0;
}

static inline int tcm_unmarshal_UINT16(BYTE **ptr, UINT32 *length, UINT16 *v)
{
  if (*length < 2) return -1;
#ifndef TCM_MEMORY_ALIGNMENT_MANDATORY
  *v = BE16_TO_CPU(**(UINT16**)ptr);
#else  
  *v = (((UINT16)(*ptr)[0] << 8) | (*ptr)[1]);
#endif  
  *ptr += 2; *length -= 2;
  return 0;
}

static inline int tcm_marshal_UINT32(BYTE **ptr, UINT32 *length, UINT32 v)
{
  if (*length < 4) return -1;
#ifndef TCM_MEMORY_ALIGNMENT_MANDATORY
  **(UINT32**)ptr = CPU_TO_BE32(v);
#else  
  (*ptr)[0] = (v >> 24) & 0xff; (*ptr)[1] = (v >> 16) & 0xff;
  (*ptr)[2] = (v >>  8) & 0xff; (*ptr)[3] = v & 0xff;
#endif
  *ptr += 4; *length -= 4;
  return 0;
}

static inline int tcm_unmarshal_UINT32(BYTE **ptr, UINT32 *length, UINT32 *v)
{
  if (*length < 4) return -1;
#ifndef TCM_MEMORY_ALIGNMENT_MANDATORY
  *v = BE32_TO_CPU(**(UINT32**)ptr);
#else
  *v = (((UINT32)(*ptr)[0] << 24) | ((UINT32)(*ptr)[1] << 16) | 
        ((UINT32)(*ptr)[2] <<  8) | (*ptr)[3]);
#endif
  *ptr += 4; *length -= 4;
  return 0;
}

static inline int tcm_marshal_UINT64(BYTE **ptr, UINT32 *length, UINT64 v)
{
  if (*length < 8) return -1;
#ifndef TCM_MEMORY_ALIGNMENT_MANDATORY
  **(UINT64**)ptr = CPU_TO_BE64(v);
#else  
  (*ptr)[0] = (v >> 56) & 0xff; (*ptr)[1] = (v >> 48) & 0xff;
  (*ptr)[2] = (v >> 40) & 0xff; (*ptr)[3] = (v >> 32) & 0xff;
  (*ptr)[4] = (v >> 24) & 0xff; (*ptr)[5] = (v >> 16) & 0xff;
  (*ptr)[6] = (v >>  8) & 0xff; (*ptr)[7] = v & 0xff;
#endif  
  *ptr += 8; *length -= 8;
  return 0;
}

static inline int tcm_unmarshal_UINT64(BYTE **ptr, UINT32 *length, UINT64 *v)
{
  if (*length < 8) return -1;
#ifndef TCM_MEMORY_ALIGNMENT_MANDATORY
  *v = BE64_TO_CPU(**(UINT64**)ptr);
#else
  *v = (((UINT64)(*ptr)[0] << 56) | ((UINT64)(*ptr)[1] << 48) |
        ((UINT64)(*ptr)[2] << 40) | ((UINT64)(*ptr)[3] << 32) |
        ((UINT64)(*ptr)[4] << 24) | ((UINT64)(*ptr)[5] << 16) |
        ((UINT64)(*ptr)[6] <<  8) | (*ptr)[7]);
#endif
  *ptr += 8; *length -= 8;
  return 0;
}

static inline int tcm_marshal_BLOB(BYTE **ptr, UINT32 *ptr_length,
                                   BYTE *b, UINT32 b_length)
{
  if (*ptr_length < b_length) return -1;
  if (b_length) memcpy(*ptr, b, b_length);
  *ptr += b_length; *ptr_length -= b_length;
  return 0;
}

static inline int tcm_unmarshal_BLOB(BYTE **ptr, UINT32 *ptr_length,
                                     BYTE **b, UINT32 b_length)
{
  if (*ptr_length < b_length) return -1;
  *b = (b_length) ? *ptr : NULL;
  *ptr += b_length; *ptr_length -= b_length;
  return 0;
}

static inline int tcm_marshal_BYTE_ARRAY(BYTE **ptr, UINT32 *ptr_length,
                                         BYTE *b, UINT32 b_length)
{
  if (*ptr_length < b_length) return -1;
  memcpy(*ptr, b, b_length);
  *ptr += b_length; *ptr_length -= b_length;
  return 0;
}

static inline int tcm_unmarshal_BYTE_ARRAY(BYTE **ptr, UINT32 *ptr_length,
                                           BYTE *b, UINT32 b_length)
{
  if (*ptr_length < b_length) return -1;
  if (b_length) memcpy(b, *ptr, b_length);
  *ptr += b_length; *ptr_length -= b_length;
  return 0;
}

#define tcm_marshal_BOOL                       tcm_marshal_BYTE
#define tcm_unmarshal_BOOL                     tcm_unmarshal_BYTE
#define tcm_marshal_BOOL_ARRAY                 tcm_marshal_BYTE_ARRAY
#define tcm_unmarshal_BOOL_ARRAY               tcm_unmarshal_BYTE_ARRAY
#define tcm_marshal_TCM_AUTH_DATA_USAGE        tcm_marshal_BYTE
#define tcm_unmarshal_TCM_AUTH_DATA_USAGE      tcm_unmarshal_BYTE
#define tcm_marshal_TCM_PAYLOAD_TYPE           tcm_marshal_BYTE
#define tcm_unmarshal_TCM_PAYLOAD_TYPE         tcm_unmarshal_BYTE
#define tcm_marshal_TCM_ENTITY_TYPE			   tcm_marshal_BYTE
#define tcm_unmarshal_TCM_ENTITY_TYPE		   tcm_unmarshal_BYTE
#define tcm_marshal_TCM_TAG                    tcm_marshal_UINT16
#define tcm_unmarshal_TCM_TAG                  tcm_unmarshal_UINT16
#define tcm_marshal_TCM_STRUCTURE_TAG          tcm_marshal_UINT16
#define tcm_unmarshal_TCM_STRUCTURE_TAG        tcm_unmarshal_UINT16
#define tcm_marshal_TCM_KEY_USAGE              tcm_marshal_UINT16
#define tcm_unmarshal_TCM_KEY_USAGE            tcm_unmarshal_UINT16
#define tcm_marshal_TCM_ENC_SCHEME             tcm_marshal_UINT16
#define tcm_unmarshal_TCM_ENC_SCHEME           tcm_unmarshal_UINT16
#define tcm_marshal_TCM_SIG_SCHEME             tcm_marshal_UINT16
#define tcm_unmarshal_TCM_SIG_SCHEME           tcm_unmarshal_UINT16
#define tcm_marshal_TCM_COMMAND_CODE           tcm_marshal_UINT32
#define tcm_unmarshal_TCM_COMMAND_CODE         tcm_unmarshal_UINT32
#define tcm_marshal_TCM_RESULT                 tcm_marshal_UINT32
#define tcm_unmarshal_TCM_RESULT               tcm_unmarshal_UINT32
#define tcm_marshal_TCM_AUTHHANDLE             tcm_marshal_UINT32
#define tcm_unmarshal_TCM_AUTHHANDLE           tcm_unmarshal_UINT32
#define tcm_marshal_TCM_KEY_HANDLE             tcm_marshal_UINT32
#define tcm_unmarshal_TCM_KEY_HANDLE           tcm_unmarshal_UINT32
#define tcm_marshal_TCM_HANDLE                 tcm_marshal_UINT32
#define tcm_unmarshal_TCM_HANDLE               tcm_unmarshal_UINT32
#define tcm_marshal_TCM_KEY_FLAGS              tcm_marshal_UINT32
#define tcm_unmarshal_TCM_KEY_FLAGS            tcm_unmarshal_UINT32
#define tcm_marshal_TCM_ALGORITHM_ID           tcm_marshal_UINT32
#define tcm_unmarshal_TCM_ALGORITHM_ID         tcm_unmarshal_UINT32
#define tcm_marshal_TCM_PCRINDEX               tcm_marshal_UINT32
#define tcm_unmarshal_TCM_PCRINDEX             tcm_unmarshal_UINT32


int tcm_marshal_UINT32_ARRAY(BYTE **ptr, UINT32 *length, UINT32 *v, UINT32 n);
int tcm_unmarshal_UINT32_ARRAY(BYTE **ptr, UINT32 *length, UINT32 *v, UINT32 n);
/*
int tcm_marshal_TCM_STRUCT_VER(BYTE **ptr, UINT32 *length, TCM_STRUCT_VER *v);
int tcm_unmarshal_TCM_STRUCT_VER(BYTE **ptr, UINT32 *length, TCM_STRUCT_VER *v);

int tcm_marshal_TCM_VERSION(BYTE **ptr, UINT32 *length, TCM_VERSION *v);
int tcm_unmarshal_TCM_VERSION(BYTE **ptr, UINT32 *length, TCM_VERSION *v);
*/
int tcm_marshal_TCM_DIGEST(BYTE **ptr, UINT32 *length, TCM_DIGEST *v);
int tcm_unmarshal_TCM_DIGEST(BYTE **ptr, UINT32 *length, TCM_DIGEST *v);

//#define tcm_marshal_TCM_CHOSENID_HASH          tcm_marshal_TCM_DIGEST
//#define tcm_unmarshal_TCM_CHOSENID_HASH        tcm_unmarshal_TCM_DIGEST
#define tcm_marshal_TCM_COMPOSITE_HASH         tcm_marshal_TCM_DIGEST
#define tcm_unmarshal_TCM_COMPOSITE_HASH       tcm_unmarshal_TCM_DIGEST
//#define tcm_marshal_TCM_DIRVALUE               tcm_marshal_TCM_DIGEST
//#define tcm_unmarshal_TCM_DIRVALUE             tcm_unmarshal_TCM_DIGEST
#define tcm_marshal_TCM_HMAC                   tcm_marshal_TCM_DIGEST
#define tcm_unmarshal_TCM_HMAC                 tcm_unmarshal_TCM_DIGEST
#define tcm_marshal_TCM_PCRVALUE               tcm_marshal_TCM_DIGEST
#define tcm_unmarshal_TCM_PCRVALUE             tcm_unmarshal_TCM_DIGEST

int tcm_marshal_TCM_PCRVALUE_ARRAY(BYTE **ptr, UINT32 *length, TCM_PCRVALUE *v, UINT32 n);
int tcm_unmarshal_TCM_PCRVALUE_ARRAY(BYTE **ptr, UINT32 *length, TCM_PCRVALUE *v, UINT32 n);

int tcm_marshal_TCM_NONCE(BYTE **ptr, UINT32 *length, TCM_NONCE *v);
int tcm_unmarshal_TCM_NONCE(BYTE **ptr, UINT32 *length, TCM_NONCE *v);

int tcm_marshal_TCM_AUTHDATA(BYTE **ptr, UINT32 *length, TCM_AUTHDATA *v);
int tcm_unmarshal_TCM_AUTHDATA(BYTE **ptr, UINT32 *length, TCM_AUTHDATA *v);

#define tcm_marshal_TCM_SECRET                 tcm_marshal_TCM_AUTHDATA
#define tcm_unmarshal_TCM_SECRET               tcm_unmarshal_TCM_AUTHDATA
#define tcm_marshal_TCM_ENCAUTH                tcm_marshal_TCM_AUTHDATA
#define tcm_unmarshal_TCM_ENCAUTH              tcm_unmarshal_TCM_AUTHDATA

int tcm_marshal_TCM_AUTH(BYTE **ptr, UINT32 *length, TCM_AUTH *v);
int tcm_unmarshal_TCM_AUTH(BYTE **ptr, UINT32 *length, TCM_AUTH *v);
/*
int tcm_marshal_TCM_KEY_HANDLE_LIST(BYTE **ptr, UINT32 *length, TCM_KEY_HANDLE_LIST *v);

int tcm_marshal_TCM_CHANGEAUTH_VALIDATE(BYTE **ptr, UINT32 *length, TCM_CHANGEAUTH_VALIDATE *v);
int tcm_unmarshal_TCM_CHANGEAUTH_VALIDATE(BYTE **ptr, UINT32 *length, TCM_CHANGEAUTH_VALIDATE *v);

int tcm_marshal_TCM_COUNTER_VALUE(BYTE **ptr, UINT32 *length, TCM_COUNTER_VALUE *v);
int tcm_unmarshal_TCM_COUNTER_VALUE(BYTE **ptr, UINT32 *length, TCM_COUNTER_VALUE *v);
*/
int tcm_marshal_TCM_PCR_SELECTION(BYTE **ptr, UINT32 *length, TCM_PCR_SELECTION *v);
int tcm_unmarshal_TCM_PCR_SELECTION(BYTE **ptr, UINT32 *length, TCM_PCR_SELECTION *v);

int tcm_marshal_TCM_PCR_COMPOSITE(BYTE **ptr, UINT32 *length, TCM_PCR_COMPOSITE *v);
int tcm_unmarshal_TCM_PCR_COMPOSITE(BYTE **ptr, UINT32 *length, TCM_PCR_COMPOSITE *v);

int tcm_marshal_TCM_PCR_INFO(BYTE **ptr, UINT32 *length, TCM_PCR_INFO *v);
int tcm_unmarshal_TCM_PCR_INFO(BYTE **ptr, UINT32 *length, TCM_PCR_INFO *v);
/*
int tcm_marshal_TCM_PCR_INFO_SHORT(BYTE **ptr, UINT32 *length, TCM_PCR_INFO_SHORT *v);
int tcm_unmarshal_TCM_PCR_INFO_SHORT(BYTE **ptr, UINT32 *length, TCM_PCR_INFO_SHORT *v);

int tcm_marshal_TCM_PCR_ATTRIBUTES(BYTE **ptr, UINT32 *length, TCM_PCR_ATTRIBUTES *v);
int tcm_unmarshal_TCM_PCR_ATTRIBUTES(BYTE **ptr, UINT32 *length, TCM_PCR_ATTRIBUTES *v);
*/
int tcm_marshal_TCM_STORED_DATA(BYTE **ptr, UINT32 *length, TCM_STORED_DATA *v);
int tcm_unmarshal_TCM_STORED_DATA(BYTE **ptr, UINT32 *length, TCM_STORED_DATA *v);

int tcm_marshal_TCM_SEALED_DATA(BYTE **ptr, UINT32 *length, TCM_SEALED_DATA *v);
int tcm_unmarshal_TCM_SEALED_DATA(BYTE **ptr, UINT32 *length, TCM_SEALED_DATA *v);


int tcm_marshal_TCM_SYMMETRIC_KEY(BYTE **ptr, UINT32 *length, TCM_SYMMETRIC_KEY *v);
int tcm_unmarshal_TCM_SYMMETRIC_KEY(BYTE **ptr, UINT32 *length, TCM_SYMMETRIC_KEY *v);

int tcm_marshal_TCM_ECC_ASYMKEY_PARMS(BYTE **ptr, UINT32 *length, TCM_ECC_ASYMKEY_PARMS *v);
int tcm_unmarshal_TCM_ECC_ASYMKEY_PARMS(BYTE **ptr, UINT32 *length, TCM_ECC_ASYMKEY_PARMS *v);

int tcm_marshal_TCM_SYMMETRIC_KEY_PARMS(BYTE **ptr, UINT32 *length, TCM_SYMMETRIC_KEY_PARMS *v);
int tcm_unmarshal_TCM_SYMMETRIC_KEY_PARMS(BYTE **ptr, UINT32 *length, TCM_SYMMETRIC_KEY_PARMS *v);

//int tcm_marshal_TCM_RSA_KEY_PARMS(BYTE **ptr, UINT32 *length, TCM_RSA_KEY_PARMS *v);
//int tcm_unmarshal_TCM_RSA_KEY_PARMS(BYTE **ptr, UINT32 *length, TCM_RSA_KEY_PARMS *v);

//////////////////////////////////¶ÔTCM_ECC_ASYMKEY_PARMSµÄ±à½âÂë

int tcm_marshal_TCM_KEY_PARMS(BYTE **ptr, UINT32 *length, TCM_KEY_PARMS *v);
int tcm_unmarshal_TCM_KEY_PARMS(BYTE **ptr, UINT32 *length, TCM_KEY_PARMS *v);

int tcm_marshal_TCM_STORE_PUBKEY(BYTE **ptr, UINT32 *length, TCM_STORE_PUBKEY *v);
int tcm_unmarshal_TCM_STORE_PUBKEY(BYTE **ptr, UINT32 *length, TCM_STORE_PUBKEY *v);

int tcm_marshal_TCM_KEY(BYTE **ptr, UINT32 *length, TCM_KEY *v);
int tcm_unmarshal_TCM_KEY(BYTE **ptr, UINT32 *length, TCM_KEY *v);

int tcm_marshal_TCM_PUBKEY(BYTE **ptr, UINT32 *length, TCM_PUBKEY *v);
int tcm_unmarshal_TCM_PUBKEY(BYTE **ptr, UINT32 *length, TCM_PUBKEY *v);

int tcm_marshal_TCM_STORE_PRIVKEY(BYTE **ptr, UINT32 *length, TCM_STORE_PRIVKEY *v);
int tcm_unmarshal_TCM_STORE_PRIVKEY(BYTE **ptr, UINT32 *length, TCM_STORE_PRIVKEY *v);

int tcm_marshal_TCM_STORE_ASYMKEY(BYTE **ptr, UINT32 *length, TCM_STORE_ASYMKEY *v);
int tcm_unmarshal_TCM_STORE_ASYMKEY(BYTE **ptr, UINT32 *length, TCM_STORE_ASYMKEY *v);

//////////////////////NEW TCM_STORE_SYMKEY
int tcm_marshal_TCM_STORE_SYMKEY(BYTE **ptr, UINT32 *length, TCM_STORE_SYMKEY *v);
int tcm_unmarshal_TCM_STORE_SYMKEY(BYTE **ptr, UINT32 *length, TCM_STORE_SYMKEY *v);

//int tcm_marshal_TCM_MIGRATIONKEYAUTH(BYTE **ptr, UINT32 *length, TCM_MIGRATIONKEYAUTH *v);
//int tcm_unmarshal_TCM_MIGRATIONKEYAUTH(BYTE **ptr, UINT32 *length, TCM_MIGRATIONKEYAUTH *v);

int tcm_marshal_TCM_CERTIFY_INFO(BYTE **ptr, UINT32 *length, TCM_CERTIFY_INFO *v);
int tcm_unmarshal_TCM_CERTIFY_INFO(BYTE **ptr, UINT32 *length, TCM_CERTIFY_INFO *v);
/*
int tcm_marshal_TCM_IDENTITY_CONTENTS(BYTE **ptr, UINT32 *length, TCM_IDENTITY_CONTENTS *v);
int tcm_unmarshal_TCM_IDENTITY_CONTENTS(BYTE **ptr, UINT32 *length, TCM_IDENTITY_CONTENTS *v);

int tcm_marshal_TCM_CURRENT_TICKS(BYTE **ptr, UINT32 *length, TCM_CURRENT_TICKS *v);
int tcm_unmarshal_TCM_CURRENT_TICKS(BYTE **ptr, UINT32 *length, TCM_CURRENT_TICKS *v);

*/
int tcm_marshal_TCM_QUOTE_INFO(BYTE **ptr, UINT32 *length, TCM_QUOTE_INFO *v);
int tcm_unmarshal_TCM_QUOTE_INFO(BYTE **ptr, UINT32 *length, TCM_QUOTE_INFO *v);
/*
int tcm_marshal_RSA(BYTE **ptr, UINT32 *length, tcm_rsa_private_key_t *v);
int tcm_unmarshal_RSA(BYTE **ptr, UINT32 *length, tcm_rsa_private_key_t *v);
*/
/*
int tcm_marshal_TCM_ASYMKEY(BYTE **ptr, UINT32 *length, TCM_ASYMKEY *v)
int tcm_unmarshal_TCM_ASYMKEY(BYTE **ptr, UINT32 *length, TCM_ASYMKEY *v)

int tcm_marshal_TCM_SYMKEY(BYTE **ptr, UINT32 *length, TCM_SYMKEY *v)
int tcm_unmarshal_TCM_SYMKEY(BYTE **ptr, UINT32 *length, TCM_SYMKEY *v)
*/

int tcm_marshal_TCM_KEY_DATA(BYTE **ptr, UINT32 *length, TCM_KEY_DATA *v);
int tcm_unmarshal_TCM_KEY_DATA(BYTE **ptr, UINT32 *length, TCM_KEY_DATA *v);

int tcm_marshal_TCM_PERMANENT_DATA(BYTE **ptr, UINT32 *length, TCM_PERMANENT_DATA *);
int tcm_unmarshal_TCM_PERMANENT_DATA(BYTE **ptr, UINT32 *length, TCM_PERMANENT_DATA *);
/*
int tcm_marshal_TCM_STCLEAR_DATA(BYTE **ptr, UINT32 *length, TCM_STCLEAR_DATA *v);
int tcm_unmarshal_TCM_STCLEAR_DATA(BYTE **ptr, UINT32 *length, TCM_STCLEAR_DATA *v);
*/
int tcm_marshal_TCM_SESSION_DATA(BYTE **ptr, UINT32 *length, TCM_SESSION_DATA *v);
int tcm_unmarshal_TCM_SESSION_DATA(BYTE **ptr, UINT32 *length, TCM_SESSION_DATA *v);

int tcm_marshal_TCM_STANY_DATA(BYTE **ptr, UINT32 *length, TCM_STANY_DATA *v);
int tcm_unmarshal_TCM_STANY_DATA(BYTE **ptr, UINT32 *length, TCM_STANY_DATA *v);

int tcm_marshal_TCM_RESPONSE(BYTE **ptr, UINT32 *length, TCM_RESPONSE *v);
int tcm_unmarshal_TCM_REQUEST(BYTE **ptr, UINT32 *length, TCM_REQUEST *v);


#endif /* _TCM_MARSHALLING_H_ */