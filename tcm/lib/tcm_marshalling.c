#include "tcm_marshalling.h"
#include "tcm_handles.h"

int tcm_marshal_UINT32_ARRAY(BYTE **ptr, UINT32 *length,
                             UINT32 *v, UINT32 n)
{
  UINT32 i;
  for (i = 0; i < n; i++) {
    if (tcm_marshal_UINT32(ptr, length, v[i])) return -1;
  }
  return 0;
}

int tcm_unmarshal_UINT32_ARRAY(BYTE **ptr, UINT32 *length,
                               UINT32 *v, UINT32 n)
{
  UINT32 i;
  for (i = 0; i < n; i++) {
    if (tcm_unmarshal_UINT32(ptr, length, &v[i])) return -1;
  }
  return 0;
}


int tcm_marshal_TCM_DIGEST(BYTE **ptr, UINT32 *length, TCM_DIGEST *v)
{
  if (tcm_marshal_BYTE_ARRAY(ptr, length, v->digest, sizeof(v->digest))) return -1;
  return 0;
}

int tcm_unmarshal_TCM_DIGEST(BYTE **ptr, UINT32 *length, TCM_DIGEST *v)
{
  if (tcm_unmarshal_BYTE_ARRAY(ptr, length, v->digest, sizeof(v->digest))) return -1;
  return 0;
}

int tcm_marshal_TCM_PCRVALUE_ARRAY(BYTE **ptr, UINT32 *length,
                                   TCM_PCRVALUE *v, UINT32 n)
{
  UINT32 i;
  for (i = 0; i < n; i++) {
    if (tcm_marshal_TCM_PCRVALUE(ptr, length, &v[i])) return -1;
  }
  return 0;
}

int tcm_unmarshal_TCM_PCRVALUE_ARRAY(BYTE **ptr, UINT32 *length,
                                     TCM_PCRVALUE *v, UINT32 n)
{
  UINT32 i;
  for (i = 0; i < n; i++) {
    if (tcm_unmarshal_TCM_PCRVALUE(ptr, length, &v[i])) return -1;
  }
  return 0;
}

int tcm_marshal_TCM_NONCE(BYTE **ptr, UINT32 *length, TCM_NONCE *v)
{
  if (tcm_marshal_BYTE_ARRAY(ptr, length, v->NONCE, sizeof(v->NONCE))) return -1;
  return 0;
}

int tcm_unmarshal_TCM_NONCE(BYTE **ptr, UINT32 *length, TCM_NONCE *v)
{
  if (tcm_unmarshal_BYTE_ARRAY(ptr, length, v->NONCE, sizeof(v->NONCE))) return -1;
  return 0;
}

int tcm_marshal_TCM_AUTHDATA(BYTE **ptr, UINT32 *length, TCM_AUTHDATA *v)
{
  if (*length < sizeof(TCM_AUTHDATA)) return -1;
  memcpy(*ptr, v, sizeof(TCM_AUTHDATA));
  *ptr += sizeof(TCM_AUTHDATA); *length -= sizeof(TCM_AUTHDATA);
  return 0;
}

int tcm_unmarshal_TCM_AUTHDATA(BYTE **ptr, UINT32 *length, TCM_AUTHDATA *v)
{
  if (*length < sizeof(TCM_AUTHDATA)) return -1;
  memcpy(v, *ptr, sizeof(TCM_AUTHDATA));
  *ptr += sizeof(TCM_AUTHDATA); *length -= sizeof(TCM_AUTHDATA);
  return 0;
}

int tcm_marshal_TCM_AUTH(BYTE **ptr, UINT32 *length, TCM_AUTH *v)
{
  if (tcm_marshal_TCM_AUTHDATA(ptr, length, &v->auth)) return -1;
  return 0;
}

int tcm_unmarshal_TCM_AUTH(BYTE **ptr, UINT32 *length, TCM_AUTH *v)
{
  if (tcm_unmarshal_TCM_AUTHDATA(ptr, length, &v->auth)) return -1;
  return 0;
}


int tcm_marshal_TCM_PCR_SELECTION(BYTE **ptr, UINT32 *length, TCM_PCR_SELECTION *v)
{
  if (tcm_marshal_UINT16(ptr, length, v->sizeOfSelect)
      || v->sizeOfSelect > sizeof(v->pcrSelect) 
      || tcm_marshal_BYTE_ARRAY(ptr, length, v->pcrSelect, v->sizeOfSelect)) return -1;
  return 0;
}

int tcm_unmarshal_TCM_PCR_SELECTION(BYTE **ptr, UINT32 *length, TCM_PCR_SELECTION *v)
{
  if (tcm_unmarshal_UINT16(ptr, length, &v->sizeOfSelect)
      || v->sizeOfSelect > sizeof(v->pcrSelect)
      || tcm_unmarshal_BYTE_ARRAY(ptr, length, v->pcrSelect, v->sizeOfSelect)) return -1;
  return 0;
}

int tcm_marshal_TCM_PCR_COMPOSITE(BYTE **ptr, UINT32 *length, TCM_PCR_COMPOSITE *v)
{
  if (tcm_marshal_TCM_PCR_SELECTION(ptr, length, &v->select)
      || tcm_marshal_UINT32(ptr, length, v->valueSize)
      || v->valueSize > sizeof(v->pcrValue) 
      || tcm_marshal_TCM_PCRVALUE_ARRAY(ptr, length, v->pcrValue, 
                                        v->valueSize / sizeof(TCM_PCRVALUE))) return -1;
  return 0;
}

int tcm_unmarshal_TCM_PCR_COMPOSITE(BYTE **ptr, UINT32 *length, TCM_PCR_COMPOSITE *v)
{
  if (tcm_unmarshal_TCM_PCR_SELECTION(ptr, length, &v->select)
      || tcm_unmarshal_UINT32(ptr, length, &v->valueSize)
      || v->valueSize > sizeof(v->pcrValue)
      || tcm_unmarshal_TCM_PCRVALUE_ARRAY(ptr, length, v->pcrValue, 
                                          v->valueSize / sizeof(TCM_PCRVALUE))) return -1;
  return 0;
}

int tcm_marshal_TCM_PCR_INFO(BYTE **ptr, UINT32 *length, TCM_PCR_INFO *v)
{
   
  if (tcm_marshal_TCM_STRUCTURE_TAG(ptr, length, v->tag)
      || tcm_marshal_TCM_PCR_SELECTION(ptr, length, &v->creationPCRSelection)
      || tcm_marshal_TCM_PCR_SELECTION(ptr, length, &v->releasePCRSelection)
      || tcm_marshal_TCM_COMPOSITE_HASH(ptr, length, &v->digestAtCreation)
      || tcm_marshal_TCM_COMPOSITE_HASH(ptr, length, &v->digestAtRelease)) return -1;
  return 0;
}

int tcm_unmarshal_TCM_PCR_INFO(BYTE **ptr, UINT32 *length, TCM_PCR_INFO *v)
{

  if (tcm_unmarshal_TCM_STRUCTURE_TAG(ptr, length, &v->tag)
      || tcm_unmarshal_TCM_PCR_SELECTION(ptr, length, &v->creationPCRSelection)
      || tcm_unmarshal_TCM_PCR_SELECTION(ptr, length, &v->releasePCRSelection)
      || tcm_unmarshal_TCM_COMPOSITE_HASH(ptr, length, &v->digestAtCreation)
      || tcm_unmarshal_TCM_COMPOSITE_HASH(ptr, length, &v->digestAtRelease)) return -1; 
  return 0;
}

int tcm_marshal_TPM_STORED_DATA(BYTE **ptr, UINT32 *length, TCM_STORED_DATA *v)
{
	if (tcm_marshal_TCM_STRUCTURE_TAG(ptr, length, v->tag)
		|| tcm_marshal_TCM_ENTITY_TYPE(ptr, length, v->et)
		|| tcm_marshal_UINT32(ptr, length, v->sealInfoSize)
		|| (v->sealInfoSize > 0
		&& tcm_marshal_TCM_PCR_INFO(ptr, length, &v->sealInfo))
		|| tcm_marshal_UINT32(ptr, length, v->encDataSize)
		|| tcm_marshal_BLOB(ptr, length, v->encData, v->encDataSize)) return -1;
	return 0;
}

int tcm_unmarshal_TCM_STORED_DATA(BYTE **ptr, UINT32 *length, TCM_STORED_DATA *v)
{
  if (tcm_unmarshal_TCM_STRUCTURE_TAG(ptr, length, &v->tag)
      || tcm_unmarshal_TCM_ENTITY_TYPE(ptr, length, &v->et)
      || tcm_unmarshal_UINT32(ptr, length, &v->sealInfoSize)
      || (v->sealInfoSize > 0
          && tcm_unmarshal_TCM_PCR_INFO(ptr, length, &v->sealInfo))
      || tcm_unmarshal_UINT32(ptr, length, &v->encDataSize)
      || tcm_unmarshal_BLOB(ptr, length, &v->encData, v->encDataSize)) return -1;
  return 0;
}

int tcm_marshal_TCM_SEALED_DATA(BYTE **ptr, UINT32 *length, TCM_SEALED_DATA *v)
{
  if (tcm_marshal_TCM_PAYLOAD_TYPE(ptr, length, v->payload)
      || tcm_marshal_TCM_SECRET(ptr, length, &v->authData)
      || tcm_marshal_TCM_NONCE(ptr, length, &v->TCMProof)
      || tcm_marshal_TCM_DIGEST(ptr, length, &v->storedDigest)
      || tcm_marshal_UINT32(ptr, length, v->dataSize)
      || tcm_marshal_BLOB(ptr, length, v->data, v->dataSize)) return -1;
  return 0;
}

int tcm_unmarshal_TCM_SEALED_DATA(BYTE **ptr, UINT32 *length, TCM_SEALED_DATA *v)
{
  if (tcm_unmarshal_TCM_PAYLOAD_TYPE(ptr, length, &v->payload)
      || tcm_unmarshal_TCM_SECRET(ptr, length, &v->authData)
      || tcm_unmarshal_TCM_NONCE(ptr, length, &v->TCMProof)
      || tcm_unmarshal_TCM_DIGEST(ptr, length, &v->storedDigest)
      || tcm_unmarshal_UINT32(ptr, length, &v->dataSize)
      || tcm_unmarshal_BLOB(ptr, length, &v->data, v->dataSize)) return -1;
  return 0;
}

int tcm_marshal_TCM_SYMMETRIC_KEY(BYTE **ptr, UINT32 *length, TCM_SYMMETRIC_KEY *v)
{
  if (tcm_marshal_TCM_ALGORITHM_ID(ptr, length, v->algId)
      || tcm_marshal_TCM_ENC_SCHEME(ptr, length, v->encScheme)
      || tcm_marshal_UINT16(ptr, length, v->size)
      || tcm_marshal_BLOB(ptr, length, v->data, v->size)) return -1;
  return 0;
}

int tcm_unmarshal_TCM_SYMMETRIC_KEY(BYTE **ptr, UINT32 *length, TCM_SYMMETRIC_KEY *v)
{
  if (tcm_unmarshal_TCM_ALGORITHM_ID(ptr, length, &v->algId)
      || tcm_unmarshal_TCM_ENC_SCHEME(ptr, length, &v->encScheme)
      || tcm_unmarshal_UINT16(ptr, length, &v->size)
      || tcm_unmarshal_BLOB(ptr, length, &v->data, v->size)) return -1;
  return 0;
}

int tcm_marshal_TCM_ECC_ASYMKEY_PARMS(BYTE **ptr, UINT32 *length, TCM_ECC_ASYMKEY_PARMS *v)
{
	if (tcm_marshal_UINT32(ptr, length, v->keyLength)) return -1;
	return 0;
}

int tcm_unmarshal_TCM_ECC_ASYMKEY_PARMS(BYTE **ptr, UINT32 *length, TCM_ECC_ASYMKEY_PARMS *v)
{
	if (tcm_unmarshal_UINT32(ptr, length, &v->keyLength)) return -1;
	return 0;
}

int tcm_marshal_TCM_SYMMETRIC_KEY_PARMS(BYTE **ptr, UINT32 *length, TCM_SYMMETRIC_KEY_PARMS *v)
{
  if (tcm_marshal_UINT32(ptr, length, v->keyLength)
      || tcm_marshal_UINT32(ptr, length, v->blockSize)
      || tcm_marshal_UINT32(ptr, length, v->ivSize)
      || tcm_marshal_BLOB(ptr, length, v->IV, v->ivSize)) return -1;
  return 0;
}

int tcm_unmarshal_TCM_SYMMETRIC_KEY_PARMS(BYTE **ptr, UINT32 *length, TCM_SYMMETRIC_KEY_PARMS *v)
{
  if (tcm_unmarshal_UINT32(ptr, length, &v->keyLength)
      || tcm_unmarshal_UINT32(ptr, length, &v->blockSize)
      || tcm_unmarshal_UINT32(ptr, length, &v->ivSize)
      || tcm_unmarshal_BLOB(ptr, length, &v->IV, v->ivSize)) return -1;
  return 0;
}


int tcm_marshal_TCM_KEY_PARMS(BYTE **ptr, UINT32 *length, TCM_KEY_PARMS *v)
{
  if (tcm_marshal_TCM_ALGORITHM_ID(ptr, length, v->algorithmID)
      || tcm_marshal_TCM_ENC_SCHEME(ptr, length, v->encScheme)
      || tcm_marshal_TCM_SIG_SCHEME(ptr, length, v->sigScheme)
      || tcm_marshal_UINT32(ptr, length, v->parmSize)) return -1;
  switch (v->algorithmID) {
    case TCM_ALG_ECC:
      if (tcm_marshal_TCM_ECC_ASYMKEY_PARMS(ptr, length, &v->parms.ecc)) return -1;
      break;
    case TCM_ALG_SMS4:
      if (tcm_marshal_TCM_SYMMETRIC_KEY_PARMS(ptr, length, &v->parms.skp)) return -1;
      break;
    default:
      if (tcm_marshal_BLOB(ptr, length, v->parms.raw, v->parmSize)) return -1;
  }
  return 0;
}

int tcm_unmarshal_TCM_KEY_PARMS(BYTE **ptr, UINT32 *length, TCM_KEY_PARMS *v)
{
  if (tcm_unmarshal_TCM_ALGORITHM_ID(ptr, length, &v->algorithmID)
      || tcm_unmarshal_TCM_ENC_SCHEME(ptr, length, &v->encScheme)
      || tcm_unmarshal_TCM_SIG_SCHEME(ptr, length, &v->sigScheme)
      || tcm_unmarshal_UINT32(ptr, length, &v->parmSize)) return -1;
  switch (v->algorithmID) {
    case TCM_ALG_ECC:
      if (tcm_unmarshal_TCM_ECC_ASYMKEY_PARMS(ptr, length, &v->parms.ecc)) return -1;
      break;
    case TCM_ALG_SMS4:
      if (tcm_unmarshal_TCM_SYMMETRIC_KEY_PARMS(ptr, length, &v->parms.skp)) return -1;
      break;
    default:
      if (tcm_unmarshal_BLOB(ptr, length, &v->parms.raw, v->parmSize)) return -1;
  }
  return 0;
}

int tcm_marshal_TCM_STORE_PUBKEY(BYTE **ptr, UINT32 *length, TCM_STORE_PUBKEY *v)
{
  if (tcm_marshal_UINT32(ptr, length, v->keyLength)
      || tcm_marshal_BLOB(ptr, length, v->key, v->keyLength)) return -1;
  return 0;
}

int tcm_unmarshal_TCM_STORE_PUBKEY(BYTE **ptr, UINT32 *length, TCM_STORE_PUBKEY *v)
{
  if (tcm_unmarshal_UINT32(ptr, length, &v->keyLength)
      || tcm_unmarshal_BLOB(ptr, length, &v->key, v->keyLength)) return -1;
  return 0;
}

int tcm_marshal_TCM_KEY(BYTE **ptr, UINT32 *length, TCM_KEY *v)
{
  if (tcm_marshal_TCM_STRUCTURE_TAG(ptr, length, v->tag)
      || tcm_marshal_UINT16(ptr, length, v->fill)
      || tcm_marshal_TCM_KEY_USAGE(ptr, length, v->keyUsage)
      || tcm_marshal_TCM_KEY_FLAGS(ptr, length, v->keyFlags)
      || tcm_marshal_TCM_AUTH_DATA_USAGE(ptr, length, v->authDataUsage)
      || tcm_marshal_TCM_KEY_PARMS(ptr, length, &v->algorithmParms)
      || tcm_marshal_UINT32(ptr, length, v->PCRInfoSize)
      || (v->PCRInfoSize > 0
          && tcm_marshal_BLOB(ptr, length, v->PCRInfo, v->PCRInfoSize))
      || tcm_marshal_TCM_STORE_PUBKEY(ptr, length, &v->pubKey)
      || tcm_marshal_UINT32(ptr, length, v->encDataSize)
      || tcm_marshal_BLOB(ptr, length, v->encData, v->encDataSize)) return -1;
  return 0;
}

int tcm_unmarshal_TCM_KEY(BYTE **ptr, UINT32 *length, TCM_KEY *v)
{
  if (tcm_unmarshal_TCM_STRUCTURE_TAG(ptr, length, &v->tag)
      || tcm_unmarshal_UINT16(ptr, length, &v->fill)
      || tcm_unmarshal_TCM_KEY_USAGE(ptr, length, &v->keyUsage)
      || tcm_unmarshal_TCM_KEY_FLAGS(ptr, length, &v->keyFlags)
      || tcm_unmarshal_TCM_AUTH_DATA_USAGE(ptr, length, &v->authDataUsage)
      || tcm_unmarshal_TCM_KEY_PARMS(ptr, length, &v->algorithmParms)
      || tcm_unmarshal_UINT32(ptr, length, &v->PCRInfoSize)
      || (v->PCRInfoSize > 0
          && tcm_unmarshal_BLOB(ptr, length, &v->PCRInfo, v->PCRInfoSize))
      || tcm_unmarshal_TCM_STORE_PUBKEY(ptr, length, &v->pubKey)
      || tcm_unmarshal_UINT32(ptr, length, &v->encDataSize)
      || tcm_unmarshal_BLOB(ptr, length, &v->encData, v->encDataSize)) return -1;
  return 0;
}

int tcm_marshal_TCM_PUBKEY(BYTE **ptr, UINT32 *length, TCM_PUBKEY *v)
{
  if (tcm_marshal_TCM_KEY_PARMS(ptr, length, &v->algorithmParms)
      || tcm_marshal_TCM_STORE_PUBKEY(ptr, length, &v->pubKey)) return -1;
  return 0;
}

int tcm_unmarshal_TCM_PUBKEY(BYTE **ptr, UINT32 *length, TCM_PUBKEY *v)
{
  if (tcm_unmarshal_TCM_KEY_PARMS(ptr, length, &v->algorithmParms)
      || tcm_unmarshal_TCM_STORE_PUBKEY(ptr, length, &v->pubKey)) return -1;
  return 0;
}

int tcm_marshal_TCM_STORE_PRIVKEY(BYTE **ptr, UINT32 *length, TCM_STORE_PRIVKEY *v)
{
  if (tcm_marshal_UINT32(ptr, length, v->keyLength)
      || tcm_marshal_BLOB(ptr, length, v->key, v->keyLength)) return -1;
  return 0;
}

int tcm_unmarshal_TCM_STORE_PRIVKEY(BYTE **ptr, UINT32 *length, TCM_STORE_PRIVKEY *v)
{
  if (tcm_unmarshal_UINT32(ptr, length, &v->keyLength)
      || tcm_unmarshal_BLOB(ptr, length, &v->key, v->keyLength)) return -1;
  return 0;
}

int tcm_marshal_TCM_STORE_ASYMKEY(BYTE **ptr, UINT32 *length, TCM_STORE_ASYMKEY *v)
{
  if (tcm_marshal_TCM_PAYLOAD_TYPE(ptr, length, v->payload)
      || tcm_marshal_TCM_SECRET(ptr, length, &v->usageAuth)
      || tcm_marshal_TCM_SECRET(ptr, length, &v->migrationAuth)
      || tcm_marshal_TCM_DIGEST(ptr, length, &v->pubDataDigest)
      || tcm_marshal_TCM_STORE_PRIVKEY(ptr, length, &v->privKey)) return -1;
  return 0;
}

int tcm_unmarshal_TCM_STORE_ASYMKEY(BYTE **ptr, UINT32 *length, TCM_STORE_ASYMKEY *v)
{
  if (tcm_unmarshal_TCM_PAYLOAD_TYPE(ptr, length, &v->payload)
      || tcm_unmarshal_TCM_SECRET(ptr, length, &v->usageAuth)
      || tcm_unmarshal_TCM_SECRET(ptr, length, &v->migrationAuth)
      || tcm_unmarshal_TCM_DIGEST(ptr, length, &v->pubDataDigest)
      || tcm_unmarshal_TCM_STORE_PRIVKEY(ptr, length, &v->privKey)) return -1;
  return 0;
}

int tcm_marshal_TCM_STORE_SYMKEY(BYTE **ptr, UINT32 *length, TCM_STORE_SYMKEY *v)
{
	if (tcm_marshal_TCM_PAYLOAD_TYPE(ptr, length, v->payload)
		|| tcm_marshal_TCM_SECRET(ptr, length, &v->usageAuth)
		|| tcm_marshal_TCM_SECRET(ptr, length, &v->migrationAuth)
		|| tcm_marshal_UINT16(ptr, length, v->size)
		|| tcm_marshal_BLOB(ptr, length, v->data, v->size)) return -1;
	return 0;
}

int tcm_unmarshal_TCM_STORE_SYMKEY(BYTE **ptr, UINT32 *length, TCM_STORE_SYMKEY *v)
{
	if (tcm_unmarshal_TCM_PAYLOAD_TYPE(ptr, length, &v->payload)
		|| tcm_unmarshal_TCM_SECRET(ptr, length, &v->usageAuth)
		|| tcm_unmarshal_TCM_SECRET(ptr, length, &v->migrationAuth)
		|| tcm_unmarshal_UINT16(ptr, length, &v->size)
		|| tcm_unmarshal_BLOB(ptr, length, &v->data, v->size)) return -1;
	return 0;
}

int tcm_marshal_TCM_CERTIFY_INFO(BYTE **ptr, UINT32 *length, TCM_CERTIFY_INFO *v)
{
  if (tcm_marshal_TCM_KEY_USAGE(ptr, length, v->keyUsage)
      || tcm_marshal_TCM_KEY_FLAGS(ptr, length, v->keyFlags)
      || tcm_marshal_TCM_AUTH_DATA_USAGE(ptr, length, v->authDataUsage)
      || tcm_marshal_TCM_KEY_PARMS(ptr, length, &v->algorithmParms)
      || tcm_marshal_TCM_DIGEST(ptr, length, &v->pubkeyDigest)
      || tcm_marshal_TCM_NONCE(ptr, length, &v->data)
      || tcm_marshal_BOOL(ptr, length, v->parentPCRStatus)
      || tcm_marshal_UINT32(ptr, length, v->PCRInfoSize)
      || (v->PCRInfoSize > 0
          && tcm_marshal_TCM_PCR_INFO(ptr, length, &v->PCRInfo))) return -1;
  return 0;
}

int tcm_unmarshal_TCM_CERTIFY_INFO(BYTE **ptr, UINT32 *length, TCM_CERTIFY_INFO *v)
{
  if (tcm_unmarshal_TCM_KEY_USAGE(ptr, length, &v->keyUsage)
      || tcm_unmarshal_TCM_KEY_FLAGS(ptr, length, &v->keyFlags)
      || tcm_unmarshal_TCM_AUTH_DATA_USAGE(ptr, length, &v->authDataUsage)
      || tcm_unmarshal_TCM_KEY_PARMS(ptr, length, &v->algorithmParms)
      || tcm_unmarshal_TCM_DIGEST(ptr, length, &v->pubkeyDigest)
      || tcm_unmarshal_TCM_NONCE(ptr, length, &v->data)
      || tcm_unmarshal_BOOL(ptr, length, &v->parentPCRStatus)
      || tcm_unmarshal_UINT32(ptr, length, &v->PCRInfoSize)
      || (v->PCRInfoSize > 0
          && tcm_unmarshal_TCM_PCR_INFO(ptr, length, &v->PCRInfo))) return -1;
  return 0;
}

int tcm_marshal_TCM_QUOTE_INFO(BYTE **ptr, UINT32 *length, TCM_QUOTE_INFO *v)
{
  if (tcm_marshal_TCM_STRUCTURE_TAG(ptr, length, v->tag)
      || tcm_marshal_BYTE(ptr, length, v->fixed[0])
      || tcm_marshal_BYTE(ptr, length, v->fixed[1])
      || tcm_marshal_BYTE(ptr, length, v->fixed[2])
      || tcm_marshal_BYTE(ptr, length, v->fixed[3])
      || tcm_marshal_TCM_NONCE(ptr, length, &v->externalData)
      || tcm_marshal_TCM_PCR_INFO(ptr, length, &v->info))
        return -1;
  return 0;
}

int tcm_unmarshal_TCM_QUOTE_INFO(BYTE **ptr, UINT32 *length, TCM_QUOTE_INFO *v)
{
  if (tcm_unmarshal_TCM_STRUCTURE_TAG(ptr, length, &v->tag)
      || tcm_unmarshal_BYTE(ptr, length, &v->fixed[0])
      || tcm_unmarshal_BYTE(ptr, length, &v->fixed[1])
      || tcm_unmarshal_BYTE(ptr, length, &v->fixed[2])
      || tcm_unmarshal_BYTE(ptr, length, &v->fixed[3])
      || tcm_unmarshal_TCM_NONCE(ptr, length, &v->externalData)
      || tcm_unmarshal_TCM_PCR_INFO(ptr, length, &v->info))
        return -1;
  return 0;
}

/*
int tcm_marshal_TCM_ASYMKEY(BYTE **ptr, UINT32 *length, TCM_ASYMKEY *v)
{
	if (tcm_marshal_BYTE_ARRAY(ptr, length, v->privKey, sizeof(v->privKey)
		|| tcm_marshal_BYTE_ARRAY(ptr, length, v->pubKey, sizeof(v->pubKey))
		return -1;
	return 0;
}

int tcm_unmarshal_TCM_ASYMKEY(BYTE **ptr, UINT32 *length, TCM_ASYMKEY *v)
{
	if (tcm_unmarshal_BYTE_ARRAY(ptr, length, v->privKey, sizeof(v->privKey)
		|| tcm_unmarshal_BYTE_ARRAY(ptr, length, v->pubKey, sizeof(v->pubKey))
		return -1;
	return 0;
}


int tcm_marshal_TCM_SYMKEY(BYTE **ptr, UINT32 *length, TCM_SYMKEY *v)
{
	if (tcm_marshal_BYTE_ARRAY(ptr, length, v->key, sizeof(v->key)))
		return -1;
	return 0;
}

int tcm_unmarshal_TCM_SYMKEY(BYTE **ptr, UINT32 *length, TCM_SYMKEY *v)
{
	if (tcm_unmarshal_BYTE_ARRAY(ptr, length, v->key, sizeof(v->key)))
		return -1;
	return 0;
}
*/

/* || (v->keyFlags && tcm_marshal_TCM_PCR_INFO(ptr, length, &v->pcrInfo))  Ï¸½ÚÐÞ¸Ä*/
int tcm_marshal_TCM_KEY_DATA(BYTE **ptr, UINT32 *length, TCM_KEY_DATA *v)
{
  if (tcm_marshal_TCM_PAYLOAD_TYPE(ptr, length, v->payload)) return -1;
  if (v->payload) {
    if (tcm_marshal_TCM_KEY_USAGE(ptr, length, v->keyUsage)
        || tcm_marshal_TCM_KEY_FLAGS(ptr, length, v->keyFlags)
        || tcm_marshal_TCM_AUTH_DATA_USAGE(ptr, length, v->authDataUsage)
        || tcm_marshal_TCM_ENC_SCHEME(ptr, length, v->encScheme)
        || tcm_marshal_TCM_SIG_SCHEME(ptr, length, v->sigScheme)
        || tcm_marshal_TCM_SECRET(ptr, length, &v->usageAuth)
        || tcm_marshal_TCM_SECRET(ptr, length, &v->migrationAuth)
        || (v->keyFlags
            && tcm_marshal_TCM_PCR_INFO(ptr, length, &v->pcrInfo))
        || tcm_marshal_BOOL(ptr, length, v->parentPCRStatus)
        || tcm_marshal_BYTE_ARRAY(ptr, length, v->parms.asymKey.privKey, sizeof(v->parms.asymKey.privKey))
		|| tcm_marshal_BYTE_ARRAY(ptr, length, v->parms.asymKey.pubKey, sizeof(v->parms.asymKey.pubKey))) return -1;
  }
  return 0;
}

int tcm_unmarshal_TCM_KEY_DATA(BYTE **ptr, UINT32 *length, TCM_KEY_DATA *v)
{
  if (tcm_unmarshal_TCM_PAYLOAD_TYPE(ptr, length, &v->payload)) return -1;
  if (v->payload) {
    if (tcm_unmarshal_TCM_KEY_USAGE(ptr, length, &v->keyUsage)
        || tcm_unmarshal_TCM_KEY_FLAGS(ptr, length, &v->keyFlags)
        || tcm_unmarshal_TCM_AUTH_DATA_USAGE(ptr, length, &v->authDataUsage)
        || tcm_unmarshal_TCM_ENC_SCHEME(ptr, length, &v->encScheme)
        || tcm_unmarshal_TCM_SIG_SCHEME(ptr, length, &v->sigScheme)
        || tcm_unmarshal_TCM_SECRET(ptr, length, &v->usageAuth)
        || tcm_unmarshal_TCM_SECRET(ptr, length, &v->migrationAuth)
        || (v->keyFlags
            && tcm_unmarshal_TCM_PCR_INFO(ptr, length, &v->pcrInfo))
        || tcm_unmarshal_BOOL(ptr, length, &v->parentPCRStatus)
        || tcm_unmarshal_BYTE_ARRAY(ptr, length, v->parms.asymKey.privKey, sizeof(v->parms.asymKey.privKey))
		|| tcm_unmarshal_BYTE_ARRAY(ptr, length, v->parms.asymKey.pubKey, sizeof(v->parms.asymKey.pubKey))) return -1;
    }
  return 0;
}


int tcm_marshal_TCM_PERMANENT_DATA(BYTE **ptr, UINT32 *length, TCM_PERMANENT_DATA *v)
{
  UINT32 i;
  if (tcm_marshal_TCM_STRUCTURE_TAG(ptr, length, v->tag)
	  || tcm_marshal_TCM_NONCE(ptr, length, &v->TCMProof)
	  || tcm_marshal_TCM_SECRET(ptr, length, &v->ownerAuth)
	  || tcm_marshal_TCM_KEY_DATA(ptr,length, &v->endorsementKey)
	  //|| tcm_marshal_BYTE_ARRAY(ptr, length, &v->endorsementKey, sizeof(v->endorsementKey))
	  || tcm_marshal_TCM_KEY_DATA(ptr, length, &v->smk)) return -1;
  for (i = 0; i < TCM_NUM_PCR; i++)   {
   if (tcm_marshal_TCM_PCRVALUE(ptr, length, &v->pcrValue[i])) return -1;
  }
  return 0;
}

int tcm_unmarshal_TCM_PERMANENT_DATA(BYTE **ptr, UINT32 *length, TCM_PERMANENT_DATA *v)
{
  UINT32 i;
  if (tcm_unmarshal_TCM_STRUCTURE_TAG(ptr, length, &v->tag)
      || tcm_unmarshal_TCM_NONCE(ptr, length, &v->TCMProof)
      || tcm_unmarshal_TCM_SECRET(ptr, length, &v->ownerAuth)
	  || tcm_unmarshal_TCM_KEY_DATA(ptr, length, &v->endorsementKey)
      || tcm_unmarshal_TCM_KEY_DATA(ptr, length, &v->smk)) return -1; 
  for (i = 0; i < TCM_NUM_PCR; i++) {
    if (tcm_unmarshal_TCM_PCRVALUE(ptr, length, &v->pcrValue[i])) return -1;
  }
  return 0;
}

int tcm_marshal_TCM_SESSION_DATA(BYTE **ptr, UINT32 *length, TCM_SESSION_DATA *v)
{
  if (tcm_marshal_BYTE(ptr, length, v->type)
      || tcm_marshal_UINT32(ptr, length ,v->nonce)
      || tcm_marshal_TCM_SYMMETRIC_KEY(ptr, length, &v->sessionKey)
      || tcm_marshal_TCM_SECRET(ptr, length, &v->sharedSecret)
      || tcm_marshal_TCM_HANDLE(ptr, length, v->handle)
      || tcm_marshal_TCM_ENTITY_TYPE(ptr, length, v->entityType)) return -1;
  return 0;
}

int tcm_unmarshal_TCM_SESSION_DATA(BYTE **ptr, UINT32 *length, TCM_SESSION_DATA *v)
{
  if (tcm_unmarshal_BYTE(ptr, length, &v->type)
	  || tcm_unmarshal_UINT32(ptr, length ,&v->nonce)
      || tcm_unmarshal_TCM_SYMMETRIC_KEY(ptr, length, &v->sessionKey)
      || tcm_unmarshal_TCM_SECRET(ptr, length, &v->sharedSecret)
      || tcm_unmarshal_TCM_HANDLE(ptr, length, &v->handle)
      || tcm_unmarshal_TCM_ENTITY_TYPE(ptr, length, &v->entityType)) return -1;
  return 0;
}

int tcm_marshal_TCM_STANY_DATA(BYTE **ptr, UINT32 *length, TCM_STANY_DATA *v)
{
  UINT32 i;
  if (tcm_marshal_TCM_STRUCTURE_TAG(ptr, length, v->tag)) return -1;
  for (i = 0; i < TCM_MAX_KEYS; i++) {
	  if (tcm_marshal_TCM_KEY_DATA(ptr, length, &v->keys[i])) return -1;
  }
  for (i = 0; i < TCM_MAX_SESSIONS; i++) {
    if (tcm_marshal_TCM_SESSION_DATA(ptr, length, &v->sessions[i])) return -1;
  }
  return 0;
}

int tcm_unmarshal_TCM_STANY_DATA(BYTE **ptr, UINT32 *length, TCM_STANY_DATA *v)
{
  UINT32 i;
  if (tcm_unmarshal_TCM_STRUCTURE_TAG(ptr, length, &v->tag)) return -1;
  for (i = 0; i < TCM_MAX_KEYS; i++) {
	  if (tcm_unmarshal_TCM_KEY_DATA(ptr, length, &v->keys[i])) return -1;
  }
  for (i = 0; i < TCM_MAX_SESSIONS; i++) {
    if (tcm_unmarshal_TCM_SESSION_DATA(ptr, length, &v->sessions[i])) return -1;
  }
  return 0;
}

int tcm_marshal_TCM_RESPONSE(BYTE **ptr, UINT32 *length, TCM_RESPONSE *v)
{
	if (tcm_marshal_TCM_TAG(ptr, length, v->tag)
		|| tcm_marshal_UINT32(ptr, length, v->size)
		|| tcm_marshal_TCM_RESULT(ptr, length, v->result)
		|| tcm_marshal_BLOB(ptr, length, v->param, v->paramSize)) return -1;
	if (v->tag == TCM_TAG_RSP_AUTH2_COMMAND) {
		if (tcm_marshal_TCM_AUTH(ptr, length, v->auth1)
			|| tcm_marshal_TCM_AUTH(ptr, length, v->auth2)) return -1;
	} else if (v->tag == TCM_TAG_RSP_AUTH1_COMMAND) {
		if (tcm_marshal_TCM_AUTH(ptr, length, v->auth1)) return -1;
	}
	return 0;
}

int tcm_unmarshal_TCM_REQUEST(BYTE **ptr, UINT32 *length, TCM_REQUEST *v)
{
  if (tcm_unmarshal_TCM_TAG(ptr, length, &v->tag)
      || tcm_unmarshal_UINT32(ptr, length, &v->size)
      || tcm_unmarshal_TCM_COMMAND_CODE(ptr, length, &v->ordinal)) return -1;
  v->param = *ptr;
  v->paramSize = *length;
  if (v->tag == TCM_TAG_RQU_AUTH2_COMMAND) {
    if (*length < 2 * 36) return -1;
    v->paramSize = *length - 2 * 36;
    if (tcm_unmarshal_BLOB(ptr, length, &v->param, v->paramSize)
        || tcm_unmarshal_TCM_AUTH(ptr, length, &v->auth1)
        || tcm_unmarshal_TCM_AUTH(ptr, length, &v->auth2)) return -1;
  } else if (v->tag == TCM_TAG_RQU_AUTH1_COMMAND) {
    if (*length < 36) return -1;
    v->paramSize = *length - 36;
    if (tcm_unmarshal_BLOB(ptr, length, &v->param, v->paramSize)
        || tcm_unmarshal_TCM_AUTH(ptr, length, &v->auth1)) return -1;
    v->auth2.authHandle = TCM_INVALID_HANDLE;
  } else {
    v->auth1.authHandle = TCM_INVALID_HANDLE;
    v->auth2.authHandle = TCM_INVALID_HANDLE;
  }
  return 0;
}
