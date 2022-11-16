#include <stdlib.h>
#include "tcm_structures.h"
#include "tcm.h"
#include "ap.h"
#include "tcm_marshalling.h"
#include "tcmalg.h"
#include "tcmfunc.h"
#include "tcm.h"
#include "tcmutil.h"

uint32_t TCM_ReadPubek(TCM_PUBKEY *k){
	uint32_t ret;
	uint32_t ordinal_no = TCM_ORD_ReadPubek;
	BYTE random[TCM_HASH_SIZE] = {0};
	STACK_TCM_BUFFER(tcmdata)
	
	ret = TSS_buildbuff("00 c1 T L %",&tcmdata,
	                             ordinal_no, TCM_HASH_SIZE, random);
	if ((ret & ERR_MASK)) {
		return ret;
	}
	
	ret = TCM_Transmit(&tcmdata,"ReadPubek");
	tcm_buffer_load32(&tcmdata, 6, &ret);	
	if (ret != 0 ) {
		return ret;
	}

	//	������Ӧ����
	uint32_t pklen = 0;
	pklen = tcmdata.used - TCM_DATA_OFFSET - TCM_AUTHDATA_SIZE;
	BYTE *pkbuf = (BYTE *)malloc(pklen);
	memcpy(pkbuf, &tcmdata.buffer[TCM_DATA_OFFSET],pklen);
	
	//����PK�ṹ
	ret = tcm_unmarshal_TCM_PUBKEY(&pkbuf, &pklen, k);

	return ret;
}

/************************************************************************/
/* TCM_CreateWrapKey ������Կ											*/
/* �����key��keyblob��bloblen											*/
/* ������������������������װTCM_CreateWrapKey��������				*/
/* ������óɹ��󣬽���TCM��Ӧ����֤��Ȩ���ݣ�������ɵ���Կ��          */
/************************************************************************/
uint32_t TCM_CreateWrapKey(uint32_t keyhandle,
						   unsigned char *parauth,
						   unsigned char *newauth,
						   unsigned char *migauth,
						   TCM_KEY *keyparms,
						   TCM_KEY *key,
						   unsigned char *keyblob,
						   unsigned int  *bloblen)
{
	uint32_t ret;
	//BYTE *kparmbuf;
	STACK_TCM_BUFFER(kparmbuf)
	STACK_TCM_BUFFER(tcmdata)
	apsess sess;
	unsigned char encauth1[TCM_HASH_SIZE];
	unsigned char encauth2[TCM_HASH_SIZE];
	unsigned char dummyauth[TCM_HASH_SIZE];
	unsigned char *cparauth;
	unsigned char *cnewauth;
	uint16_t keytype;

	//1)	��ʼ����Ȩ��Ϣ����Կ����
	memset(dummyauth,0,sizeof dummyauth);
	/* check input arguments */
	if (keyparms == NULL) return ERR_NULL_ARG;
	if (parauth == NULL) cparauth = dummyauth;
	else                 cparauth = parauth;
	if (newauth == NULL) cnewauth = dummyauth;
	else                 cnewauth = newauth;
	if (keyhandle == TCM_KH_SMK) keytype = TCM_ET_SMK;
	else                         keytype = TCM_ET_KEYHANDLE;


	//2)	����AP�Ựsess
	ret = TSS_APopen(&sess, cparauth, keytype, keyhandle);
	if (ret != 0) 
		return ret;
//printf("222\n");

	//3)	����newauth��migauth��Ӧ�ļ�����Ȩ��Ϣencauth1��encauth2
	TCM_CreateEncAuth(&sess, cnewauth, encauth1);
	/* calculate encrypted authorization value for migration of new key */
	if (migauth != NULL) 
	{
		TCM_CreateEncAuth(&sess, migauth, encauth2);
	} else 
	{
		memset(encauth2,0,TCM_HASH_SIZE);
	}
//printf("333\n");

	//4)	��TCM_KEY�ṹ��keyparm���뵽kparmbuf
	UINT32 len = sizeof_TCM_KEY((*keyparms));
	UINT32 len2 = len;
	BYTE *ptr = kparmbuf.buffer;
	if (tcm_marshal_TCM_KEY( &ptr, &len, keyparms)) 
	{
		//debug("tcm_marshal_TCM_KEY() failed."); 
		TSS_APclose(&sess);
		return -1;//
	}
	kparmbuf.used = len2;
//printf("444\n");

	//5)	������Ȩ����sess->authdata
	//	����Ҫ����hmac���������buf
	
	STACK_TCM_BUFFER(tmpbuf)	
	uint32_t ordinal = TCM_ORD_CreateWrapKey;
	// TSS_buildbuff("LL%%%L", &buf, ordinal, keyhandle,TCM_HASH_SIZE, encauth1,TCM_HASH_SIZE,
		// encauth2, kparmbuf.used, kparmbuf.buffer, sess.nonce);	
	TSS_buildbuff("%%%", &tmpbuf, TCM_HASH_SIZE, encauth1,TCM_HASH_SIZE, encauth2,
		 kparmbuf.used, kparmbuf.buffer);
	ret = compute_authdata2(ordinal, &tmpbuf, &sess);
	if (ret == 0)
	{
		TSS_APclose(&sess);
		return ret;
	}

	//6)	������������tcmdata
	//UINT32 Paramsize = sizeof(uint32_t) + TCM_HASH_SIZE + TCM_HASH_SIZE + kparmbuf.used;
	TSS_buildbuff("00 C2 T L L % % % L %", &tcmdata, ordinal, keyhandle,
		TCM_HASH_SIZE, encauth1, TCM_HASH_SIZE,  encauth2, kparmbuf.used,
		kparmbuf.buffer, sess.handle, TCM_HASH_SIZE, sess.authdata);

	//7)	���������TCM/TCM�豸
	ret = TCM_Transmit(&tcmdata, "CreateWrapKey-AUTH1");
	if (ret != 0)
	{
		TSS_APclose(&sess);
		return ret;
	}

	//8)	��ֹAP�Ự
	sess.nonce++;
	TSS_APclose(&sess);

	//9)	������Ӧ����
	uint32_t result;
	tcm_buffer_load32(&tcmdata, TCM_RETURN_OFFSET, &result);
	*bloblen = tcmdata.used - TCM_DATA_OFFSET - TCM_AUTHDATA_SIZE;
	memcpy(keyblob, &tcmdata.buffer[TCM_DATA_OFFSET],*bloblen);
//memcpy(&sess.nonce, &tcmdata.buffer[TCM_DATA_OFFSET+ *bloblen+4],4);


	memcpy(sess.authdata, &tcmdata.buffer[TCM_DATA_OFFSET + *bloblen], TCM_AUTHDATA_SIZE);

	//10)	��֤��Ȩ����sess->authdata
	// STACK_TCM_BUFFER(buf2)
	// unsigned char authdata[TCM_AUTHDATA_SIZE];
	// TSS_buildbuff("L L % L", &buf2, ordinal, result, *bloblen, keyblob, sess.nonce);
	// tcm_hmac(buf2.buffer, buf2.used, sess.sharedsecret, TCM_HASH_SIZE, authdata);

	// ret = memcmp(sess.authdata,authdata,TCM_HASH_SIZE);
	// if ( ret!=0 )
	// {
	// 	return ret;
	// }

	//11)	����keyblobΪTCM_KEY�ṹ��key
	unsigned int templen = *bloblen;
	if (tcm_unmarshal_TCM_KEY(&keyblob, bloblen, key)) 
	{
		//debug("tcm_umarshal_TCM_KEY() failed."); 
		return -1;
	}
	*bloblen = templen;
	return result;
}


uint32_t TCM_LoadKey_internal(apsess * sess, uint32_t keyhandle, TCM_KEY *keyparms, uint32_t *newhandle){
	uint32_t ret = 0;
	STACK_TCM_BUFFER(tcmdata)
	STACK_TCM_BUFFER(kparmbuf)

//3)	��TCM_KEY�ṹ��keyparms���뵽kparmbuf
	UINT32 len = sizeof_TCM_KEY((*keyparms));
	UINT32 len2 = len;
	BYTE *ptr = kparmbuf.buffer;
	if (tcm_marshal_TCM_KEY( &ptr, &len, keyparms)) 
	{
		TSS_APclose(sess);
		return -1;//
	}
	kparmbuf.used = len2;

	//4)	������Ȩ����sess->authdata
	//	����Ҫ����hmac���������buf		
	uint32_t ordinal = TCM_ORD_LoadKey;
	ret = compute_authdata2(ordinal, &kparmbuf, sess);
	if (ret == 0)
	{
		TSS_APclose(sess);
		return ret;
	}

	//5)	������������tcmdata
	TSS_buildbuff("00 C2 T L L % L %", &tcmdata, ordinal, keyhandle, 
		kparmbuf.used, kparmbuf.buffer, sess->handle, TCM_HASH_SIZE, sess->authdata);

	//6)	���������TCM/TCM�豸
	ret = TCM_Transmit(&tcmdata, "LoadKey-AUTH1");

	//8)	������Ӧ����
	uint32_t result;
	tcm_buffer_load32(&tcmdata, TCM_RETURN_OFFSET, &result);

	unsigned int handlelen = tcmdata.used - TCM_DATA_OFFSET - TCM_AUTHDATA_SIZE;
	BYTE *ptr2;
	ptr2 =(BYTE *)malloc(handlelen);
	memcpy(ptr2, &tcmdata.buffer[TCM_DATA_OFFSET],handlelen);
	if (tcm_unmarshal_TCM_KEY_HANDLE(&ptr2, &handlelen, newhandle)) {
			
		return -1;
	}

	memcpy(sess->authdata, &tcmdata.buffer[TCM_DATA_OFFSET + TCM_U32_SIZE], TCM_AUTHDATA_SIZE);

	return ret;
//printf("666\n");
}

uint32_t TCM_FlushSpecific(uint32_t resourceHandle, uint32_t resourceType){
	uint32_t ret = 0;
	uint32_t ordinal = TCM_ORD_FlushSpecific;

	STACK_TCM_BUFFER(tcmdata)
	TSS_buildbuff("00 C1 T L L L", &tcmdata, ordinal, resourceHandle,  resourceType);
	ret = TCM_Transmit(&tcmdata, "TCM_FlushSpecific");
	tcm_buffer_load32(&tcmdata, TCM_RETURN_OFFSET, &ret);
	return ret;
}

/****************************************************************************/
/* TCM_LoadKey �������ɵ���Կ������TCM										*/                                                                         
/* �����newhandle															*/
/* ������������������������װTCM_CreateWrapKey��������					*/
/* ������óɹ��󣬽���TCM��Ӧ����֤��Ȩ���ݣ�������Կ�����ɵ�����Կ�����	*/
/****************************************************************************/
uint32_t TCM_LoadKey(uint32_t keyhandle, unsigned char *keyauth,
	TCM_KEY *keyparms, uint32_t *newhandle)
{
	uint32_t ret;
	//unsigned char nonceodd[TCM_NONCE_SIZE];
	//unsigned char pubauth[TCM_HASH_SIZE];
	//unsigned char c = 0;
	//uint32_t ordinal = TCM_ORD_LoadKey;//htonl(TCM_ORD_LoadKey);
	uint16_t keytype;
	apsess sess;
/*
	ret = needKeysRoom(keyhandle, 0, 0, 0);
	if (ret != 0) {
		return ret;
	}
*/
	//1)	����������
	if (keyparms == NULL || newhandle == NULL) return ERR_NULL_ARG;

	//2)	����AP�Ựsess
	if (keyhandle == TCM_KH_SMK) keytype = TCM_ET_SMK;
	else                         keytype = TCM_ET_KEYHANDLE;
	ret = TSS_APopen(&sess, keyauth, keytype, keyhandle);
	if (ret!=0)
		return ret;

	// 3-6 move to internal, so as to use outside this function
	ret = TCM_LoadKey_internal(&sess, keyhandle, keyparms, newhandle);
	if (ret != 0)
	{
		TSS_APclose(&sess);
		return ret;
	}

	uint32_t resourcetype = TCM_RT_KEY;
    	//ret = TCM_FlushSpecific(*newhandle, resourcetype);
	//if (0 != ret) {
	//	TSS_APclose(&sess);
	//	return ret;
	//}

	//7)	��ֹAP�Ự
	sess.nonce++;
	TSS_APclose(&sess);

	//9)	��֤��Ȩ����sess->authdata
	// unsigned char authdata[TCM_AUTHDATA_SIZE];
	// STACK_TCM_BUFFER(buf2)
	// TSS_buildbuff("L L L L", &buf2, ordinal, result, *newhandle, sess.nonce);

	// tcm_hmac(buf2.buffer, buf2.used, sess.sharedsecret, TCM_HASH_SIZE, authdata);
	// ret = memcmp(sess.authdata,authdata,TCM_HASH_SIZE);
	// if ( ret!=0 )
	// {
	// 	return ret;
	// }

	return 0;
}

uint32_t TCM_GetPubKey_internal(apsess *sess, uint32_t keyhandle, TCM_PUBKEY *pk){
	uint32_t ret;
	STACK_TCM_BUFFER(tcmdata)
	
	//4)	������Ȩ����sess->authdata
	STACK_TCM_BUFFER(params)
	uint32_t ordinal = TCM_ORD_GetPubKey;
	ret = compute_authdata2(ordinal, &params, sess);
	if (ret == 0)
	{
		TSS_APclose(sess);
		return ret;
	}

	//5)	������������tcmdata
	TSS_buildbuff("00 C2 T L L L %", &tcmdata, ordinal, keyhandle,
		 sess->handle, TCM_HASH_SIZE, sess->authdata);
	
	//6)	���������TCM/TCM�豸
	ret = TCM_Transmit(&tcmdata, "GetPubKey - AUTH1");
	if (ret != 0)
	{
		TSS_APclose(sess);
		return ret;
	}
	
	//8)	������Ӧ����
	uint32_t result = 0;
	uint32_t pklen = 0;
	tcm_buffer_load32(&tcmdata, TCM_RETURN_OFFSET, &result);
	pklen = tcmdata.used - TCM_DATA_OFFSET - TCM_AUTHDATA_SIZE;
	BYTE *pkbuf = (BYTE *)malloc(pklen);
	memcpy(pkbuf, &(tcmdata.buffer[TCM_DATA_OFFSET]),pklen);
	memcpy(sess->authdata, &(tcmdata.buffer[TCM_DATA_OFFSET + pklen]), TCM_AUTHDATA_SIZE);
	
	//9)	��֤��Ȩ����sess->authdata
// 	STACK_TCM_BUFFER(buf2)
// 	unsigned char authdata[TCM_AUTHDATA_SIZE];
// 	TSS_buildbuff("L L % L", &buf2, ordinal, result, pklen, pkbuf, sess.nonce);
// 	tcm_hmac(buf2.buffer, buf2.used, sess.sharedsecret, TCM_HASH_SIZE, authdata);
// //printf("sess.authdata %s\n",sess.authdata);
// //printf("authdata %s\n",authdata);
// 	ret = memcmp(sess.authdata,authdata,TCM_HASH_SIZE);
// 	if ( ret!=0 )
// 		return ret;
	
	//����PK�ṹ
	ret = tcm_unmarshal_TCM_PUBKEY(&pkbuf, &pklen, pk);
	if ( ret!=0 )
		return ret;

	return ret;
}

/************************************************************************/
/* TCM_GetPubKey ������Կ�����TCM��ù�Կ								*/
/* �����pk																*/
/* ������������������������װTCM_GetPubKey��������					*/
/* ������óɹ��󣬽���TCM��Ӧ����֤��Ȩ���ݣ������Կ�Ĺ�Կpk��		*/
/************************************************************************/
uint32_t TCM_GetPubKey(uint32_t keyhandle,
	unsigned char *keyauth,
	TCM_PUBKEY *pk)
{
	uint32_t ret;
	uint16_t keytype;
	apsess sess;

	//1)	����������
	if (pk == NULL || keyhandle == TCM_KH_SMK) return ERR_NULL_ARG;

	//2)	����AP�Ựsess
	keytype = TCM_ET_KEYHANDLE;		
	ret = TSS_APopen(&sess, keyauth, keytype, keyhandle);
	if (ret != 0) 
		return ret;

	//3)	���кż�1
	// sess.nonce++;

	ret = TCM_GetPubKey_internal(&sess, keyhandle, pk);

	//7)	��ֹAP�Ự
	sess.nonce++;
	TSS_APclose(&sess);

	return 0;
}

/************************************************************************/
/* TCM_EvictKey �����Ѽ�����TCM����Կ									*/
/* ������������������������װTCM_EvictKey��������						*/
/* ������óɹ��󣬽���TCM��Ӧ������ִ�н����							*/
/************************************************************************/
uint32_t TCM_EvictKey(uint32_t keyhandle)
{
	uint32_t ret;
	STACK_TCM_BUFFER(tcmdata)
	uint32_t ordinal = TCM_ORD_EvictKey;
	TSS_buildbuff("00 C1 T L L", &tcmdata, ordinal, keyhandle);
	ret = TCM_Transmit(&tcmdata, "EvictKey");
	if (ret != 0)
		return ret;
	uint32_t result = 0;
	tcm_buffer_load32(&tcmdata, TCM_RETURN_OFFSET, &result);
	if (result==TCM_SUCCESS)
		return 0;
	else return result;
}

/************************************************************************/
/* TCM_GetKeyHandle ��ѯ�Ѽ�����TCM����Կ								*/	
/* �����*respSize, *resp												*/
/* ������������������������װTCM_GetKeyHandle��������					*/
/* ������óɹ��󣬽���TCM��Ӧ��										*/
/************************************************************************/
uint32_t TCM_GetKeyHandle(UINT32 *respSize, BYTE *resp)
{
	uint32_t ret;
	STACK_TCM_BUFFER(tcmdata)
	uint32_t ordinal = TCM_ORD_GetKeyHandle;
	TSS_buildbuff("00 C1 T L", &tcmdata, ordinal);
	ret = TCM_Transmit(&tcmdata, "GetKeyHandle");
	if (ret != 0)
		return ret;
	uint32_t result = 0;
	tcm_buffer_load32(&tcmdata, TCM_RETURN_OFFSET, &result);
	ret = tcm_buffer_load32(&tcmdata, TCM_DATA_OFFSET, respSize);
	if (ret != 0)
		return ret;
	//resp = (BYTE *)malloc(*respSize);
	memcpy(resp, &tcmdata.buffer[TCM_DATA_OFFSET+TCM_U32_SIZE], *respSize);
	return 0;
}

/************************************************************************/
/* TCM_GetRandom ���������												*/	
/* �����UINT32 len, BYTE *data											*/
/* ������������������������װTCM_GetRandom��������						*/
/* ������óɹ��󣬽���TCM��Ӧ��										*/
/************************************************************************/
uint32_t TCM_GetRandom(UINT32 len, BYTE *data)
{
	uint32_t ret;
	uint32_t ordinal = TCM_ORD_GetRandom;	
	STACK_TCM_BUFFER(tcmdata)

	ret = TSS_buildbuff("00 C1 T L L",&tcmdata, ordinal, len);
	if ((ret & ERR_MASK) != 0 ) return ret;
	ret = TCM_Transmit(&tcmdata,"GetRandom");
	if (ret != 0) return ret;
 	memcpy(data, &tcmdata.buffer[TCM_DATA_OFFSET+TCM_U32_SIZE], len);	
	return 0;
}
