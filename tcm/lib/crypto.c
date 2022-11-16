#include <stdlib.h>
#include <stdio.h>
#include "tcm_structures.h"
#include "tcm.h"
#include "ap.h"
//#include "tcm_marshalling.h"
#include "tcmalg.h"
#include "tcmfunc.h"
#include "time.h"
#include "tcm.h"
#include "tcmutil.h"
#include "tcm_marshalling.h"


uint32_t TCM_Sign_internal(apsess *sess, uint32_t keyhandle,
							unsigned char *data, uint32_t datalen, 
							unsigned char *sig, uint32_t *siglen){
	
	STACK_TCM_BUFFER(tcmdata)
	uint32_t ordinal = 0;
	// unsigned char schsum[TCM_NONCE_SIZE];
	// uint32_t sumLen;
	uint32_t ret = 0;

	//3)	����schsum��sumLen
	// char *pUserID = "ALICE123@YAHOO.COM";
	// unsigned int userIDLen = strlen(pUserID);
	// tcm_ecc_init();
	// ret = tcm_get_message_hash(data, datalen, (unsigned char*)pUserID, userIDLen, 
	// 	tcmpubkey.pubKey.key, tcmpubkey.pubKey.keyLength, 
	// 	schsum, &sumLen);
	// if (ret!=0)
	// 	return -1;

	//6)	������Ȩ����sess->authdata
	STACK_TCM_BUFFER(buf)
	ordinal = TCM_ORD_Sign;
	TSS_buildbuff("@", &buf, datalen, data);
	ret = compute_authdata2(ordinal, &buf, sess);	
	// ret = tcm_hmac(buf.buffer, buf.used, sess.sharedsecret, TCM_HASH_SIZE, sess.authdata);
	if (ret == 0)
	{
		printf("compute_authdata2 error!\n");
		TSS_APclose(sess);
		return ret;
	}

	//7)	������������tcmdata
	// TSS_buildbuff("00 C2 T L L L % L %", &tcmdata, ordinal, keyhandle, sumLen, sumLen, schsum,
	// 	sess.handle, TCM_HASH_SIZE, sess.authdata);
	TSS_buildbuff("00 C2 T L L @ L %", &tcmdata, ordinal, keyhandle, datalen, data, sess->handle, TCM_HASH_SIZE, sess->authdata);

	//8)	���������TCM/TCM�豸
	ret = TCM_Transmit(&tcmdata, "Sign");
	if (ret != 0)
	{
		TSS_APclose(sess);
		return ret;
	}

	//10)	������Ӧ����
	uint32_t result = 0;	
	tcm_buffer_load32(&tcmdata, TCM_RETURN_OFFSET, &result);
	if (result!=TCM_SUCCESS)
		return -1;
	tcm_buffer_load32(&tcmdata, TCM_DATA_OFFSET, siglen);
	memcpy(sig, &tcmdata.buffer[TCM_DATA_OFFSET+4], *siglen);
	memcpy(sess->authdata, &tcmdata.buffer[tcmdata.used-TCM_AUTHDATA_SIZE], TCM_AUTHDATA_SIZE);

	//11)	��֤��Ȩ����sess->authdata
	// STACK_TCM_BUFFER(buf2)
	// unsigned char authdata[TCM_AUTHDATA_SIZE];
	// TSS_buildbuff("L L L % L", &buf2, ordinal, result, *siglen, *siglen, sig, sess.nonce);
	// tcm_hmac(buf2.buffer, buf2.used, sess.sharedsecret, TCM_HASH_SIZE, authdata);
	// ret = memcmp(sess.authdata,authdata,TCM_HASH_SIZE);
	// if ( ret!=0 )
	// 	return ret;

	return ret;

}

/************************************************************************/
/* TCM_Sign ǩ��														*/
/* �����sig��siglen													*/
/* ������������������������װTCM_Sign��������							*/
/* ������óɹ��󣬽���TCM��Ӧ����֤��Ȩ���ݣ����ǩ�����ݡ�			*/
/************************************************************************/
uint32_t TCM_Sign(uint32_t keyhandle, unsigned char *keyauth,
			 unsigned char *data, uint32_t datalen, 
			 unsigned char *sig, uint32_t *siglen)
{
	uint32_t ret;
	
	apsess sess;
	uint8_t keytype = 0;
	TCM_PUBKEY tcmpubkey;
	//��ʼ��tcmpubkey
	tcmpubkey.algorithmParms.algorithmID = 0;
	tcmpubkey.algorithmParms.encScheme = 0;
	tcmpubkey.algorithmParms.sigScheme = 0;
	tcmpubkey.algorithmParms.parmSize = 4;
	tcmpubkey.algorithmParms.parms.ecc.keyLength = 0;
	tcmpubkey.pubKey.keyLength = 0;
	tcmpubkey.pubKey.key = NULL;

	//1)	��֤�������data��sig��Ϊ��
	if (data == NULL || sig == NULL) return ERR_NULL_ARG;

	//4)	��TSS_APopen()����AP�Ựsess
	keytype = TCM_ET_KEYHANDLE;		
	ret = TSS_APopen(&sess, keyauth, keytype, keyhandle);
	if (ret != 0) 
		return ret;

	//2)	��ȡǩ����Կ��Ӧ�Ĺ�Կ
	ret = TCM_GetPubKey_internal(&sess, keyhandle, &tcmpubkey);
	if (ret!=0)
		return ret;

	//5)	���кż�1
	sess.nonce++;

	ret = TCM_Sign_internal(&sess, keyhandle, data, datalen, sig, siglen);
	sess.nonce++;

/*	ret = tcm_ecc_init();
	ret = tcm_ecc_verify(data, datalen, sig, *siglen, tcmpubkey.pubKey.key, tcmpubkey.pubKey.keyLength);
	if (ret != 0)
	{
		printf("tcm_ecc_verify error!\n");
	}else
	{
		printf("tcm_ecc_verify success!\n");
	}
	
	ret = tcm_ecc_release();
*/
	//9)	��TSS_APclose()��ֹAP�Ự
	TSS_APclose(&sess);

	return ret;
}

/************************************************************************/
/* TCM_Verify ��֤														*/
/* �����verifyResult													*/
/* ������������������������װTCM_Verify��������						*/
/* ������óɹ��󣬽���TCM��Ӧ����֤��Ȩ���ݣ������֤�����			*/
/************************************************************************/
uint32_t TCM_Verify(TCM_PUBKEY *key,
			unsigned char *signedData, uint32_t signedDataSize,
			unsigned char *signatureValue, uint32_t signatureValueSize,
			unsigned char *ownerAuth, 
			unsigned char *verifyResult)
{
	uint32_t ret;
	STACK_TCM_BUFFER(tcmdata)
	uint32_t ordinal = 0;
	unsigned char schsum[TCM_NONCE_SIZE];
	uint32_t sumLen;
	apsess sess;

	//1)	��֤�������ownerAuth ��signedData��signatureValue��key��Ϊ��
	if (ownerAuth == NULL || signedData == NULL
		|| signatureValue ==NULL || key == NULL) return ERR_NULL_ARG;

	//2)	����schsum��sumLen
	char *pUserID = "ALICE123@YAHOO.COM";
	unsigned int userIDLen = strlen(pUserID);
	tcm_ecc_init();
	ret = tcm_get_message_hash(signedData, signedDataSize, (unsigned char*)pUserID, userIDLen, 
		key->pubKey.key, key->pubKey.keyLength, 
		schsum, &sumLen);
	if (ret!=0)
		return -1;

	//3)	��TSS_APopen()����AP�Ựsess
	ret = TSS_APopen(&sess, ownerAuth, TCM_ET_OWNER, TCM_KH_OWNER);
	if (ret != 0) 
		return ret;

	//4)	���кż�1
	sess.nonce++;

	//5)	������Ȩ����sess->authdata
	STACK_TCM_BUFFER(buf)
	ordinal = TCM_ORD_Verify;
	uint32_t keylen = sizeof_TCM_PUBKEY((*key));
	uint32_t keylen1 = keylen;
	BYTE *ptr = (BYTE *)malloc(keylen);

	ret = tcm_marshal_TCM_PUBKEY(&ptr,&keylen,key);
	if (ret != 0)
	{
		TSS_APclose(&sess);
		return ret;
	}
	ptr = ptr-keylen1;

	TSS_buildbuff("L%L%L%L", &buf, ordinal, keylen1, ptr, sumLen, sumLen, schsum,
			signatureValueSize, signatureValueSize,signatureValue,sess.nonce);	
	ret = tcm_hmac(buf.buffer, buf.used, sess.sharedsecret, TCM_HASH_SIZE, sess.authdata);
	if (ret != 0)
	{
		TSS_APclose(&sess);
		return ret;
	}

	//6)	������������tcmdata
	TSS_buildbuff("00 C2 T L % L % L % L %", &tcmdata, ordinal, keylen1, ptr, 
			sumLen, sumLen, schsum,	signatureValueSize, signatureValueSize,signatureValue,  
			sess.handle, TCM_HASH_SIZE, sess.authdata);

	//7)	���������TCM/TCM�豸
	ret = TCM_Transmit(&tcmdata, "Verify-AUTH1");
	if (ret != 0)
	{
		TSS_APclose(&sess);
		return ret;
	}

	//8)	��TSS_APclose()��ֹAP�Ự
	TSS_APclose(&sess);

	//9)	������Ӧ����
	uint32_t result = 0;
	tcm_buffer_load32(&tcmdata, TCM_RETURN_OFFSET, &result);
	if (result!=TCM_SUCCESS)
		return -1;
	memcpy(verifyResult, &tcmdata.buffer[TCM_DATA_OFFSET],1);
	memcpy(sess.authdata, &tcmdata.buffer[TCM_DATA_OFFSET + 1], TCM_AUTHDATA_SIZE);

	//10)	��֤��Ȩ����sess->authdata
	STACK_TCM_BUFFER(buf2)
	unsigned char authdata[TCM_AUTHDATA_SIZE];
	TSS_buildbuff("L L % L", &buf2, ordinal, result, 1, verifyResult, sess.nonce);
	tcm_hmac(buf2.buffer, buf2.used, sess.sharedsecret, TCM_HASH_SIZE, authdata);
	ret = memcmp(sess.authdata,authdata,TCM_HASH_SIZE);
	if ( ret!=0 )
		return ret;

	return 0;
}

/************************************************************************/
/* TCM_EccEncrypt ECC����												*/
/* �����enc��encSize													*/
/* ������������������������װTCM_ EccEncrypt��������					*/
/* ������óɹ��󣬽���TCM��Ӧ����֤��Ȩ���ݡ�							*/
/************************************************************************/
uint32_t TCM_EccEncrypt(TCM_PUBKEY * key,
	unsigned char * areaToEnc, uint32_t areaToEncSize,
	unsigned char *ownerAuth,
	unsigned char *enc, uint32_t *encSize)
{
	uint32_t ret;
	STACK_TCM_BUFFER(tcmdata)
	uint32_t ordinal = 0;
	apsess sess;

	//1)	��֤�������ownerAuth��areaToEnc��enc��Ϊ��
	if (ownerAuth == NULL || areaToEnc == NULL
		|| enc ==NULL ) return ERR_NULL_ARG;

	//2)    ����AP�Ự
	ret = TSS_APopen(&sess, ownerAuth, TCM_ET_OWNER, TCM_KH_OWNER);
	if (ret != 0) 
		return ret;

	//3)	���кż�1
	sess.nonce++;

	//4)	������Ȩ����sess->authdata
	STACK_TCM_BUFFER(buf)
	ordinal = TCM_ORD_ECCEncrypt;

	uint32_t keylen = sizeof_TCM_PUBKEY((*key));
	uint32_t keylen1 = keylen;
	BYTE *ptr = (BYTE *)malloc(keylen);

	ret = tcm_marshal_TCM_PUBKEY(&ptr,&keylen,key);
	if (ret != 0)
	{
		TSS_APclose(&sess);
		return ret;
	}
	ptr = ptr-keylen1;

	TSS_buildbuff("L%L%L", &buf, ordinal, keylen1, ptr, areaToEncSize,
		areaToEncSize, areaToEnc, sess.nonce);	
	ret = tcm_hmac(buf.buffer, buf.used, sess.sharedsecret, TCM_HASH_SIZE, sess.authdata);
	if (ret != 0)
	{
		TSS_APclose(&sess);
		return ret;
	}

	//5)	������������tcmdata
	TSS_buildbuff("00 C2 T L % L % L %", &tcmdata, ordinal, keylen1, ptr, 
		areaToEncSize, areaToEncSize, areaToEnc, sess.handle, TCM_HASH_SIZE, sess.authdata);

	//6)	���������TCM/TCM�豸
	ret = TCM_Transmit(&tcmdata, "EccEncrypt-AUTH1");
	if (ret != 0)
	{
		TSS_APclose(&sess);
		return ret;
	}

	//7)    ��ֹAP�Ự
	TSS_APclose(&sess);

	//8)	������Ӧ����
	uint32_t result = 0;
	tcm_buffer_load32(&tcmdata, TCM_RETURN_OFFSET, &result);
	if (result!=TCM_SUCCESS)
		return -1;
	tcm_buffer_load32(&tcmdata, TCM_DATA_OFFSET, encSize);
	memcpy(enc, &tcmdata.buffer[TCM_DATA_OFFSET+4], *encSize);
	memcpy(sess.authdata, &tcmdata.buffer[tcmdata.used-TCM_AUTHDATA_SIZE], TCM_AUTHDATA_SIZE);

	//9)	��֤��Ȩ����sess->authdata
	STACK_TCM_BUFFER(buf2)
	unsigned char authdata[TCM_AUTHDATA_SIZE];
	TSS_buildbuff("L L L % L", &buf2, ordinal, result, *encSize, *encSize, enc, sess.nonce);
	tcm_hmac(buf2.buffer, buf2.used, sess.sharedsecret, TCM_HASH_SIZE, authdata);
	ret = memcmp(sess.authdata,authdata,TCM_HASH_SIZE);
	if ( ret!=0 )
		return ret;

	return 0;
}

/************************************************************************/
/* TCM_EccDecrypt ECC����												*/
/* �����blob��bloblen													*/
/* ������������������������װTCM_EccDecrypt��������					*/
/* ������óɹ��󣬽���TCM��Ӧ����֤��Ȩ���ݣ�������ܺ�����ݺͳ��ȡ�	*/
/************************************************************************/
uint32_t TCM_EccDecrypt(uint32_t keyhandle, unsigned char *keyauth,
	unsigned char *data, uint32_t datalen, 
	unsigned char *blob, uint32_t *bloblen)
{
	uint32_t ret;
	STACK_TCM_BUFFER(tcmdata)
	uint32_t ordinal = 0;
	apsess sess;
	uint8_t keytype;

	//1)	��֤�������data��blob��Ϊ��
	if (data == NULL || blob == NULL) return ERR_NULL_ARG;

	//2)    ����AP�Ự
	if (keyhandle == TCM_KH_SMK) keytype = TCM_ET_SMK;
	else                         keytype = TCM_ET_KEYHANDLE;

	ret = TSS_APopen(&sess, keyauth, keytype, keyhandle);
	if (ret != 0) 
		return ret;

	//3)	���кż�1
	sess.nonce++;

	//4)	������Ȩ����sess->authdata
	STACK_TCM_BUFFER(buf)
	ordinal = TCM_ORD_ECCDecrypt;
	TSS_buildbuff("LLL%L", &buf, ordinal, keyhandle, datalen,
		datalen, data, sess.nonce);	
	ret = tcm_hmac(buf.buffer, buf.used, sess.sharedsecret, TCM_HASH_SIZE, sess.authdata);
	if (ret != 0)
	{
		TSS_APclose(&sess);
		return ret;
	}

	//5)	������������tcmdata
	TSS_buildbuff("00 C2 T L L L % L %", &tcmdata, ordinal, keyhandle, 
		datalen, datalen, data, sess.handle, TCM_HASH_SIZE, sess.authdata);

	//6)	���������TCM/TCM�豸
	ret = TCM_Transmit(&tcmdata, "EccDecrypt-AUTH1");
	if (ret != 0)
	{
		TSS_APclose(&sess);
		return ret;
	}

	//7)    ��ֹAP�Ự
	TSS_APclose(&sess);

	//8)	������Ӧ����
	uint32_t result = 0;
	tcm_buffer_load32(&tcmdata, TCM_RETURN_OFFSET, &result);
	if (result!=TCM_SUCCESS)
		return -1;
	tcm_buffer_load32(&tcmdata, TCM_DATA_OFFSET, bloblen);
	memcpy(blob, &tcmdata.buffer[TCM_DATA_OFFSET+4], *bloblen);
	memcpy(sess.authdata, &tcmdata.buffer[tcmdata.used-TCM_AUTHDATA_SIZE], TCM_AUTHDATA_SIZE);

	//9)	��֤��Ȩ����sess->authdata
	STACK_TCM_BUFFER(buf2)
	unsigned char authdata[TCM_AUTHDATA_SIZE];
	TSS_buildbuff("L L L % L", &buf2, ordinal, result, *bloblen, *bloblen, blob, sess.nonce);
	tcm_hmac(buf2.buffer, buf2.used, sess.sharedsecret, TCM_HASH_SIZE, authdata);
	ret = memcmp(sess.authdata,authdata,TCM_HASH_SIZE);
	if ( ret!=0 )
		return ret;

	return 0;
}

/************************************************************************/
/* TCM_SMS4Encrypt SMS4����												*/
/* �����IV��blob��bloblen												*/
/* ������������������������װTCM_ SMS4Encrypt��������					*/
/* ������óɹ��󣬽���TCM��Ӧ����֤��Ȩ���ݣ������ʼ���������ĺͳ��ȡ�*/
/************************************************************************/
uint32_t TCM_SMS4Encrypt(uint32_t keyhandle, unsigned char *keyauth,
	unsigned char *data, uint32_t datalen, 
	unsigned char *IV, unsigned char *blob, uint32_t *bloblen)
{
	uint32_t ret;
	uint8_t keytype;
	STACK_TCM_BUFFER(tcmdata)
	uint32_t ordinal = 0;
	apsess sess;

	//1)	��֤�������keyauth��data��IV��blob��Ϊ��
	if ( keyauth == NULL || data == NULL
		 || IV == NULL || blob ==NULL ) return ERR_NULL_ARG;

	//2)    ����AP�Ự
	if (keyhandle == TCM_KH_SMK) keytype = TCM_ET_SMK;
	else                         keytype = TCM_ET_KEYHANDLE;
	ret = TSS_APopen(&sess, keyauth, keytype, keyhandle);
	if (ret != 0) 
		return ret;

	//3)	���кż�1
	sess.nonce++;

	//4)	����128bit�����IV
	srand( (unsigned)time( NULL ) );
	unsigned int i;
	for (  i=0; i<16; i++)
	{
		IV[i] = rand()%256;
	}

	//5)	������Ȩ����sess->authdata
	STACK_TCM_BUFFER(buf)
	ordinal = TCM_ORD_SMS4Encrypt;
	
	TSS_buildbuff("LL%L%L", &buf, ordinal, keyhandle, 16, IV, datalen,
		datalen, data, sess.nonce);	
	ret = tcm_hmac(buf.buffer, buf.used, sess.sharedsecret, TCM_HASH_SIZE, sess.authdata);
	if (ret != 0)
	{
		TSS_APclose(&sess);
		return ret;
	}

	//6)	������������tcmdata
	TSS_buildbuff("00 C2 T L L % L % L %", &tcmdata, ordinal, keyhandle, 16, IV, 
		datalen, datalen, data, sess.handle, TCM_HASH_SIZE, sess.authdata);

	//7)	���������TCM/TCM�豸
	ret = TCM_Transmit(&tcmdata, "SMS4Encrypt-AUTH1");
	if (ret != 0)
	{
		TSS_APclose(&sess);
		return ret;
	}

	//7)    ��ֹAP�Ự
	TSS_APclose(&sess);

	//8)	������Ӧ����
	uint32_t result = 0;
	tcm_buffer_load32(&tcmdata, TCM_RETURN_OFFSET, &result);
	if (result!=TCM_SUCCESS)
		return -1;
	tcm_buffer_load32(&tcmdata, TCM_DATA_OFFSET, bloblen);
	memcpy(blob, &tcmdata.buffer[TCM_DATA_OFFSET+4], *bloblen);
	memcpy(sess.authdata, &tcmdata.buffer[tcmdata.used-TCM_AUTHDATA_SIZE], TCM_AUTHDATA_SIZE);

	//9)	��֤��Ȩ����sess->authdata
	STACK_TCM_BUFFER(buf2)
	unsigned char authdata[TCM_AUTHDATA_SIZE];
	TSS_buildbuff("L L L % L", &buf2, ordinal, result, *bloblen, *bloblen, blob, sess.nonce);
	tcm_hmac(buf2.buffer, buf2.used, sess.sharedsecret, TCM_HASH_SIZE, authdata);
	ret = memcmp(sess.authdata,authdata,TCM_HASH_SIZE);
	if ( ret!=0 )
		return ret;

	return 0;
}

/************************************************************************/
/* TCM_SMS4Decrypt SMS4����												*/
/* �����blob��bloblen													*/
/* ������������������������װTCM_SMS4Decrypt��������					*/
/* ������óɹ��󣬽���TCM��Ӧ����֤��Ȩ���ݣ�������ĺͳ��ȡ�			*/
/************************************************************************/
uint32_t TCM_SMS4Decrypt(uint32_t keyhandle, unsigned char *keyauth, unsigned char *IV,
	unsigned char *data, uint32_t datalen, 
	unsigned char *blob, uint32_t *bloblen)
{
	uint32_t ret;
	STACK_TCM_BUFFER(tcmdata)
	uint32_t ordinal = 0;
	apsess sess;
	uint8_t keytype;

	//1)	��֤�������IV��data��blob��Ϊ��
	if (IV == NULL || data == NULL
		|| blob == NULL) return ERR_NULL_ARG;

	//2)    ����AP�Ự
	if (keyhandle == TCM_KH_SMK) keytype = TCM_ET_SMK;
	else                         keytype = TCM_ET_KEYHANDLE;

	ret = TSS_APopen(&sess, keyauth, keytype, keyhandle);
	if (ret != 0) 
		return ret;

	//3)	���кż�1
	sess.nonce++;

	//4)	������Ȩ����sess->authdata
	STACK_TCM_BUFFER(buf)
	ordinal = TCM_ORD_SMS4Decrypt;
	TSS_buildbuff("LL%L%L", &buf, ordinal, keyhandle, 16, IV, datalen,
		datalen, data, sess.nonce);	
	ret = tcm_hmac(buf.buffer, buf.used, sess.sharedsecret, TCM_HASH_SIZE, sess.authdata);
	if (ret != 0)
	{
		TSS_APclose(&sess);
		return ret;
	}

	//5)	������������tcmdata
	TSS_buildbuff("00 C2 T L L % L % L %", &tcmdata, ordinal, keyhandle, 16, IV,
		datalen, datalen, data, sess.handle, TCM_HASH_SIZE, sess.authdata);

	//6)	���������TCM/TCM�豸
	ret = TCM_Transmit(&tcmdata, "SMS4Decrypt-AUTH1");
	if (ret != 0)
	{
		TSS_APclose(&sess);
		return ret;
	}

	//7)    ��ֹAP�Ự
	TSS_APclose(&sess);

	//8)	������Ӧ����
	uint32_t result = 0;
	tcm_buffer_load32(&tcmdata, TCM_RETURN_OFFSET, &result);
	if (result!=TCM_SUCCESS)
		return -1;
	tcm_buffer_load32(&tcmdata, TCM_DATA_OFFSET, bloblen);
	memcpy(blob, &tcmdata.buffer[TCM_DATA_OFFSET+4], *bloblen);
	memcpy(sess.authdata, &tcmdata.buffer[tcmdata.used-TCM_AUTHDATA_SIZE], TCM_AUTHDATA_SIZE);

	//9)	��֤��Ȩ����sess->authdata
	STACK_TCM_BUFFER(buf2)
	unsigned char authdata[TCM_AUTHDATA_SIZE];
	TSS_buildbuff("L L L % L", &buf2, ordinal, result, *bloblen, *bloblen, blob, sess.nonce);
	tcm_hmac(buf2.buffer, buf2.used, sess.sharedsecret, TCM_HASH_SIZE, authdata);
	ret = memcmp(sess.authdata,authdata,TCM_HASH_SIZE);
	if ( ret!=0 )
		return ret;

	return 0;
}
