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

	//3)	计算schsum、sumLen
	// char *pUserID = "ALICE123@YAHOO.COM";
	// unsigned int userIDLen = strlen(pUserID);
	// tcm_ecc_init();
	// ret = tcm_get_message_hash(data, datalen, (unsigned char*)pUserID, userIDLen, 
	// 	tcmpubkey.pubKey.key, tcmpubkey.pubKey.keyLength, 
	// 	schsum, &sumLen);
	// if (ret!=0)
	// 	return -1;

	//6)	计算授权数据sess->authdata
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

	//7)	创建请求数组tcmdata
	// TSS_buildbuff("00 C2 T L L L % L %", &tcmdata, ordinal, keyhandle, sumLen, sumLen, schsum,
	// 	sess.handle, TCM_HASH_SIZE, sess.authdata);
	TSS_buildbuff("00 C2 T L L @ L %", &tcmdata, ordinal, keyhandle, datalen, data, sess->handle, TCM_HASH_SIZE, sess->authdata);

	//8)	发送请求给TCM/TCM设备
	ret = TCM_Transmit(&tcmdata, "Sign");
	if (ret != 0)
	{
		TSS_APclose(sess);
		return ret;
	}

	//10)	解析响应数据
	uint32_t result = 0;	
	tcm_buffer_load32(&tcmdata, TCM_RETURN_OFFSET, &result);
	if (result!=TCM_SUCCESS)
		return -1;
	tcm_buffer_load32(&tcmdata, TCM_DATA_OFFSET, siglen);
	memcpy(sig, &tcmdata.buffer[TCM_DATA_OFFSET+4], *siglen);
	memcpy(sess->authdata, &tcmdata.buffer[tcmdata.used-TCM_AUTHDATA_SIZE], TCM_AUTHDATA_SIZE);

	//11)	验证授权数据sess->authdata
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
/* TCM_Sign 签名														*/
/* 输出：sig、siglen													*/
/* 功能描述：根据输入数据组装TCM_Sign命令请求，							*/
/* 命令调用成功后，解析TCM响应，验证授权数据，输出签名数据。			*/
/************************************************************************/
uint32_t TCM_Sign(uint32_t keyhandle, unsigned char *keyauth,
			 unsigned char *data, uint32_t datalen, 
			 unsigned char *sig, uint32_t *siglen)
{
	uint32_t ret;
	
	apsess sess;
	uint8_t keytype = 0;
	TCM_PUBKEY tcmpubkey;
	//初始化tcmpubkey
	tcmpubkey.algorithmParms.algorithmID = 0;
	tcmpubkey.algorithmParms.encScheme = 0;
	tcmpubkey.algorithmParms.sigScheme = 0;
	tcmpubkey.algorithmParms.parmSize = 4;
	tcmpubkey.algorithmParms.parms.ecc.keyLength = 0;
	tcmpubkey.pubKey.keyLength = 0;
	tcmpubkey.pubKey.key = NULL;

	//1)	验证输入参数data和sig不为空
	if (data == NULL || sig == NULL) return ERR_NULL_ARG;

	//4)	用TSS_APopen()创建AP会话sess
	keytype = TCM_ET_KEYHANDLE;		
	ret = TSS_APopen(&sess, keyauth, keytype, keyhandle);
	if (ret != 0) 
		return ret;

	//2)	获取签名密钥对应的公钥
	ret = TCM_GetPubKey_internal(&sess, keyhandle, &tcmpubkey);
	if (ret!=0)
		return ret;

	//5)	序列号加1
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
	//9)	用TSS_APclose()终止AP会话
	TSS_APclose(&sess);

	return ret;
}

/************************************************************************/
/* TCM_Verify 验证														*/
/* 输出：verifyResult													*/
/* 功能描述：根据输入数据组装TCM_Verify命令请求，						*/
/* 命令调用成功后，解析TCM响应，验证授权数据，输出验证结果。			*/
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

	//1)	验证输入参数ownerAuth 、signedData、signatureValue和key不为空
	if (ownerAuth == NULL || signedData == NULL
		|| signatureValue ==NULL || key == NULL) return ERR_NULL_ARG;

	//2)	计算schsum、sumLen
	char *pUserID = "ALICE123@YAHOO.COM";
	unsigned int userIDLen = strlen(pUserID);
	tcm_ecc_init();
	ret = tcm_get_message_hash(signedData, signedDataSize, (unsigned char*)pUserID, userIDLen, 
		key->pubKey.key, key->pubKey.keyLength, 
		schsum, &sumLen);
	if (ret!=0)
		return -1;

	//3)	用TSS_APopen()创建AP会话sess
	ret = TSS_APopen(&sess, ownerAuth, TCM_ET_OWNER, TCM_KH_OWNER);
	if (ret != 0) 
		return ret;

	//4)	序列号加1
	sess.nonce++;

	//5)	计算授权数据sess->authdata
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

	//6)	创建请求数组tcmdata
	TSS_buildbuff("00 C2 T L % L % L % L %", &tcmdata, ordinal, keylen1, ptr, 
			sumLen, sumLen, schsum,	signatureValueSize, signatureValueSize,signatureValue,  
			sess.handle, TCM_HASH_SIZE, sess.authdata);

	//7)	发送请求给TCM/TCM设备
	ret = TCM_Transmit(&tcmdata, "Verify-AUTH1");
	if (ret != 0)
	{
		TSS_APclose(&sess);
		return ret;
	}

	//8)	用TSS_APclose()终止AP会话
	TSS_APclose(&sess);

	//9)	解析响应数据
	uint32_t result = 0;
	tcm_buffer_load32(&tcmdata, TCM_RETURN_OFFSET, &result);
	if (result!=TCM_SUCCESS)
		return -1;
	memcpy(verifyResult, &tcmdata.buffer[TCM_DATA_OFFSET],1);
	memcpy(sess.authdata, &tcmdata.buffer[TCM_DATA_OFFSET + 1], TCM_AUTHDATA_SIZE);

	//10)	验证授权数据sess->authdata
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
/* TCM_EccEncrypt ECC加密												*/
/* 输出：enc、encSize													*/
/* 功能描述：根据输入数据组装TCM_ EccEncrypt命令请求，					*/
/* 命令调用成功后，解析TCM响应，验证授权数据。							*/
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

	//1)	验证输入参数ownerAuth、areaToEnc和enc不为空
	if (ownerAuth == NULL || areaToEnc == NULL
		|| enc ==NULL ) return ERR_NULL_ARG;

	//2)    创建AP会话
	ret = TSS_APopen(&sess, ownerAuth, TCM_ET_OWNER, TCM_KH_OWNER);
	if (ret != 0) 
		return ret;

	//3)	序列号加1
	sess.nonce++;

	//4)	计算授权数据sess->authdata
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

	//5)	创建请求数组tcmdata
	TSS_buildbuff("00 C2 T L % L % L %", &tcmdata, ordinal, keylen1, ptr, 
		areaToEncSize, areaToEncSize, areaToEnc, sess.handle, TCM_HASH_SIZE, sess.authdata);

	//6)	发送请求给TCM/TCM设备
	ret = TCM_Transmit(&tcmdata, "EccEncrypt-AUTH1");
	if (ret != 0)
	{
		TSS_APclose(&sess);
		return ret;
	}

	//7)    终止AP会话
	TSS_APclose(&sess);

	//8)	解析响应数据
	uint32_t result = 0;
	tcm_buffer_load32(&tcmdata, TCM_RETURN_OFFSET, &result);
	if (result!=TCM_SUCCESS)
		return -1;
	tcm_buffer_load32(&tcmdata, TCM_DATA_OFFSET, encSize);
	memcpy(enc, &tcmdata.buffer[TCM_DATA_OFFSET+4], *encSize);
	memcpy(sess.authdata, &tcmdata.buffer[tcmdata.used-TCM_AUTHDATA_SIZE], TCM_AUTHDATA_SIZE);

	//9)	验证授权数据sess->authdata
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
/* TCM_EccDecrypt ECC解密												*/
/* 输出：blob、bloblen													*/
/* 功能描述：根据输入数据组装TCM_EccDecrypt命令请求，					*/
/* 命令调用成功后，解析TCM响应，验证授权数据，输出解密后的数据和长度。	*/
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

	//1)	验证输入参数data和blob不为空
	if (data == NULL || blob == NULL) return ERR_NULL_ARG;

	//2)    创建AP会话
	if (keyhandle == TCM_KH_SMK) keytype = TCM_ET_SMK;
	else                         keytype = TCM_ET_KEYHANDLE;

	ret = TSS_APopen(&sess, keyauth, keytype, keyhandle);
	if (ret != 0) 
		return ret;

	//3)	序列号加1
	sess.nonce++;

	//4)	计算授权数据sess->authdata
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

	//5)	创建请求数组tcmdata
	TSS_buildbuff("00 C2 T L L L % L %", &tcmdata, ordinal, keyhandle, 
		datalen, datalen, data, sess.handle, TCM_HASH_SIZE, sess.authdata);

	//6)	发送请求给TCM/TCM设备
	ret = TCM_Transmit(&tcmdata, "EccDecrypt-AUTH1");
	if (ret != 0)
	{
		TSS_APclose(&sess);
		return ret;
	}

	//7)    终止AP会话
	TSS_APclose(&sess);

	//8)	解析响应数据
	uint32_t result = 0;
	tcm_buffer_load32(&tcmdata, TCM_RETURN_OFFSET, &result);
	if (result!=TCM_SUCCESS)
		return -1;
	tcm_buffer_load32(&tcmdata, TCM_DATA_OFFSET, bloblen);
	memcpy(blob, &tcmdata.buffer[TCM_DATA_OFFSET+4], *bloblen);
	memcpy(sess.authdata, &tcmdata.buffer[tcmdata.used-TCM_AUTHDATA_SIZE], TCM_AUTHDATA_SIZE);

	//9)	验证授权数据sess->authdata
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
/* TCM_SMS4Encrypt SMS4加密												*/
/* 输出：IV、blob、bloblen												*/
/* 功能描述：根据输入数据组装TCM_ SMS4Encrypt命令请求，					*/
/* 命令调用成功后，解析TCM响应，验证授权数据，输出初始向量、密文和长度。*/
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

	//1)	验证输入参数keyauth、data、IV和blob不为空
	if ( keyauth == NULL || data == NULL
		 || IV == NULL || blob ==NULL ) return ERR_NULL_ARG;

	//2)    创建AP会话
	if (keyhandle == TCM_KH_SMK) keytype = TCM_ET_SMK;
	else                         keytype = TCM_ET_KEYHANDLE;
	ret = TSS_APopen(&sess, keyauth, keytype, keyhandle);
	if (ret != 0) 
		return ret;

	//3)	序列号加1
	sess.nonce++;

	//4)	生成128bit随机数IV
	srand( (unsigned)time( NULL ) );
	unsigned int i;
	for (  i=0; i<16; i++)
	{
		IV[i] = rand()%256;
	}

	//5)	计算授权数据sess->authdata
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

	//6)	创建请求数组tcmdata
	TSS_buildbuff("00 C2 T L L % L % L %", &tcmdata, ordinal, keyhandle, 16, IV, 
		datalen, datalen, data, sess.handle, TCM_HASH_SIZE, sess.authdata);

	//7)	发送请求给TCM/TCM设备
	ret = TCM_Transmit(&tcmdata, "SMS4Encrypt-AUTH1");
	if (ret != 0)
	{
		TSS_APclose(&sess);
		return ret;
	}

	//7)    终止AP会话
	TSS_APclose(&sess);

	//8)	解析响应数据
	uint32_t result = 0;
	tcm_buffer_load32(&tcmdata, TCM_RETURN_OFFSET, &result);
	if (result!=TCM_SUCCESS)
		return -1;
	tcm_buffer_load32(&tcmdata, TCM_DATA_OFFSET, bloblen);
	memcpy(blob, &tcmdata.buffer[TCM_DATA_OFFSET+4], *bloblen);
	memcpy(sess.authdata, &tcmdata.buffer[tcmdata.used-TCM_AUTHDATA_SIZE], TCM_AUTHDATA_SIZE);

	//9)	验证授权数据sess->authdata
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
/* TCM_SMS4Decrypt SMS4解密												*/
/* 输出：blob、bloblen													*/
/* 功能描述：根据输入数据组装TCM_SMS4Decrypt命令请求，					*/
/* 命令调用成功后，解析TCM响应，验证授权数据，输出明文和长度。			*/
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

	//1)	验证输入参数IV、data和blob不为空
	if (IV == NULL || data == NULL
		|| blob == NULL) return ERR_NULL_ARG;

	//2)    创建AP会话
	if (keyhandle == TCM_KH_SMK) keytype = TCM_ET_SMK;
	else                         keytype = TCM_ET_KEYHANDLE;

	ret = TSS_APopen(&sess, keyauth, keytype, keyhandle);
	if (ret != 0) 
		return ret;

	//3)	序列号加1
	sess.nonce++;

	//4)	计算授权数据sess->authdata
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

	//5)	创建请求数组tcmdata
	TSS_buildbuff("00 C2 T L L % L % L %", &tcmdata, ordinal, keyhandle, 16, IV,
		datalen, datalen, data, sess.handle, TCM_HASH_SIZE, sess.authdata);

	//6)	发送请求给TCM/TCM设备
	ret = TCM_Transmit(&tcmdata, "SMS4Decrypt-AUTH1");
	if (ret != 0)
	{
		TSS_APclose(&sess);
		return ret;
	}

	//7)    终止AP会话
	TSS_APclose(&sess);

	//8)	解析响应数据
	uint32_t result = 0;
	tcm_buffer_load32(&tcmdata, TCM_RETURN_OFFSET, &result);
	if (result!=TCM_SUCCESS)
		return -1;
	tcm_buffer_load32(&tcmdata, TCM_DATA_OFFSET, bloblen);
	memcpy(blob, &tcmdata.buffer[TCM_DATA_OFFSET+4], *bloblen);
	memcpy(sess.authdata, &tcmdata.buffer[tcmdata.used-TCM_AUTHDATA_SIZE], TCM_AUTHDATA_SIZE);

	//9)	验证授权数据sess->authdata
	STACK_TCM_BUFFER(buf2)
	unsigned char authdata[TCM_AUTHDATA_SIZE];
	TSS_buildbuff("L L L % L", &buf2, ordinal, result, *bloblen, *bloblen, blob, sess.nonce);
	tcm_hmac(buf2.buffer, buf2.used, sess.sharedsecret, TCM_HASH_SIZE, authdata);
	ret = memcmp(sess.authdata,authdata,TCM_HASH_SIZE);
	if ( ret!=0 )
		return ret;

	return 0;
}
