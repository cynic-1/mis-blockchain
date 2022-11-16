#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef TCM_POSIX
#include <netinet/in.h>
#endif
#ifdef TCM_WINDOWS
#include <winsock2.h>
#endif
#include <tcm.h>
#include <tcmfunc.h>
#include <tcmutil.h>
#include <ap.h>
#include <tcmalg.h>
#include <tcm_structures.h>
#include <tcmkeys.h>

uint32_t compute_ownerauth_enc(TCM_STORE_PUBKEY * pubEK, unsigned char *ownerauth, struct tcm_buffer *ownerauth_enc){
	uint32_t ret = 0;
	uint32_t ownerauth_enc_length = TCM_MAX_BUFF_SIZE;
	unsigned char temp_ownerauth_enc[TCM_MAX_BUFF_SIZE] = {0};
	ret = tcm_ecc_init();
	if(ret != 0)return ret;
	ret = tcm_ecc_encrypt(ownerauth, 32, pubEK->key, 65, temp_ownerauth_enc, &ownerauth_enc_length);
	if(ret != 0)return ret;
	ret = tcm_ecc_release();
	if(ret != 0)return ret;
	ret = TSS_buildbuff(" % ", ownerauth_enc, ownerauth_enc_length, temp_ownerauth_enc);
	// memcpy(ownerauth_enc->buffer, temp_ownerauth_enc, ownerauth_enc_length);
	// ownerauth_enc->used = ownerauth_enc_length;
	return ret;
}

uint32_t compute_smkauth_enc(TCM_STORE_PUBKEY * pubEK, unsigned char *smkauth, struct tcm_buffer *smkauth_enc){
	uint32_t ret = 0;
	uint32_t smkauth_enc_length = TCM_MAX_BUFF_SIZE;
	unsigned char temp_smkauth_enc[TCM_MAX_BUFF_SIZE] = {0};
	ret = tcm_ecc_init();
	if(ret != 0)return ret;
	ret = tcm_ecc_encrypt(smkauth, 32, pubEK->key, 65, temp_smkauth_enc, &smkauth_enc_length);
	if(ret != 0)return ret;
	ret = tcm_ecc_release();
	if(ret != 0)return ret;
	ret = TSS_buildbuff(" % ", smkauth_enc, smkauth_enc_length, temp_smkauth_enc);
	// memcpy(smkauth_enc->buffer, temp_smkauth_enc, smkauth_enc_length);
	// smkauth_enc->used = smkauth_enc_length;
	return ret;
}

uint32_t set_smk(struct tcm_buffer *smk){
	uint16_t tag = TCM_TAG_KEY;
	uint16_t fill = 0;
	uint16_t keyUsage = TCM_SMS4KEY_STORAGE;
	uint32_t keyFlags = 0x00000000;
	BYTE authDataUsage = TCM_AUTH_ALWAYS;
	uint32_t algorithmID = TCM_ALG_SMS4; 
	uint16_t encScheme = TCM_ES_SMS4_CBC; 
	uint16_t sigScheme = TCM_SS_ECCNONE; 
	uint32_t parmSize = 28;
	//uint32_t SM2KeyLength = -1;
	uint32_t SYMKeyLength = 128; //0x80
	uint32_t blockSize = 128; //0x80
	uint32_t ivSize = 16;
	BYTE iv[16] = {0};
	uint32_t PCRInfoSize = 0;
	BYTE *PCRInfo = NULL;
	uint32_t pubKeyLength = 0;
	BYTE *pubKey = NULL;
	uint32_t encDataSize = 0;
	BYTE *encData = NULL;

	uint32_t ret = 0;

	ret = TSS_buildbuff(" S S S L o L S S L L L @ @ @ @", smk,
							tag, fill, keyUsage, keyFlags,
							authDataUsage, algorithmID, encScheme, sigScheme,
							parmSize, SYMKeyLength, blockSize,
							ivSize, iv, PCRInfoSize, PCRInfo,
							pubKeyLength, pubKey, encDataSize, encData);

	return ret;
}

uint32_t compute_auth(unsigned char *ownerauth, uint32_t ordinal_no, uint16_t ownerid, 
								struct tcm_buffer *ownerauth_enc, struct tcm_buffer *smkauth_enc,
								struct tcm_buffer *smk, apsess * sess){
	STACK_TCM_BUFFER(paramarray)
	STACK_TCM_BUFFER(hashbuf)
	STACK_TCM_BUFFER(buf)
	uint32_t ret = 0;
	ret = TSS_buildbuff("L S @ @ % ", &paramarray, 
										ordinal_no, ownerid, 
										ownerauth_enc->used, ownerauth_enc->buffer,
										smkauth_enc->used, smkauth_enc->buffer,
										smk->used, smk->buffer);

	if (tcm_sch_hash(paramarray.used, paramarray.buffer, hashbuf.buffer) != 0) return ERR_HMAC_FAIL;
	hashbuf.used = TCM_HASH_SIZE;

	/* compute hmac(key, ordinal||nonce) */
	ret = TSS_buildbuff("% L", &buf, TCM_HASH_SIZE, hashbuf.buffer, sess->nonce);
	if ((ret & ERR_MASK) != 0) return ret;
	// note the key is ownerauth, not sess->sharedsecret, so we cannot use compute_auth2() here
	// maybe extend compute_auth2() in the future
	if (tcm_hmac(buf.buffer, buf.used, ownerauth, TCM_HASH_SIZE, sess->authdata) != 0) return ERR_HMAC_FAIL;
	return ret;
}

/****************************************************************************/
/*                                                                          */
/*  Take Ownership of the TCM                                               */
/*                                                                          */
/*                                                                          */
/****************************************************************************/
uint32_t TCM_TakeOwnership(	TCM_STORE_PUBKEY *pubEK, 
						unsigned char *ownerauth, unsigned char *smkauth)
{
	uint32_t ret = 0;
    STACK_TCM_BUFFER(tcmdata)

    /* fields to be inserted into Owner Clear Request Buffer */
    uint32_t ordinal_no = TCM_ORD_TakeOwnership;
    apsess sess;
    uint32_t evalue;
	uint16_t etype;

	//初始化授权信息和密钥类型
	unsigned char keyauth[TCM_HASH_SIZE] = {0};
	etype = TCM_ET_NONE;
    evalue = 0;

	//	创建AP会话sess
    ret = TSS_APopen(&sess, keyauth, etype, evalue);
    if (ret != 0) 
        return ret;
    //sess.nonce++;

	// 生成构造所需要的数据
	STACK_TCM_BUFFER(ownerauth_enc)
	STACK_TCM_BUFFER(smkauth_enc)
	STACK_TCM_BUFFER(smk)
	// STACK_TCM_BUFFER(auth)

	ret = compute_ownerauth_enc(pubEK, ownerauth, &ownerauth_enc);
	ret = compute_smkauth_enc(pubEK, smkauth, &smkauth_enc);
	ret = set_smk(&smk);

	uint16_t ownerid = TCM_PID_OWNER;

	ret = compute_auth(ownerauth, ordinal_no, ownerid, &ownerauth_enc, &smkauth_enc,
								&smk, &sess);

	// 构建命令
    ret = TSS_buildbuff("00 c2 T L S @ @ % L %",&tcmdata,
						ordinal_no, ownerid,
                        ownerauth_enc.used, ownerauth_enc.buffer, 
						smkauth_enc.used, smkauth_enc.buffer,
						smk.used, smk.buffer,
						sess.handle,
						TCM_HASH_SIZE, sess.authdata);

    if ((ret & ERR_MASK) != 0)
	{
        TSS_APclose(&sess);
        return ret;
	}
    ret = TCM_Transmit(&tcmdata,"Takeownership");
	tcm_buffer_load32(&tcmdata, 6, &ret);	

	sess.nonce++;
	TSS_APclose(&sess);

	return ret;
}

/****************************************************************************/
/*                                                                          */
/*  Clear the TCM                                                           */
/*                                                                          */
/*                                                                          */
/****************************************************************************/
uint32_t TCM_OwnerClear(unsigned char *ownerauth, uint16_t entitytype, uint32_t entityvalue)
{
    uint32_t ret;
    STACK_TCM_BUFFER(tcmdata)

    /* fields to be inserted into Owner Clear Request Buffer */
    uint32_t ordinal_no = TCM_ORD_OwnerClear;
	//uint8_t ordinal[4] = {0x0, 0x0, 0x80, 0x5b};
    apsess sess;
    // uint32_t keyhandle;
	// uint16_t keytype;

    //初始化授权信息和密钥类型
	// keytype = TCM_ET_OWNER;
    // keyhandle = TCM_KH_OWNER;

    //	创建AP会话sess
    ret = TSS_APopen(&sess, ownerauth, entitytype, entityvalue);
    if (ret != 0) 
        return ret;

	STACK_TCM_BUFFER(params)
	ret = compute_authdata2(ordinal_no, &params, &sess);
    if (ret == 0)
    {
		printf("Ownerclear compute_authdata2 failed!\n");
        TSS_APclose(&sess);
        return ret;
    }

    // 构建命令
    ret = TSS_buildbuff("00 c2 T L L %",&tcmdata,
                        ordinal_no, sess.handle,
                        TCM_HASH_SIZE, sess.authdata);
    if ((ret & ERR_MASK) != 0)
	{
		printf("Ownerclear TSS_buildbuff failed!\n");
        TSS_APclose(&sess);
        return ret;
	}
    ret = TCM_Transmit(&tcmdata,"Owner Clear");
	tcm_buffer_load32(&tcmdata, 6, &ret);	

    sess.nonce++;
    TSS_APclose(&sess);
    return ret;
}


uint32_t TCM_ForceClear()
{
	uint32_t ret;
	uint32_t ordinal_no = TCM_ORD_ForceClear;
	STACK_TCM_BUFFER(tcmdata)
	
	ret = TSS_buildbuff("00 c1 T L",&tcmdata,
	                             ordinal_no);
	if ((ret & ERR_MASK)) {
		return ret;
	}
	
	ret = TCM_Transmit(&tcmdata,"ForceClear");

	if (ret == 0 && tcmdata.used != 10) {
		ret = ERR_BAD_RESP;
	}
	tcm_buffer_load32(&tcmdata, 6, &ret);	
	return ret;
}