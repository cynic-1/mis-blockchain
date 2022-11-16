#ifdef TCM_POSIX
#include <netinet/in.h>
#endif
#ifdef TCM_WINDOWS
#include <winsock2.h>
#endif
#include "tcm_structures.h"
#include "tcm.h"
#include <memory.h>
#include "ap.h"
#include "tcmalg.h"
#include "tcmutil.h"


void TCM_CreateEncAuth(apsess *sess, unsigned char *in, unsigned char *out)
{
	uint32_t i;
	STACK_TCM_BUFFER(buf)
	unsigned char xorhash[TCM_HASH_SIZE];
	/* ALL BUFFERS MUST USE BUILDBUFF TO BUILD, AVOID USING MEMCPY *
	* ESPECIALY SCH_HASH BUFFER, USING ONE DAY TO FIND THIS ERROR */
	/* error code is listed below, WARING IN THE WRITING */
	/*// unsigned char inhash[TCM_HASH_SIZE+4];
	// memcpy(inhash, sess->sharedsecret, TCM_HASH_SIZE);
	// memcpy(inhash+TCM_HASH_SIZE,&sess->nonce,4);*/

	/* this function includes rebuilding the sessionkey, will take this procedure to an independent function in the future */
	TSS_buildbuff("% L", &buf, TCM_HASH_SIZE, sess->sharedsecret, sess->nonce);
	tcm_sch_hash(TCM_HASH_SIZE+4, buf.buffer, xorhash);
	for (i = 0; i < TCM_HASH_SIZE; i++) 
		out[i] = xorhash[i] ^ in[i];	
}

uint32_t compute_authdata1(unsigned char *key, uint32_t ordinal, apsess *sess){

	uint32_t ret = 0;
	STACK_TCM_BUFFER(buf)
	/* compute hmac(key, ordinal||etype||evalue||callerNonce) */
	// ret = TSS_buildbuff("L o L %", &buf, ordinal, etype, evalue, TCM_NONCE_SIZE, sess->callernonce);
	ret = TSS_buildbuff("L %", &buf, ordinal, TCM_NONCE_SIZE, sess->callernonce);
	if ((ret & ERR_MASK) != 0) return ret;

 	if (tcm_hmac(buf.buffer, buf.used, key, TCM_HASH_SIZE, sess->authdata) != 0) return ERR_HMAC_FAIL;

	memset(buf.buffer, 0, buf.used);
	buf.used = 0;
	return ret;
}

uint32_t compute_shared_secret(unsigned char *key, apsess *sess){

	uint32_t ret = 0;
	STACK_TCM_BUFFER(buf)
	  /* compute sharedSecret */
	ret = TSS_buildbuff("% %", &buf, TCM_NONCE_SIZE, sess->callernonce, TCM_NONCE_SIZE, sess->tcmnonce);
	if ((ret & ERR_MASK)) return ret;
	//printf("HMAC 1\n");
	if (tcm_hmac(buf.buffer, buf.used, key, TCM_HASH_SIZE, sess->sharedsecret) != 0) return ERR_HMAC_FAIL;
	//printf("HMAC 2\n");	
	memset(buf.buffer, 0, buf.used);
	buf.used = 0;	
	return ret;
}

uint32_t parse_result(struct tcm_buffer *tcmdata, apsess *sess){
	uint32_t ret = 0;
	
	ret = tcm_buffer_load32(tcmdata, TCM_DATA_OFFSET, &sess->handle);
	if ((ret & ERR_MASK)) return ret;

	memcpy(sess->tcmnonce, &tcmdata->buffer[TCM_DATA_OFFSET + TCM_U32_SIZE], TCM_NONCE_SIZE);

	ret = tcm_buffer_load32(tcmdata, TCM_DATA_OFFSET + TCM_U32_SIZE + TCM_NONCE_SIZE, &sess->nonce);
	if ((ret & ERR_MASK)) return ret;

	memcpy(sess->authdata, &tcmdata->buffer[TCM_DATA_OFFSET + TCM_U32_SIZE + TCM_NONCE_SIZE + TCM_U32_SIZE], TCM_AUTHDATA_SIZE);   
	return ret;
}

/****************************************************************************/
/*                                                                          */
/* Open an AP session                                                       */
/*                                                                          */
/****************************************************************************/
uint32_t TSS_APopen(apsess *sess, unsigned char *key, uint16_t etype, uint32_t evalue)
{
	uint32_t ret = 0;
	STACK_TCM_BUFFER(tcmdata)
	uint32_t ordinal = TCM_ORD_APCreate;
	unsigned char authdata[TCM_AUTHDATA_SIZE];

	/* check input arguments */
	if (key == NULL || sess == NULL) return ERR_NULL_ARG;

      /* generate callerNonce */
	TSS_tcmgennonce(sess->callernonce);

	ret = compute_authdata1(key, ordinal, sess);

	/* invoke TCM_APCreate */
	// ret = TSS_buildbuff("00 C2 T L o L % %", &tcmdata, ordinal, etype, evalue, TCM_NONCE_SIZE, sess->callernonce, TCM_HASH_SIZE, sess->authdata);
	ret = TSS_buildbuff("00 C1 T L S L % %", &tcmdata, ordinal, etype, evalue, TCM_NONCE_SIZE, sess->callernonce, TCM_HASH_SIZE, sess->authdata);

	//printf("tcmdata %s",&tcmdata);
     ret = TCM_Transmit(&tcmdata, "APCreate");
	tcm_buffer_load32(&tcmdata, 6, &ret);	
	if (0 != ret) return ret;
	
	parse_result(&tcmdata, sess);
    sess->entitytype = etype;

    /* compute sharedSecret */
	ret = compute_shared_secret(key, sess);

      /* check authdata */
//       ret = TSS_buildbuff("L L L % L", &buf, ordinal, result, sess->handle, TCM_NONCE_SIZE, sess->tcmnonce, sess->nonce);
// 	if ((ret & ERR_MASK)) return ret;

// //printf("HMAC 3\n");	
// 	if (tcm_hmac(buf.buffer, buf.used, sess->sharedsecret, TCM_HASH_SIZE, authdata) != 0) return ERR_HMAC_FAIL;
// //printf("HMAC 4\n");	


// 	memset(buf.buffer, 0, buf.used);
// 	buf.used = 0;

// 	if (memcmp(sess->authdata,authdata,TCM_HASH_SIZE) != 0) return ERR_HMAC_FAIL;    

	return 0;
}

uint32_t compute_authdata2(uint32_t ordinal, struct tcm_buffer * params, apsess *sess){
	uint32_t ret = 0;
	STACK_TCM_BUFFER(tmpbuf)
	STACK_TCM_BUFFER(hashbuf)
	STACK_TCM_BUFFER(buf)

	TSS_buildbuff("L%", &tmpbuf, ordinal, params->used, params->buffer);
	if (tcm_sch_hash(tmpbuf.used, tmpbuf.buffer, hashbuf.buffer) != 0) return ERR_HMAC_FAIL;
	hashbuf.used = TCM_HASH_SIZE;

	/* compute hmac(key, ordinal||nonce) */
	ret = TSS_buildbuff("% L", &buf, TCM_HASH_SIZE, hashbuf.buffer, sess->nonce);
	if ((ret & ERR_MASK) != 0) return ret;

	if (tcm_hmac(buf.buffer, buf.used, sess->sharedsecret, TCM_HASH_SIZE, sess->authdata) != 0) return ERR_HMAC_FAIL;

	memset(buf.buffer, 0, buf.used);
	buf.used = 0;

	return ret;
}

/****************************************************************************/
/*                                                                          */
/* Close an AP session                                                      */
/*                                                                          */
/****************************************************************************/
uint32_t TSS_APclose(apsess *sess)
{
	uint32_t ret;
	STACK_TCM_BUFFER(tcmdata)
	STACK_TCM_BUFFER(parambuf)
	uint32_t ordinal = TCM_ORD_APTerminate;

	if (sess == NULL) return ERR_NULL_ARG;	
		
	ret = compute_authdata2(ordinal, &parambuf, sess);
	
	/* invoke TCM_APTerminate */
	ret = TSS_buildbuff("00 C2 T L L %", &tcmdata, ordinal, sess->handle, TCM_AUTHDATA_SIZE, sess->authdata); 
	if ((ret & ERR_MASK) != 0) return ret;

    ret = TCM_Transmit(&tcmdata, "APClose");	
	
	tcm_buffer_load32(&tcmdata, 6, &ret);	
	return ret;
}
