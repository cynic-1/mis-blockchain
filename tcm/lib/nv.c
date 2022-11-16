#ifdef TCM_POSIX
#include <netinet/in.h>
#endif
#ifdef TCM_WINDOWS
#include <winsock2.h>
#endif
#include "tcm.h"
#include "ap.h"
#include "tcm_structures.h"
#include "tcmfunc.h"
#include "tcmalg.h"
#include "common.h"
#include "tcmutil.h"
#include "libtddl.h"

//#define MAX_BUFSIZE 2048
BYTE g_outBuffer[MAX_BUFSIZE];
uint32_t g_outBufferLength;
BYTE g_OwnerAuthData[32] = {0};


unsigned char APTerminate_part[10] = {0x00,0xC2, 0x00,0x00,0x00,0x2E, 0x00,0x00,0x80,0xC0};

uint32_t TCM_NV_DefineSpace(unsigned char index,BYTE nvSize[] ,BYTE attribute[])
{
	int returnCode = 0;
	int ErrorFlag = 0; // =1 seq not ++ ,=0 ,seq++		
	//BYTE buf1[32]={ 0x00 };
	unsigned int iret, i;
	//unsigned int attributes; 
	BYTE hmac_Text[64] = {0x00}; 
	BYTE hmac_inMac[32] = { 0x00 };
	BYTE session_key[32];
	BYTE APcreate[80] = { 0x00 };
	BYTE sessionHandle[4] = { 0x00 };
	BYTE seq_APCreateOut[4] = { 0x00 };
	unsigned char AP2[16] = { 0x00,0xc1, 0x00,0x00,0x00,0x50, 0x00,0x00,0x80,0xBF, 0x00,0x02, 0x00,0x00,0x00,0x00 };
	unsigned char APTerminate_part[10] = {0x00,0xC2, 0x00,0x00,0x00,0x2E, 0x00,0x00,0x80,0xC0};

	sch_context ctx_nv;
	unsigned char DefineSpace[249] =	{	
											0x00,0xc2,	//tag: TCM_TAG_RQU_AUTH1_COMMAND
											0x00,0x00,0x00,0xf9,	//paramSize: 249
											0x00,0x00,0x80,0xcc,	//TCM_ORD_NV_DefineSpace
																	//NV¿ÕŒä¹«¿ªÐÅÏ¢
											0x00,0x18,		//TCM_TAG_NV_DATA_PUBLIC
															//0x00,0x01,0x12,0x85,	//nvIndex: 70277
											0x00,0x00,0x00,0x00,	//nvIndex: 1  test
											0x00,0x06,
											0x01,0x01,
											0x00,0x02,		// (sizeOfSelect: 2)
											0x00,0x01,		//(pcrSelect: 1)
											0x00,0x02,		// (sizeOfSelect: 2)
											0x00,0x01,		//(pcrSelect: 1)              28
											0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
											0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
											0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
											0x00,0x00,		//digestAtCreation	32b   28+32
											0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
											0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
											0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
											0x00,0x00,		//digestAtRelease	32b   28+32+32
											0x00,0x06, 		//(tag: TCM_TAG_PCR_INFO_FINAL)
											0x01,0x01,
											0x00,0x02,		// (sizeOfSelect: 2)
											0x00,0x01,		//(pcrSelect: 1)
											0x00,0x02,		// (sizeOfSelect: 2)
											0x00,0x01,		//(pcrSelect: 1)	      28+32+32+12
											0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
											0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
											0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
											0x00,0x00,		//digestAtCreation	32b   28+32+32+12+32
											0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
											0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
											0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
											0x00,0x00,		//digestAtRelease	32b   28+32+32+12+32+32
											0x00,0x17,		//(tag: TCM_TAG_NV_ATTRIBUTES)
											//0x00,0x04,0x00,0x04,	// (attributes: 262148) attributes = TCM_NV_PER_AUTH_READ | TCM_NV_PER_AUTHWRITE;
											0x00,0x02,0x00,0x02,//TCM_NV_PER_OWNER_READ|TCM_NV_PER_OWNERWRITE
											0x00,0x00,0x00,
											0x00,0x00,0x03,0x00, 	//(dataSize: 128*6 ,first 32B for cnt the number of apk pub key)
																	//¹«¿ªÐÅÏ¢ end					       28+32+32+12+32+32+13
											0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
											0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
											0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
											0x00,0x00,		//encAuth	32b		28+32+32+12+32+32+13+32
											0x00,0x00,0x00,0x00,	//Session handle
																	//0x00,0x00,0x00,0x05,	//Session handle	test
											0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
											0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
											0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
											0x00,0x00		//HMAC	32b
										};
	//set the index
	memcpy(DefineSpace + 15, &index, 1);
	memcpy(DefineSpace + 28 + 32 + 32 + 12 + 32 + 32 + 13-4, nvSize,4);
	//memset(out_buf, 0, sizeof(out_buf));
	//attributes = TCM_NV_PER_OWNERWRITE | TCM_NV_PER_OWNER_READ;//TCM_NV_PER_AUTH_READ | TCM_NV_PER_AUTHWRITE;
	memcpy(DefineSpace + 170, attribute, 4);
	tcmPrintf_internalDebug("attribute",4,attribute);
	printf("PCR Read\n");
	g_outBufferLength = MAX_BUFSIZE;
	memset(g_outBuffer, 0x00, MAX_BUFSIZE);
	BYTE cmd_PCRRead[] = { 0x00,0xc1, 0x00,0x00,0x00,0x0e, 0x00,0x00,0x80,0x15 ,0x00,0x00,0x00,0x08 };
	tcmPrintf("In :", 14, cmd_PCRRead);

	Tddli_Open();
	iret = Tddli_TransmitData(cmd_PCRRead, 14, g_outBuffer, &g_outBufferLength);
	Tddli_Close();

	tcmPrintf("Out :", g_outBufferLength, g_outBuffer);
	//memcpy(out_buf, OutBuf, g_outBufferLength);
	
	if ( 0x00== Unpack32(g_outBuffer +6))
	{
		BYTE tempData[4] = { 0x00 };
		tcm_sch_starts(&ctx_nv);
		tempData[0] = 0x00;
		tempData[1] = 0x02;
		tcm_sch_update(&ctx_nv, tempData, 2);  //0x00 0x02
		tempData[0] = 0x00;
		tempData[1] = 0x01;
		tcm_sch_update(&ctx_nv, tempData, 2);  //0x00 0x01
		tempData[0] = 0x00;
		tempData[1] = 0x00;
		tempData[2] = 0x00;
		tempData[3] = 0x20;
		tcm_sch_update(&ctx_nv, tempData, 4);  //0x00 0x00 0x00 0x20
		tcm_sch_update(&ctx_nv, g_outBuffer + 10, 32);
		BYTE buf1[32]={0x00};
		memset(buf1, 0, sizeof(buf1));
		tcm_sch_finish(&ctx_nv, buf1);
		//digestAtCreation	32b
		memcpy(DefineSpace + 28, buf1, 32);
		memcpy(DefineSpace + 28 + 32, buf1, 32);
		memcpy(DefineSpace + 28 + 32 + 32 + 12, buf1, 32);
		memcpy(DefineSpace + 28 + 32 + 32 + 12 + 32, buf1, 32);

	}
	else
	{
		printf("PCR Read Error\n");
		return Unpack32(g_outBuffer + 6);
	}

	BYTE entityType[2] = { 0x00 };
	Pack16( entityType, TCM_ET_OWNER);
	BYTE entityValue[4] = { 0x00 };
 
	//APCreateIncallerNounce
	//printf("GetRandom\n");
	g_outBufferLength = MAX_BUFSIZE;
	memset(g_outBuffer, 0x00, MAX_BUFSIZE);
	BYTE cmd_GetRandom[] = { 0x00,0xc1,0x00,0x00,0x00,0x0e,0x00,0x00,0x80,0x46,0x00,0x00,0x00,0x20 };
	tcmPrintf("In :", sizeof(cmd_GetRandom), cmd_GetRandom);

	Tddli_Open();
	iret = Tddli_TransmitData(cmd_GetRandom, sizeof(cmd_GetRandom), g_outBuffer, &g_outBufferLength);
	Tddli_Close();

	tcmPrintf("Out :", g_outBufferLength, g_outBuffer); 
	Pack32(hmac_Text, TCM_ORD_APCreate);
	BYTE APCreateIncallerNounce[32] = { 0x00 }; 
	BYTE APCreateOutcallernNounce[32] = { 0x00 };
	memcpy(APCreateIncallerNounce, g_outBuffer + 14, 32);
	g_outBufferLength = MAX_BUFSIZE;
	memset(g_outBuffer, 0x00, MAX_BUFSIZE);
	returnCode = fu_TCM_APCreate(entityType, entityValue, APCreateIncallerNounce, g_OwnerAuthData);
	if (0 == returnCode)
	{
		//printf("APCreate Success\n");
	}
	else
	{
		printf("APCreate Failed\n");
		return returnCode;
	}
	//ÊÚÈš»á»°Ÿä±ú 4 B
	memcpy(sessionHandle, g_outBuffer + 10, 4);
	memcpy(seq_APCreateOut, g_outBuffer + 14 + 32, 4);
	tcmPrintf_internalDebug("APCreate Handle:\n",4, sessionHandle);
	tcmPrintf_internalDebug("APCreate Seq:\n", 4, seq_APCreateOut);
	/*--------------------APCreate  end---------------------------*/
	memcpy(APCreateOutcallernNounce, g_outBuffer + 14, 32);
	//session handle  4B
	tcmPrintf_internalDebug("APCreateIncallerNounce", 32, APCreateIncallerNounce);
	tcmPrintf_internalDebug("APCreateOutcallernNounce", 32, APCreateOutcallernNounce);
	memcpy(DefineSpace + 213, sessionHandle, 4);
	memcpy(hmac_Text, APCreateIncallerNounce, 32);
	memcpy(hmac_Text + 32, APCreateOutcallernNounce, 32);
	memset(session_key, 0, sizeof(session_key));
	tcm_hmac(hmac_Text, 64, g_OwnerAuthData, 32, session_key);
	tcmPrintf_internalDebug("hmac_Text", 64, hmac_Text);
	tcmPrintf_internalDebug("session_key", 32, session_key);
	//make encAuth
	memset(&ctx_nv, 0, sizeof(ctx_nv));
	tcm_sch_starts(&ctx_nv);
	tcm_sch_update(&ctx_nv, session_key, 32);
	tcm_sch_update(&ctx_nv, seq_APCreateOut, 4);
	tcm_sch_finish(&ctx_nv, hmac_inMac);
	BYTE encAuth[32];
	for (i = 0; i < 32; i++)
	{
		encAuth[i] = hmac_inMac[i] ^ 0x0;
	} 
	memcpy(DefineSpace + 181, encAuth, 32);
	printf("-----------------------------------\n");
	//HMAC--inMac	 
	tcm_sch_starts(&ctx_nv);
	tcm_sch_update(&ctx_nv, DefineSpace + 6, 4);	//cmd code:00 00 80 CC
	tcm_sch_update(&ctx_nv, DefineSpace + 10, 171);	//PubInfo_NVDefineSpace
	tcm_sch_update(&ctx_nv, encAuth, 32);		//encAuth
	memset(hmac_inMac, 0x00, 32);
	tcm_sch_finish(&ctx_nv, hmac_inMac); 
	memset(hmac_Text, 0x00, 64);
	memcpy(hmac_Text , hmac_inMac, 32);
	memcpy(hmac_Text + 32, seq_APCreateOut, 4);
	tcm_hmac(hmac_Text, 36, session_key, 32, hmac_inMac); 	
	//end HMAC
	memcpy(DefineSpace + 217, hmac_inMac, 32); 
	tcmPrintf_internalDebug("nvIndex",4, DefineSpace +12);
	printf("nvIndex=%d\n",Unpack32(DefineSpace + 12));
	tcmPrintf_internalDebug("nvSize",4, DefineSpace + 28 + 32 + 32 + 12 + 32 + 32 + 13-4);
	printf("nvSize=%d\n", Unpack32(DefineSpace + 28 + 32 + 32 + 12 + 32 + 32 + 13-4));
	//printf( "DefineSpace\n");
	g_outBufferLength = MAX_BUFSIZE;
	memset(g_outBuffer, 0x00, MAX_BUFSIZE);
	tcmPrintf("In :", sizeof(DefineSpace), DefineSpace);
	Tddli_Open();
	iret = Tddli_TransmitData(DefineSpace, sizeof(DefineSpace), g_outBuffer, &g_outBufferLength);
	Tddli_Close();
	tcmPrintf("Out :", g_outBufferLength, g_outBuffer);
	//nvIndex
	tcmPrintf_internalDebug("nvIndex:", 4,DefineSpace+12);
	if ((Unpack32(g_outBuffer +6)==0))
	{
		printf("NVDefineSpace Success.\n");
	}
	else 
	{
		printf("NVDefineSpace Error,returnCode=%d\n",Unpack32(g_outBuffer+6));		 
		//printf("Error Code=%d,%s\n", Unpack32(g_outBuffer + 6), itcm_status_to_str(Unpack32(g_outBuffer + 6)));
		ErrorFlag = 1;
	}
	//APTerminate

	if (0 == ErrorFlag)
	{
		int nSeq = 0;
		nSeq = Unpack32(seq_APCreateOut);
		nSeq++;
		memset(seq_APCreateOut, 0x00, 4);
		Pack32(seq_APCreateOut, nSeq);
	}
	g_outBufferLength = MAX_BUFSIZE;
	memset(g_outBuffer, 0x00, MAX_BUFSIZE);
	//fu_TCM_APTerminate(BYTE handle_APCreateOut[], BYTE entityAuth[], BYTE seq[], BYTE APCreateIncallerNounce[], BYTE callernounceAPCreateOut[])
	fu_TCM_APTerminate(sessionHandle, g_OwnerAuthData, seq_APCreateOut, APCreateIncallerNounce, APCreateOutcallernNounce,g_OwnerAuthData);
 
	if (Unpack32(g_outBuffer +6)==0)
	{
		//printf("APTerminate Success!\n");
	}
	else {
		printf("APTerminate Error!\n");
		returnCode = Unpack32(g_outBuffer + 6);
	}
	//end APTerminate
	printf("NVDefinespace Success\n");
	if (1 == ErrorFlag )
	{
		return -1;
	}
	return returnCode;
}
#if 0
int fu_APCreate(unsigned char *AP_part, unsigned char *AP_out, unsigned char * AP_nonce)
{
	g_outBufferLength = MAX_BUFSIZE;
	memset(g_outBuffer, 0x00, MAX_BUFSIZE);
	BYTE hmac_key[32]={0x00};
	int returnCode = 0;
	int ErrorFlag = 0; // =1 seq not ++ ,=0 ,seq++

 
	unsigned char APcreate[80] = { 0 };
	unsigned char out_buf[82] = { 0 };
	unsigned char inMac[32] = { 0 };
	if ((AP_part == NULL) || (AP_out == NULL) || (AP_nonce == NULL))
	{
		printf("[ljj] APCreat:  AP_part/AP_out/AP_nonce  ==  NULL  !!\n");
		return -1;
	}
  
	printf("Getrandom\n");
 
	BYTE cmd_GetRandom[] = { 0x00,0xc1,0x00,0x00,0x00,0x0e,0x00,0x00,0x80,0x46,0x00,0x00,0x00,0x20 };
	tcmPrintf("In :", sizeof(cmd_GetRandom), cmd_GetRandom);
	returnCode = Tddli_TransmitData(cmd_GetRandom, sizeof(cmd_GetRandom), g_outBuffer, &g_outBufferLength);
	tcmPrintf("Out :", g_outBufferLength, g_outBuffer);
	//memcpy(outBuffer5, OutBuf, nOutBufLen);
	memcpy(AP_nonce, g_outBuffer + 14, 32);
	//hmac cmd
	out_buf[0] = 0x00;
	out_buf[1] = 0x00;
	out_buf[2] = 0x80;
	out_buf[3] = 0xBF;
	memcpy(out_buf + 4, g_outBuffer + 14, 32);
	memcpy(hmac_key, g_OwnerAuthData, 32);
	//memset(buf1, 0, 32);
	tcm_hmac(out_buf, 36, hmac_key, 32, inMac);
	//	printk("-------------    APCreate    ---------------\n");
	//2¡¢APCreate
	memcpy(APcreate, AP_part, 16);
	memcpy(APcreate + 16, g_outBuffer + 14, 32);
	memcpy(APcreate + 16 + 32, inMac, 32);
	printf("APcreate\n");
 
	tcmPrintf("In :", sizeof(APcreate), APcreate);
	returnCode = Tddli_TransmitData(APcreate, sizeof(APcreate), g_outBuffer, &g_outBufferLength);
	tcmPrintf("Out :", g_outBufferLength, g_outBuffer);
	memcpy(AP_out, g_outBuffer, g_outBufferLength);
	return 0;
}


int fu_APTerminate(unsigned char *buf_xvlie, unsigned char *buf_huihua, unsigned char * APT_out, unsigned char *session_key)
{
	BYTE	OutBuf[MAX_BUFSIZE] ={0x00}; 
	UINT32 nOutBufLen = MAX_BUFSIZE;
	int iret, i;
	sch_context * ctx_APT = NULL;
	unsigned char out_temp[46] = { 0 };
	unsigned char buf[36] = { 0 };
	unsigned char inMac[32] = { 0 };

	if ((buf_xvlie == NULL) || (APT_out == NULL) || (buf_huihua == NULL))
	{
		printf("[ljj] APTerminate:  buf_xvlie/APT_out/buf_huihua  ==  NULL  !!\n");
		//fprintf(fp,"[ljj] APTerminate:  buf_xvlie/APT_out/buf_huihua  ==  NULL  !!\n");
		return -1;
	}
	//ctx_APT = (sch_context *)kzalloc(sizeof(sch_context), GFP_KERNEL);
	ctx_APT = new sch_context();
	tcm_sch_starts(ctx_APT);
	tcm_sch_update(ctx_APT, APTerminate_part + 6, 4);
	tcm_sch_finish(ctx_APT, buf);

	//buf_xvlie[3] += 1;
	memcpy(buf + 32, buf_xvlie, 4);
	tcm_hmac(buf, 36, session_key, 32, inMac);
	memcpy(out_temp, APTerminate_part, 10);
	memcpy(out_temp + 10, buf_huihua, 4);
	memcpy(out_temp + 14, inMac, 32);
	printf( "APTerminate\n");
	//fprintf(fp,"APTerminate\n");
	memset(OutBuf, 0x00, 4096);
	nOutBufLen = 4096;
	tcmPrintf("In :", 46, out_temp);
	iret = Tddli_TransmitData(out_temp, 46, OutBuf, &nOutBufLen);
	tcmPrintf("Out :", nOutBufLen, OutBuf);
	memcpy(APT_out, OutBuf, nOutBufLen);
	//kfree(ctx_APT);
	delete ctx_APT;
	return 0;
}
#endif


uint32_t TCM_NV_WriteValue(unsigned char index, BYTE offset[]/*unsigned char *offset*/, BYTE *nvSize, unsigned char *buffer_Data)
{
	g_outBufferLength = MAX_BUFSIZE;
	memset(g_outBuffer, 0x00, MAX_BUFSIZE);
	int returnCode = 0;
	int ErrorFlag = 0; // =1 seq not ++ ,=0 ,seq++
	//BYTE buf1[32]={0x00};
	int iret, i;
	//unsigned char out_buf[82] = { 0 };
	unsigned char TCM_nonce[32] = { 0 };
	unsigned char AP_nonce[32] = { 0 };
	unsigned char session_key[32] = { 0 };
	//unsigned char buf_huihua[4] = { 0 };
	//unsigned char buf_xvlie[4] = { 0 };
	unsigned char inMac[32] = { 0 };
	sch_context ctx_nv_w;
	//APCreate
	//unsigned char AP3[16] = { 0x00,0xC1,0x00,0x00,0x00,0x50,0x00,0x00,0x80,0xBF,0x00,0x02,0x00,0x00,0x00,0x00 };
	BYTE WriteValue[4096] = {
		0x00,0xc2, 		//(tag: TCM_TAG_RQU_AUTH1_COMMAND)  
		0x00,0x00,0x00,0x5a, 	//(paramSize: 90)
		0x00,0x00,0x80,0xcd, 	//(ordinal: TCM_ORD_NV_WriteValue
		0x00,0x00,0x00,0x00, 	//(nvIndex: 1)           	        
		0x00,0x00,0x00,0x00,	//(offset: 0)  
		0x00,0x00,0x00,0x20,	//data size:32
		//data(apk pub_key   len = 32)
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,//(Session handle)
		//HMAC
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,//96
	};

	memcpy(WriteValue + 13, &index, 1);
	memcpy(WriteValue + 14, offset, 4);
	memcpy(WriteValue + 18, nvSize, 4);
	memcpy(WriteValue + 22, buffer_Data, Unpack32(nvSize));
	//memcpy(AP3 + 15, &index, 1);
	//memset(out_buf, 0, sizeof(out_buf));
	///////////////////////////APCreate Begin//////////////////////////////////
	BYTE entityType[2] = { 0x00 };
	Pack16(entityType, TCM_ET_OWNER);
	BYTE entityValue[4] = { 0x00 };
	BYTE hmac_Text[64] = { 0x00 };
	//APCreateIncallerNounce
	printf("GetRandom\n");
	g_outBufferLength = MAX_BUFSIZE;
	memset(g_outBuffer, 0x00, MAX_BUFSIZE);
	BYTE cmd_GetRandom[] = { 0x00,0xc1,0x00,0x00,0x00,0x0e,0x00,0x00,0x80,0x46,0x00,0x00,0x00,0x20 };
	tcmPrintf("In :", sizeof(cmd_GetRandom), cmd_GetRandom);

	Tddli_Open();
	iret = Tddli_TransmitData(cmd_GetRandom, sizeof(cmd_GetRandom), g_outBuffer, &g_outBufferLength);
	Tddli_Close();

	tcmPrintf("Out :", g_outBufferLength, g_outBuffer);
	Pack32(hmac_Text, TCM_ORD_APCreate);
	BYTE APCreateIncallerNounce[32] = { 0x00 };
	BYTE APCreateOutcallernNounce[32] = { 0x00 };
	memcpy(APCreateIncallerNounce, g_outBuffer + 14, 32);
	g_outBufferLength = MAX_BUFSIZE;
	memset(g_outBuffer, 0x00, MAX_BUFSIZE);
	returnCode = fu_TCM_APCreate(entityType, entityValue, APCreateIncallerNounce, g_OwnerAuthData);
	if (0 == returnCode)
	{
		//printf("APCreate Success\n");
	}
	else
	{
		printf("APCreate Failed\n");
		return returnCode;
	}
	//sessinHandle and Seq
	BYTE sessionHandle[4] = { 0x00 };
	BYTE seq_APCreateOut[4] = { 0x00 };
	memcpy(sessionHandle, g_outBuffer + 10, 4);
	memcpy(seq_APCreateOut, g_outBuffer + 14 + 32, 4);
	tcmPrintf_internalDebug("APCreate Handle:\n", 4, sessionHandle);
	tcmPrintf_internalDebug("APCreate Seq:\n", 4, seq_APCreateOut);
	////////////////////////APCreate  end//////////////////////////////////////////
	memcpy(APCreateOutcallernNounce, g_outBuffer + 14, 32);
	//session handle  4B
	tcmPrintf_internalDebug("APCreateIncallerNounce", 32, APCreateIncallerNounce);
	tcmPrintf_internalDebug("APCreateOutcallernNounce", 32, APCreateOutcallernNounce);
	//memcpy(out_buf, g_outBuffer, g_outBufferLength);
	///////////////////////////////////////////////////////////////////////////////
#if 0
	iret = fu_APCreate(AP3, out_buf, AP_nonce);
	if (0 != iret)
	{
		return -2;
	}
	if ( 0x00 ==Unpack32(out_buf+6) )
	{
		//temporarily save the TCM nonce in [inMac]
		memcpy(TCM_nonce, out_buf + 14, 32);
		//ÊÚÈš»á»°Ÿä±ú 4 B
		memcpy(buf_huihua, out_buf + 10, 4);
		memcpy(buf_xvlie, out_buf + 14 + 32, 4);
	}
	else 
	{
		printf("APCreate Error\n");
		return Unpack32(out_buf + 6);
	}
#endif 
	//session key
	//memset(buf1, 0, sizeof(buf1));
	BYTE hmac_key[32] = { 0x00 };
	memcpy(hmac_key, g_OwnerAuthData, 32);
	memcpy(hmac_Text, APCreateIncallerNounce, 32);
	memcpy(hmac_Text + 32, APCreateOutcallernNounce, 32);
	memset(session_key, 0, sizeof(session_key));
	tcmPrintf_internalDebug("hmac_text",64, hmac_Text);
	tcm_hmac(hmac_Text, 64, hmac_key, 32, session_key);
#ifdef DEBUG_PRINT
	printk("------------------    [nv-w]session   key   ----------------------\n");
	for (i = 0; i < 32; i++)
	{
		printk("0x%x ", session_key[i]);
	}
	printk("\n--------------    [nv-w]session   key  end  -----------------\n");
#endif
	//hash result
	//ctx_nv_w = (sch_context *)kzalloc(sizeof(sch_context), GFP_KERNEL);
	BYTE hash_Result[32] = { 0x00 };
	tcm_sch_starts(	&ctx_nv_w	);
	tcm_sch_update(	&ctx_nv_w, WriteValue + 6, 4	);	//cmd code: 0x00,0x00,0x80,0xce
	tcm_sch_update(	&ctx_nv_w, WriteValue + 10, 4	);	//index
	tcm_sch_update(	&ctx_nv_w, WriteValue + 14, 4	);	//offset
	tcm_sch_update(	&ctx_nv_w, WriteValue + 18, 4	);	//datasize
	tcm_sch_update(	&ctx_nv_w, WriteValue + 22, Unpack32(nvSize)	);	//data
	tcm_sch_finish(	&ctx_nv_w, hash_Result);
	tcmPrintf_internalDebug("hash_Result", 32, hash_Result);
	//HMAC
	memset(hmac_Text, 0x00, 64);	
	memcpy(hmac_Text, hash_Result, 32);
	memcpy(hmac_Text+32, seq_APCreateOut, 4);
	tcmPrintf_internalDebug("hmac_Text",36, hmac_Text);
	tcm_hmac(hmac_Text, 36, session_key, 32, inMac);	
	//NV_WriteValueAuth
	memcpy( WriteValue +22+Unpack32(nvSize), sessionHandle, 4);
	memcpy(WriteValue + 22+ Unpack32(nvSize)+4, inMac, 32);
	int cmdLength =54+4+ Unpack32(nvSize);
	Pack32(WriteValue + 2, cmdLength);
 
	tcmPrintf_internalDebug("WriteValueAuth\n", 4, WriteValue +2);
	//printf("cmdLength=%d\n", cmdLength);
	//printf("cmdLength=%d\n", Unpack32(nvSize));
	//fprintf(fp,"WriteValueAuth\n");
	memset( g_outBuffer, 0x00, MAX_BUFSIZE );
	g_outBufferLength = MAX_BUFSIZE;
	printf("*****************************************TCM_NV_WriteValue*****************************************\n");
	tcmPrintf("In :", cmdLength, WriteValue);

	Tddli_Open();
	iret = Tddli_TransmitData(WriteValue, cmdLength, g_outBuffer, &g_outBufferLength);
	Tddli_Close();
	tcmPrintf("Out :", g_outBufferLength, g_outBuffer);

	if ( Unpack32(g_outBuffer +6)==0 )
	{
		tcmPrintf_internalDebug("nvIndex:", 4, WriteValue + 10);
		tcmPrintf_internalDebug("offset:", 4, WriteValue + 14);
	}
	else 
	{
		ErrorFlag = 1;
		printf(" NV_WriteValueAuth Error\n");
	}
		//APTerminate

	if (0 == ErrorFlag)
	{
		int nSeq = 0;
		nSeq = Unpack32(seq_APCreateOut);
		nSeq++;
		memset(seq_APCreateOut, 0x00, 4);
		Pack32(seq_APCreateOut, nSeq);
	}
	g_outBufferLength = MAX_BUFSIZE;
	memset(g_outBuffer, 0x00, MAX_BUFSIZE);
	//fu_TCM_APTerminate(BYTE handle_APCreateOut[], BYTE entityAuth[], BYTE seq[], BYTE APCreateIncallerNounce[], BYTE callernounceAPCreateOut[])
	fu_TCM_APTerminate(sessionHandle, g_OwnerAuthData, seq_APCreateOut, APCreateIncallerNounce, APCreateOutcallernNounce,g_OwnerAuthData);

	if (Unpack32(g_outBuffer + 6) == 0)
	{
		//printf("APTerminate Success!\n");
	}
	else 
	{
		printf("APTerminate Error!\n");
		returnCode = Unpack32(g_outBuffer + 6);
	}
	//end APTerminate
	printf("NV WriteValue Success\n");
	if (1 == ErrorFlag)
	{
		return -1;
	}
#if 0
	if (ErrorFlag == 0 )
	{
		//buf_xvlie[3] += 1;
		//seq++		
		int nSeq = 0;
		nSeq = Unpack32(seq_APCreateOut);
		nSeq++;
		memset(seq_APCreateOut, 0x00, 4);
		Pack32(seq_APCreateOut, nSeq);
	}

	iret = fu_APTerminate(seq_APCreateOut, sessionHandle, out_buf, session_key);
	if (iret < 0)
	{
		//goto kfree_nv_2w;
		printf("[ljj][NV-W]  ***[3]. APTerminate *** ret err !\n");
		//fprintf(fp,"[ljj][NV-W]  ***[3]. APTerminate *** ret err !\n");
		delete ctx_nv_w;
		return iret;
	}
	if ( Unpack32(out_buf+6) == 0 )
	{

	}
	else
	{
		printf("[ljj][NV-W]  ***[3]. APTerminate *** ret err !\n");	
		//fprintf(fp,"9999[ljj][NV-W]  ***[3]. APTerminate *** ret err !\n");
		//goto kfree_nv_2w;
	}
#endif
	//intf("\n[ljj][NV-W]  NV-WriteValue success !! \n");
	if (1==ErrorFlag)
		return -1;

	return 0;

}


uint32_t TCM_NV_ReadValue(unsigned char index, BYTE offset[], BYTE *nvSize, unsigned char * buffer_Data)
{
	g_outBufferLength = MAX_BUFSIZE;
	memset(g_outBuffer, 0x00, MAX_BUFSIZE);
	int returnCode = 0;
	int ErrorFlag = 0; // =1 seq not ++ ,=0 ,seq++
	BYTE buf1[32]={0x00};
	int iret, i;
	//unsigned char out_buf[4096] = { 0 };
	unsigned char TCM_nonce[32] = { 0 };
	unsigned char AP_nonce[32] = { 0 };
	unsigned char session_key[32] = { 0 };
	BYTE  inMac[32] = { 0x00 };

	sch_context ctx_nv_r;
	//APCreate
	//unsigned char AP4[16] = { 0x00,0xC1, 0x00,0x00,0x00,0x50, 0x00,0x00,0x80,0xBF, 0x00,0x02, 0x00,0x00,0x00,0x00 };
	unsigned char ReadValueAuth[] = {
		0x00,0xc2, 		//(tag: TCM_TAG_RQU_AUTH1_COMMAND)  
		0x00,0x00,0x00,0x3a, 	//(paramSize: 90)				     
		//0x00,0x00,0x80,0xd0, 	//(ordinal: TCM_ORD_NV_ReadValueAuth	
		0x00,0x00,0x80,0xcf, 	//(ordinal: TCM_ORD_NV_ReadValue	
		0x00,0x00,0x00,0x00, 	//(nvIndex: 1)
		0x00,0x00,0x00,0x00,	//(offset: 0)
		0x00,0x00,0x00,0x20,	//data size:32
		0x00,0x00,0x00,0x00,//(Session handle)
		//  HMAC
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,//58
	};
	memcpy(ReadValueAuth + 13, &index, 1);
	memcpy(ReadValueAuth + 14, offset, 4);
	memcpy(ReadValueAuth + 18,nvSize,4);
	//memcpy(AP4 + 15, &index, 1);
	//memset(out_buf, 0, sizeof(out_buf));
	///////////////////////////APCreate Begin//////////////////////////////////
	BYTE entityType[2] = { 0x00 };
	Pack16(entityType, TCM_ET_OWNER);
	BYTE entityValue[4] = { 0x00 };
	BYTE hmac_Text[64] = { 0x00 };
	//APCreateIncallerNounce
	//printf("GetRandom\n");
	g_outBufferLength = MAX_BUFSIZE;
	memset(g_outBuffer, 0x00, MAX_BUFSIZE);
	BYTE cmd_GetRandom[] = { 0x00,0xc1,0x00,0x00,0x00,0x0e,0x00,0x00,0x80,0x46,0x00,0x00,0x00,0x20 };
	tcmPrintf("In :", sizeof(cmd_GetRandom), cmd_GetRandom);

	Tddli_Open();
	iret = Tddli_TransmitData(cmd_GetRandom, sizeof(cmd_GetRandom), g_outBuffer, &g_outBufferLength);
	Tddli_Close();

	tcmPrintf("Out :", g_outBufferLength, g_outBuffer);
	Pack32(hmac_Text, TCM_ORD_APCreate);
	BYTE APCreateIncallerNounce[32] = { 0x00 };
	BYTE APCreateOutcallernNounce[32] = { 0x00 };
	memcpy(APCreateIncallerNounce, g_outBuffer + 14, 32);
	g_outBufferLength = MAX_BUFSIZE;
	memset(g_outBuffer, 0x00, MAX_BUFSIZE);
	returnCode = fu_TCM_APCreate(entityType, entityValue, APCreateIncallerNounce, g_OwnerAuthData);
	if (0 == returnCode)
	{
		//printf("APCreate Success\n");
	}
	else
	{
		printf("APCreate Failed\n");
		return returnCode;
	}
	//sessinHandle and Seq
	BYTE sessionHandle[4] = { 0x00 };
	BYTE seq_APCreateOut[4] = { 0x00 };
	memcpy(sessionHandle, g_outBuffer + 10, 4);
	memcpy(seq_APCreateOut, g_outBuffer + 14 + 32, 4);
	tcmPrintf_internalDebug("APCreate Handle:\n", 4, sessionHandle);
	tcmPrintf_internalDebug("APCreate Seq:\n", 4, seq_APCreateOut);
	////////////////////////APCreate  end//////////////////////////////////////////
	memcpy(APCreateOutcallernNounce, g_outBuffer + 14, 32);
	//session handle  4B
	tcmPrintf_internalDebug("APCreateIncallerNounce", 32, APCreateIncallerNounce);
	tcmPrintf_internalDebug("APCreateOutcallernNounce", 32, APCreateOutcallernNounce);

#if 0
	iret = fu_APCreate(AP4, out_buf, AP_nonce);
	if (0 != iret)
	{
		return -2;
	}
	if ( 0x00 == Unpack32(out_buf+6) )
	{
		//temporarily save the TCM nonce in [inMac]
		memcpy(TCM_nonce, out_buf + 14, 32);
		//ÊÚÈš»á»°Ÿä±ú 4 B
		memcpy(buf_huihua, out_buf + 10, 4);
		memcpy(buf_xvlie, out_buf + 14 + 32, 4);
	}
	else {
		printf("APCreate Error\n");
		return -3;
	}
#endif
	BYTE hmac_text[64] = { 0x00 };
	BYTE hmac_key[32] = { 0x00};
	memcpy(hmac_text, APCreateIncallerNounce, 32);
	memcpy(hmac_text + 32, APCreateOutcallernNounce, 32);
	memcpy(hmac_key, g_OwnerAuthData, 32);
	tcm_hmac(hmac_text, 64, hmac_key, 32, session_key);
	//hash result
	BYTE hash_Result[32] = { 0x00 };
	tcm_sch_starts(&ctx_nv_r);
	tcm_sch_update(&ctx_nv_r, ReadValueAuth + 6, 4);	//cmd code: 0x00,0x00,0x80,0xd0
	tcm_sch_update(&ctx_nv_r, ReadValueAuth + 10, 4);	//index
	tcm_sch_update(&ctx_nv_r, ReadValueAuth + 14, 4);	//offset
	tcm_sch_update(&ctx_nv_r, ReadValueAuth + 18, 4);	//datasize
	tcm_sch_finish(&ctx_nv_r, hash_Result);

	//HMAC
	memset(hmac_text, 0x00, 64);
	memcpy(hmac_text, hash_Result, 32);
	memcpy(hmac_text + 32, seq_APCreateOut, 4);
	tcm_hmac(hmac_text, 36, session_key, 32, inMac);

	memcpy(ReadValueAuth + 22, sessionHandle, 4);
	memcpy(ReadValueAuth + 26, inMac, 32);
 
	//printf("ReadValueAuth\n");
 
	tcmPrintf("In :", sizeof(ReadValueAuth), ReadValueAuth);
	Tddli_Open();
	iret = Tddli_TransmitData(ReadValueAuth, sizeof(ReadValueAuth), g_outBuffer, &g_outBufferLength);
	Tddli_Close();
	tcmPrintf("Out :", g_outBufferLength, g_outBuffer);
 
	
	if ( 0x00 == Unpack32(g_outBuffer +6) )
	{
		int length = Unpack32(g_outBuffer + 10);
	
		memcpy(buffer_Data, g_outBuffer + 14, length);
		//printf ("---------------------------------------------------\n");
		tcmPrintf_internalDebug("ReadValueAuth nvIndex:", 4, ReadValueAuth + 10);
		tcmPrintf_internalDebug("ReadValueAuth offset:", 4, ReadValueAuth + 14);
		//printf("ReadDataLength:%d\n", length);
		//printf("---------------------------------------------------\n");
		tcmPrintf_internalDebug("ReadDataa:", length, buffer_Data);
	}
	else 
	{
		printf("NV  ReadValue Failed\n");
		ErrorFlag = 1;
	}

	//APTerminate

	if ( 0 == ErrorFlag )
	{
		int nSeq = 0;
		nSeq = Unpack32(seq_APCreateOut);
		nSeq++;
		memset(seq_APCreateOut, 0x00, 4);
		Pack32(seq_APCreateOut, nSeq);
	}
	g_outBufferLength = MAX_BUFSIZE;
	memset(g_outBuffer, 0x00, MAX_BUFSIZE);
	//fu_TCM_APTerminate(BYTE handle_APCreateOut[], BYTE entityAuth[], BYTE seq[], BYTE APCreateIncallerNounce[], BYTE callernounceAPCreateOut[])
	fu_TCM_APTerminate(sessionHandle, g_OwnerAuthData, seq_APCreateOut, APCreateIncallerNounce, APCreateOutcallernNounce,g_OwnerAuthData);
  
	if (Unpack32(g_outBuffer + 6) == 0)
	{
		//printf("APTerminate Success\n");
	}
	else
	{
		printf("APTerminate Error\n");
		//returnCode = Unpack32(g_outBuffer + 6);
	}
	//end APTerminate
	if (ErrorFlag == 1)
	{
		printf("NV ReadValueAuth Failed \n");
		return -1;
	}
	//printf("NV ReadValueAuth success\n");

	return 0;
}
