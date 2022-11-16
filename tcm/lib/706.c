#include <stdio.h>
#include <stdlib.h>
#include <string.h>
//#include <sys/time.h>
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
#include "tcm_marshalling.h"

int Tspi_Init(uint8_t mode)
{
    uint32_t ret=0;
    uint8_t auth[32] = {0};
    uint8_t pubEK[65] = {0};
    TCM_PUBKEY key;
    key.pubKey.key = pubEK;
    ret = TCM_Startup();
    if(ret != 0) return ret;

	//liu.daqiu add
	ret = TCM_PhysicalEnable();
    if(ret != 0) return ret;
    ret = TCM_PhysicalSetDeactivated(FALSE);
    if(ret != 0) return ret;

    ret = TCM_ReadPubek(&key);
    if(ret == 0) {
    switch (mode){
        case 1:  // First time to use
        ret = TCM_TakeOwnership(&(key.pubKey),auth,auth);
    	if(ret != 0 ) return ret;
        break;
        case 2:  //TCM_OWNER_SET; Owner had been set
        ret = TCM_TakeOwnership(&(key.pubKey),auth,auth);
    	if(ret == 0x00000014 ) return 0;  
        break;
        default:
        ret = TCM_ForceClear();
        break;
        }
    }
    else if(ret == 8) return 0;
    else return ret;
}

int Tspi_AddUser(char *user_name,uint32_t name_len,uint32_t pin_type, uint8_t *pin,uint32_t pin_len)
{
    uint32_t ret=0;
    unsigned char index = 0x01;  //All users in this NV
	  BYTE nvSize[4] = {0x00,0x00,0x03,0x20};
	  BYTE offset[4] = {0x00,0x00,0x00,0x00};
    unsigned char data[800] = { 0 };;
    BYTE attribute[4]= {0x00,0x02,0x00,0x02};   //attribute = TCM_NV_PER_OWNERWRITE | TCM_NV_PER_OWNER_READ;  // Have owner, owner auth

    uint32_t count;
    TCM_ALL_USERS allUser;

    memset(&allUser,0,sizeof(TCM_ALL_USERS));
    if(pin_len>32) return -1;
    /*uint32_t TCM_NV_ReadValue(unsigned char index, BYTE offset[], BYTE *nvSize, unsigned char * buffer_Data) */
    ret = TCM_NV_ReadValue(index,offset,nvSize,data);
    if(ret !=0 )
    {
        /* uint32_t TCM_NV_DefineSpace(unsigned char index,BYTE nvSize[],BYTE attribute[]); */ 
        ret = TCM_NV_DefineSpace(index,nvSize,attribute);
        if(ret != 0 ) return ret;
        count = 0x00000001;
    }
    else 
    {
        memcpy(&allUser,data,sizeof(TCM_ALL_USERS));
        count = allUser.count;
   }

 		if(count > USERS_MAX-1) return -11;   //Error : No Space
    allUser.count++;
    if(count > 0) allUser.user[count].index = allUser.user[count-1].index+1;
    else allUser.user[count].index = 1;
	  memcpy(allUser.user[count].user_name,user_name,name_len);
    allUser.user[count].name_len = name_len;
    allUser.user[count].pin_type = pin_type;
    memcpy(allUser.user[count].pin,pin,pin_len);
    allUser.user[count].pin_len = pin_len;

    /* uint32_t TCM_NV_WriteValue(unsigned char index, BYTE offset[], BYTE *nvSize, unsigned char *buffer_Data) */ 
    ret = TCM_NV_WriteValue(index,offset,nvSize,(unsigned char *)&allUser);   

    return ret;
}

int Tspi_DelPin(char *user_name,uint32_t name_len,uint8_t *pin,uint32_t pinlen)
{
    uint32_t ret=0;
    unsigned char index = 0x01;  //All users in this NV
	  BYTE nvSize[4] = {0x00,0x00,0x03,0x20};
	  BYTE offset[4] = {0x00,0x00,0x00,0x00};
    unsigned char data[800] = { 0 };;
    BYTE attribute[4]= {0x00,0x02,0x00,0x02};
    TCM_ALL_USERS allUser;
    uint32_t i=0;

    memset(&allUser,0,sizeof(TCM_ALL_USERS));
    if(pinlen>32) return -1;
    /*uint32_t TCM_NV_ReadValue(unsigned char index, BYTE offset[], BYTE *nvSize, unsigned char * buffer_Data) */
    ret = TCM_NV_ReadValue(index,offset,nvSize,data);
    if(ret !=0 ) return ret;

    memcpy(&allUser,data,sizeof(TCM_ALL_USERS));
		printf(" \n###### Tspi_DelPin %d count ###### \n",allUser.count);
    for(i=0;i++,i<allUser.count;)
    {
        if( (memcmp(user_name,allUser.user[i].user_name,name_len) == 0) 
         && (memcmp(pin,allUser.user[i].pin,pinlen) == 0) )
        {
            memset(data,0,800);
            allUser.count--;
            memcpy(data,&allUser,4+64*i);
            if(allUser.count-i>2) {
                memcpy(data,&allUser+4+64*(i+1),64*(allUser.count-i-1));
            }
            ret = TCM_NV_WriteValue(index,offset,nvSize,data);
            if(ret !=0 ) return ret;
        }
    }
    return ret;
}

int Tspi_ModifyPin(char *user_name,uint32_t name_len,uint8_t *old_pin,uint32_t old_len,uint8_t * *new_pin,uint32_t new_len)
{
    uint32_t ret=0;
    unsigned char index = 0x01;  //All users in this NV
	  BYTE nvSize[4] = {0x00,0x00,0x03,0x20};
	  BYTE offset[4] = {0x00,0x00,0x00,0x00};
    unsigned char data[800] = { 0 };;
    BYTE attribute[4]= {0x00,0x02,0x00,0x02};
    TCM_ALL_USERS allUser;
    uint32_t i=0;

    memset(&allUser,0,sizeof(TCM_ALL_USERS));
    if(new_len>32) return -1;
    /*uint32_t TCM_NV_ReadValue(unsigned char index, BYTE offset[], BYTE *nvSize, unsigned char * buffer_Data) */
    ret = TCM_NV_ReadValue(index,offset,nvSize,data);
    if(ret !=0 ) return ret;

    memcpy(&allUser,data,sizeof(TCM_ALL_USERS));
    for(i=0;i++,i<allUser.count;)
    {
        if( (memcmp(user_name,allUser.user[i].user_name,name_len) == 0)
          && (memcmp(old_pin,allUser.user[i].pin,old_len) == 0) )
        {
            memcpy(allUser.user[i].pin,new_pin,new_len);
            allUser.user[i].pin_len = new_len;
            ret = TCM_NV_WriteValue(index,offset,nvSize,(unsigned char *)&allUser);
            if(ret !=0 ) return ret;
        }
    }
    return ret;
}

int Tspi_Login(char *user_name,uint32_t name_len,uint8_t *pin,uint32_t pin_len)
{
    uint32_t ret=0;
    unsigned char index = 0x01;  //All users in this NV
    BYTE nvSize[4] = {0x00,0x00,0x03,0x20};
    BYTE offset[4] = {0x00,0x00,0x00,0x00};
    unsigned char data[800] = { 0 };;
    BYTE attribute[4]= {0x00,0x02,0x00,0x02};
    TCM_ALL_USERS allUser;
    uint32_t i=0;

    memset(&allUser,0,sizeof(TCM_ALL_USERS));
    if(pin_len>32) return -1;
    /*uint32_t TCM_NV_ReadValue(unsigned char index, BYTE offset[], BYTE *nvSize, unsigned char * buffer_Data) */
    ret = TCM_NV_ReadValue(index,offset,nvSize,data);
    if(ret !=0 ) return ret;

    memcpy(&allUser,data,sizeof(TCM_ALL_USERS));
    for(i=0;i++,i<allUser.count;)
    {
        if( (memcmp(user_name,allUser.user[i].user_name,name_len) == 0)
          && (memcmp(pin,allUser.user[i].pin,pin_len) == 0) )
        {
            return 0;
        }
    }
    return -1;

}


int Tspi_GetRandom(UINT32 len,BYTE *data)
{
    //Call hardware(TCM) get random data
    return TCM_GetRandom(len,data);
 }

int Tspi_Hash (uint8_t *in_data,uint32_t indata_len,uint8_t *out_data,uint32_t out_datalen)
{
/*
    //Use software HASH(SM3) algrithm firstly
    //Later change to hardware HASH(SM3)
    out_datalen = 32;
    return tcm_sch_hash(indata_len,in_data,out_data);
*/
    //Call Hardware(TCM) HASH(SM3) algrithm 
    uint32_t ret=0;
    uint32_t i = 0;
    uint32_t updateMax = 0;
    ret = TCM_SCHStart(&updateMax);
    if(ret!=0) return ret;
    if(indata_len < updateMax) { //MAX Hash legth =1024
        ret = TCM_SCHUpdate(in_data,indata_len);
        if(ret!=0) return ret;
        out_datalen = 32;
        ret = TCM_SCHComplete(in_data,indata_len,out_data);
        if(ret!=0) return ret;
   }
    else {
        for(i=0;i<(indata_len/updateMax);i++)
	{
            ret = TCM_SCHUpdate(in_data+updateMax*i,updateMax);
            if(ret!=0) return ret;
	}
        ret = TCM_SCHUpdate(in_data+updateMax*i,indata_len-updateMax*i);
        if(ret!=0) return ret;
        out_datalen = 32;
        ret = TCM_SCHComplete(in_data+updateMax*i,indata_len-updateMax*i,out_data);
        if(ret!=0) return ret;
    }
    return 0;
}

int Tspi_CreateAsymmKey(uint32_t *key_index)
{
    /*Call hardware(TCM) to generate SM2 Key, stored in TCM; Return the index. */
    uint32_t ret=0;
	unsigned char auth[32] = {0};
	//SM2 Key
	TCM_KEY outKey;
	unsigned char keyblob[700]={0};
	unsigned int bloblen = 0;
	TCM_KEY keyinfo;
	TCM_KEY_PARMS algorithmParms;

    unsigned char nvIdx = 0x05;
    BYTE nvSize[4] = {0x00,0x00,0x03,0x20};
    BYTE offset[4] = {0x00,0x00,0x00,0x00};
    unsigned char data[800] = { 0 };;
    BYTE attribute[4]= {0x00,0x02,0x00,0x02};
	uint32_t count;
	TCM_STORED_KEY stdKey;

   	//Prepare data:keyinfo
	algorithmParms.algorithmID = 0x0000000B; //TCM_ALG_ECC;
	algorithmParms.sigScheme = 0x0005; //TCM_SS_ECCSIGN_SCH; 
	algorithmParms.encScheme = 0x0004; //TCM_ES_NONE;  
	algorithmParms.parms.ecc.keyLength = 0x00000100; //SM2 256 bit
	algorithmParms.parmSize = 4;
	TCM_STORE_PUBKEY pubkey;
	pubkey.key = NULL;
	pubkey.keyLength = 0;
	keyinfo.tag=0x0015;  //TCM_TAG_KEY;
	keyinfo.fill=0x0000;
	keyinfo.keyUsage = 0x0010;  //TCM_ECCKEY_SIGNING; // For Sign,  must be TCM_ECCKEY_SIGNING
	keyinfo.keyFlags = 0x00000004;
	keyinfo.authDataUsage = 0x00;  //TCM_AUTH_NEVER; 
	keyinfo.algorithmParms = algorithmParms;
	keyinfo.PCRInfoSize = 0;
	keyinfo.PCRInfo = NULL;
	keyinfo.pubKey = pubkey;
	keyinfo.encData = NULL;
	keyinfo.encDataSize = 0;	
	/*int32_t TCM_CreateWrapKey(uint32_t keyhandle,
						   unsigned char *parauth,
						   unsigned char *newauth,
						   unsigned char *migauth,
						   TCM_KEY *keyparms,
						   TCM_KEY *key,
						   unsigned char *keyblob,
						   unsigned int  *bloblen)   
	*/ 
	ret = TCM_CreateWrapKey(TCM_KH_SMK,auth,auth,auth,&keyinfo,&outKey,keyblob,&bloblen);
	if(ret != 0 ) return ret;
	
    //Test
    uint32_t keyHandle=0;
    ret = TCM_LoadKey(TCM_KH_SMK,auth,&outKey,&keyHandle);
    //
    ret = TCM_NV_ReadValue(nvIdx,offset,nvSize,data);
 	memset(&stdKey,0,sizeof(TCM_STORED_KEY));
   	if(ret !=0 ) {
        ret = TCM_NV_DefineSpace(nvIdx,nvSize,attribute);
        if(ret != 0 ) return ret;
		stdKey.count = 1;
		stdKey.index = nvIdx;
		stdKey.keyLength = bloblen;
		memcpy(stdKey.keyBlob,keyblob,bloblen);
		*key_index = nvIdx;
		ret = TCM_NV_WriteValue(nvIdx,offset,nvSize,(unsigned char*)&stdKey);
		if(ret != 0 ) return ret;
		return 0;
	} else {
		memcpy(&stdKey,data,sizeof(TCM_STORED_KEY));
		count = stdKey.count;
		//printf("\n ############## Tspi_CreateAsymmKey Key Count = %d \n",count);
		*key_index = nvIdx + count;
		//printf("\n ############## Tspi_CreateAsymmKey Key *key_index = %d \n",*key_index);
        ret = TCM_NV_DefineSpace((unsigned char)(*key_index),nvSize,attribute);
        if(ret != 0 ) return ret;
		stdKey.count = count + 1;
		stdKey.index = *key_index;
		stdKey.keyLength = bloblen;
		memcpy(stdKey.keyBlob,keyblob,bloblen);
		ret = TCM_NV_WriteValue(*key_index,offset,nvSize,&stdKey);
		if(ret != 0 ) return ret;
		nvSize[3] = 0; nvSize[4]=1;
		count ++;
		ret = TCM_NV_WriteValue(nvIdx,offset,nvSize,(unsigned char*)&count);
		if(ret != 0 ) return ret;
	}
	return ret;	
}

int Tspi_Signature(uint8_t *sign_data,uint32_t sign_len,uint8_t *sign_value,uint32_t *value_len,uint32_t prikey_index)
{
    uint32_t ret=0;
	unsigned char auth[32] = {0};

    BYTE nvSize[4] = {0x00,0x00,0x03,0x20};
    BYTE offset[4] = {0x00,0x00,0x00,0x00};
    unsigned char data[800] = { 0 };;
    BYTE attribute[4]= {0x00,0x02,0x00,0x02};
	uint32_t count;
	TCM_STORED_KEY stdKey;

	uint32_t keyHandle=0;
	TCM_KEY key;

	ret = TCM_NV_ReadValue((unsigned char)prikey_index,offset,nvSize,data);
	if(ret != 0 ) return ret;
	
	memcpy(&stdKey,data,sizeof(TCM_STORED_KEY));
	//memcpy(&key,stdKey.keyBlob,stdKey.keyLength);

	unsigned int templen = stdKey.keyLength;
	BYTE *ptr = (BYTE *)malloc(templen);
	memcpy(ptr, stdKey.keyBlob , templen);
	if (tcm_unmarshal_TCM_KEY(&ptr, &templen, &key)) 
	{
		printf("\n ############## tcm_unmarshal_TCM_KEY Error \n");
		return -1;
	}
	stdKey.keyLength = templen;

	ret = TCM_LoadKey(TCM_KH_SMK,auth,&key,&keyHandle);
	if(ret != 0 ) return ret;

	/*Call hardware(TCM) to sign(SM2) data, the interface is: 
	uint32_t TCM_Sign(uint32_t keyhandle, unsigned char *keyauth,
			 unsigned char *data, uint32_t datalen, 
			 unsigned char *sig, uint32_t *siglen)
	Note: The data to be signed should be Hashed firstly. datalen = 32
	keyauth use WELLKNOWN = 0x00 (32)
	prikey_index use keyhandle
	*/
	ret = TCM_Sign(keyHandle,auth,sign_data,sign_len,sign_value,value_len);
	//printf("\n ############## value_len = %d \n",value_len);
	if(ret != 0 ) return ret;

	uint32_t resourcetype = TCM_RT_KEY;
    	ret = TCM_FlushSpecific(keyHandle, resourcetype);
	if(ret != 0 ) return ret;
	return 0;
}

int Tspi_ECC_Verification(uint8_t *sign_data,uint32_t sign_len,uint8_t *sign_value,uint32_t value_len,uint32_t pubkey_index)
{
    uint32_t ret=0;
	unsigned char auth[32] = {0};

    BYTE nvSize[4] = {0x00,0x00,0x03,0x20};
    BYTE offset[4] = {0x00,0x00,0x00,0x00};
    unsigned char data[800] = { 0 };;
    BYTE attribute[4]= {0x00,0x02,0x00,0x02};
	uint32_t count;
	TCM_STORED_KEY stdKey;

	uint32_t keyHandle=0;
	TCM_KEY key;
	TCM_PUBKEY pubkey;
	unsigned char verifyReuslt;

	//byj add time test
    //struct timeval start, end;
    //gettimeofday(&start, NULL);
	ret = TCM_NV_ReadValue((unsigned char)pubkey_index,offset,nvSize,data);
	if(ret != 0 ) return ret;
    //gettimeofday(&end, NULL);
    //printf("\033[31;43mTCM_NV_ReadValue: %ld \033[0m\n", (end.tv_sec - start.tv_sec) * 1000000 + end.tv_usec - start.tv_usec);
	
	memcpy(&stdKey,data,sizeof(TCM_STORED_KEY));
	unsigned int templen = stdKey.keyLength;
	BYTE *ptr = (BYTE *)malloc(templen);
	memcpy(ptr, stdKey.keyBlob , templen);
	if (tcm_unmarshal_TCM_KEY(&ptr, &templen, &key)) 
	{
		//printf("\n ############## tcm_unmarshal_TCM_KEY Error \n");
		return -1;
	}
	stdKey.keyLength = templen;
    //gettimeofday(&start, NULL);
	ret = TCM_LoadKey(TCM_KH_SMK,auth,&key,&keyHandle);
    //gettimeofday(&end, NULL);
    //printf("\033[31;43mTCM_LoadKey: %ld \033[0m\n", (end.tv_sec - start.tv_sec) * 1000000 + end.tv_usec - start.tv_usec);
	if(ret != 0 ) return ret;

	/*Call software to verify SM2 signed data, the interface is:
	uint32_t TCM_Verify(TCM_PUBKEY *key,
			unsigned char *signedData, uint32_t signedDataSize,
			unsigned char *signatureValue, uint32_t signatureValueSize,
			unsigned char *ownerAuth, 
			unsigned char *verifyResult)
	*/

	//Get the PubKey by pubkey_index
    //gettimeofday(&start, NULL);
	ret = TCM_GetPubKey(keyHandle,auth,&pubkey);
    //gettimeofday(&end, NULL);
    //printf("\033[31;43mTCM_GetPubKey: %ld \033[0m\n", (end.tv_sec - start.tv_sec) * 1000000 + end.tv_usec - start.tv_usec);
	if(ret != 0 ) return ret;

	uint32_t resourcetype = TCM_RT_KEY;
    //gettimeofday(&start, NULL);
	ret = TCM_FlushSpecific(keyHandle, resourcetype);
    //gettimeofday(&end, NULL);
    //printf("\033[31;43mTCM_FlushSpecific: %ld \033[0m\n", (end.tv_sec - start.tv_sec) * 1000000 + end.tv_usec - start.tv_usec);
	if(ret != 0 ) return ret;
	//ret = TCM_Verify(&pubkey,sign_data,sign_len,sign_value,value_len,auth,verifyReuslt);
    //gettimeofday(&start, NULL);
	ret = tcm_ecc_init();
    //gettimeofday(&end, NULL);
    //printf("\033[31;43mtcm_ecc_init: %ld \033[0m\n", (end.tv_sec - start.tv_sec) * 1000000 + end.tv_usec - start.tv_usec);
	if(ret != 0 ) return ret;
    //gettimeofday(&start, NULL);
	ret = tcm_ecc_verify(sign_data,sign_len,sign_value,value_len,pubkey.pubKey.key,pubkey.pubKey.keyLength);
    //gettimeofday(&end, NULL);
    //printf("\033[31;43mtcm_ecc_verify: %ld \033[0m\n", (end.tv_sec - start.tv_sec) * 1000000 + end.tv_usec - start.tv_usec);
	//printf("\n ############## tcm_ecc_verify result = %d \n",ret);
	if(ret != 0 ) return ret;
    //gettimeofday(&start, NULL);
	ret = tcm_ecc_release();
	if(ret != 0 ) return ret;
    //gettimeofday(&end, NULL);
    //printf("\033[31;43mtcm_ecc_release: %ld \033[0m\n", (end.tv_sec - start.tv_sec) * 1000000 + end.tv_usec - start.tv_usec);
	return ret;
}

/*
key nv design:
header: 4 Bytes Index_Num
key: 4 bytes keyindex + 16 Bytes key
keyindex: start from 0x80000001

eg1: 2 key index
00 00 00 02
80 00 00 01 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10
80 00 00 02 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F 20

eg2: 3 key index, delete key 80000002
00 00 00 03
80 00 00 01 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10
80 00 00 02 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F 20
80 00 00 03 21 22 23 24 25 26 27 28 29 2A 2B 2C 2D 2E 2F 30

...

00 00 00 02
80 00 00 01 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10
80 00 00 03 21 22 23 24 25 26 27 28 29 2A 2B 2C 2D 2E 2F 30
*/
int Tspi_CreateSymmKey(uint32_t *key_index)
{
#if 0
    //before getrandom,first send TCM_Startup, TCM_PhysicalEnable, TCM_PhysicalSetDeactivated
    ret = TCM_PhysicalEnable();
    if(ret != 0)
        return ret;
    ret = TCM_PhysicalSetDeactivated(FALSE);
    if(ret != 0)
        return ret;
#endif
	int ret = 0;
	unsigned char nvindex = 0x02;
	BYTE nvsize[4] = {0x00,0x00,0x03,0x20};
	BYTE offset[4] = {0x00,0x00,0x00,0x00};
	uint8_t nvattribute[4] = { 0x00 };
	uint8_t nvbuff[800] = { 0 };
	uint8_t randomdata[16];
	uint32_t index_num = 0;

	ret = TCM_GetRandom(16, randomdata);
	if(ret != 0 ) return ret;

	ret = TCM_NV_ReadValue(nvindex, offset, nvsize, nvbuff);
	if(ret != 0 )
	{
		Pack32(nvattribute, TCM_NV_PER_OWNER_READ | TCM_NV_PER_OWNERWRITE);
		ret = TCM_NV_DefineSpace(nvindex, nvsize, nvattribute);
		if(ret != 0 ) return ret;
		//*key_index = 0x80000001;//set initial key index 0x80000001
		//index_num = 0;
	}

	index_num = Unpack32(&nvbuff[0]);
//printf("LDQ_DEBUG__indexnum = %d\r\n", index_num);
	//NV size = 800, set max_index = 30
	if(index_num > 30)
		return -1;//too many key index
	if(index_num > 0)
		*key_index = Unpack32(&nvbuff[(index_num - 1) * 20 + 4]) + 1;
	else 
		*key_index = 0x80000001;//set initial key index 0x80000001
	//update index_num, add new key 
	Value2Array(&nvbuff[0], index_num + 1, 4);
	Value2Array(&nvbuff[index_num * 20 + 4], *key_index, 4);
	memcpy(&nvbuff[index_num * 20 + 4 + 4], randomdata, 16);

	ret = TCM_NV_WriteValue(nvindex, offset, nvsize, nvbuff);
    if(ret != 0 ) return ret;
	return ret;
}

int Tspi_ExportKey(uint32_t *key_index, uint8_t *key)
{
	int ret = 0;
	uint32_t nvindex = 0x02;
	uint8_t nvsize[4] = {0x00,0x00,0x03,0x20};
	BYTE offset[4] = {0x00,0x00,0x00,0x00};
	uint8_t nvbuff[800] = { 0 };
	uint32_t index_num;
	ret = TCM_NV_ReadValue(nvindex, offset, nvsize, nvbuff);
	if(ret != 0 ) return ret;
	index_num = Unpack32(&nvbuff[0]);
	if(index_num < 1)
		return -1;//no key to export
	for(int i = 0; i < index_num; i++)
	{
		if(Unpack32(&nvbuff[i * 20 + 4]) == *key_index)
		{
			memcpy(key, &nvbuff[i * 20 + 4 + 4], 16);
			return 0;
		}
	}
	return -2;//not find keyindex
}

int Tspi_DestroyKey(uint32_t *key_index)
{
	int ret = 0;
	uint32_t nvindex = 0x02;
	uint8_t nvsize[4] = {0x00,0x00,0x03,0x20};
	BYTE offset[4] = {0x00,0x00,0x00,0x00};
	uint8_t nvbuff[800] = { 0 };
	uint32_t index_num;
	ret = TCM_NV_ReadValue(nvindex, offset, nvsize, nvbuff);
	if(ret != 0 ) return ret;
	index_num = Unpack32(&nvbuff[0]);
	if(index_num < 1)
		return -1;//no key to destroy
	for(int i = 0; i < index_num; i++)
	{
		if(Unpack32(&nvbuff[i * 20 + 4]) == *key_index)
		{
			//copy remaind key to deleted key destination
			memcpy(&nvbuff[i * 20 + 4], &nvbuff[(i + 1) * 20 + 4 ], Unpack32(&nvsize[0]) - (i * 20 + 4));
			Value2Array(&nvbuff[0], index_num - 1, 4);//index_num reduce 1
			ret = TCM_NV_WriteValue(nvindex, offset, nvsize, nvbuff);
			return ret;
		}
	}
	return -2;//not find keyindex
}

int Tspi_GetPcrValue (UINT32 PcrIndex,BYTE *PcrValue)
{
	int ret = 0;
	uint8_t pcrreadvalue[TCM_HASH_SIZE] = {0};
	memcpy(pcrreadvalue, PcrValue, TCM_HASH_SIZE);
  ret = TCM_PcrRead(PcrIndex, pcrreadvalue);
	if(ret != 0 ) return ret;
 	memcpy(PcrValue, pcrreadvalue, TCM_HASH_SIZE);	
	return ret;
}

int Tspi_SetPcrValue (UINT32 PcrIndex,BYTE *PcrValue)
{
	int ret = 0;
	uint8_t pcrsetvalue[TCM_HASH_SIZE] = {0};
	memcpy(pcrsetvalue, PcrValue, TCM_HASH_SIZE);
	ret = TCM_PcrExtend(PcrIndex, pcrsetvalue);
	if(ret != 0 ) return ret;
 	memcpy(PcrValue, pcrsetvalue, TCM_HASH_SIZE);	
	return ret;
}

int Tspi_DelPcrValue (UINT32 PcrIndex)
{
	return TCM_PcrReset(PcrIndex);
}

/*
uint32_t Unpack32(uint8_t * src)
{
	return (((UINT32)src[0]) << 24
		| ((UINT32)src[1]) << 16
		| ((UINT32)src[2]) << 8
		| (UINT32)src[3]);
}
*/
void Value2Array(char *dest, unsigned int src, int size)
{
	if (size == 4)
	{
		*dest++ = (src >> 24) & 0xFF;
		*dest++ = (src >> 16) & 0xFF;
		*dest++ = (src >> 8) & 0xFF;
		*dest = (src) & 0xFF;
	}
	else if (size == 2)
	{
		*dest++ = (src >> 8) & 0xFF;
		*dest = (src) & 0xFF;
	}
	return;
}
/*
void Pack32(BYTE* dst, int val)
{
	dst[0] = (BYTE)((val >> 24) & 0xff);
	dst[1] = (BYTE)((val >> 16) & 0xff);
	dst[2] = (BYTE)((val >> 8) & 0xff);
	dst[3] = (BYTE)(val & 0xff);
}
*/

//byj add
int Tspi_GetPubkey(uint32_t pubkey_index, uint8_t *pubkey, uint32_t *pubkeyLen)
{
    uint32_t ret=0;
	unsigned char auth[32] = {0};

    BYTE nvSize[4] = {0x00,0x00,0x03,0x20};
    BYTE offset[4] = {0x00,0x00,0x00,0x00};
    unsigned char data[800] = { 0 };;
    BYTE attribute[4]= {0x00,0x02,0x00,0x02};
	uint32_t count;
	TCM_STORED_KEY stdKey;

	uint32_t keyHandle=0;
	TCM_KEY key;
	TCM_PUBKEY tcm_pubkey;

	ret = TCM_NV_ReadValue((unsigned char)pubkey_index,offset,nvSize,data);
	if(ret != 0 ) return ret;

	memcpy(&stdKey,data,sizeof(TCM_STORED_KEY));
	unsigned int templen = stdKey.keyLength;
	BYTE *ptr = (BYTE *)malloc(templen);
	memcpy(ptr, stdKey.keyBlob , templen);
	if (tcm_unmarshal_TCM_KEY(&ptr, &templen, &key))
	{
		//printf("\n ############## tcm_unmarshal_TCM_KEY Error \n");
		return -1;
	}
	stdKey.keyLength = templen;
	ret = TCM_LoadKey(TCM_KH_SMK,auth,&key,&keyHandle);
	if(ret != 0 ) return ret;

	//Get the PubKey by pubkey_index
	ret = TCM_GetPubKey(keyHandle,auth,&tcm_pubkey);
	if(ret != 0 ) return ret;

	uint32_t resourcetype = TCM_RT_KEY;
	ret = TCM_FlushSpecific(keyHandle, resourcetype);
	if(ret != 0 ) return ret;

	memcpy(pubkey,tcm_pubkey.pubKey.key,tcm_pubkey.pubKey.keyLength);
	*pubkeyLen = tcm_pubkey.pubKey.keyLength;
	return ret;
}

int Tspi_Verify(uint8_t *sign_data,uint32_t sign_len,uint8_t *sign_value,uint32_t value_len,uint8_t *pubkey,uint32_t pubkeyLen)
{
    uint32_t ret=0;
	ret = tcm_ecc_init();
	if(ret != 0 ) return ret;

	ret = tcm_ecc_verify(sign_data,sign_len,sign_value,value_len,pubkey,pubkeyLen);
	if(ret != 0 ) return ret;

	ret = tcm_ecc_release();
	if(ret != 0 ) return ret;

	return ret;
}
