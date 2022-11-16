#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#ifdef TCM_POSIX
#include <netinet/in.h>
#endif
#ifdef TCM_WINDOWS
#include <winsock2.h>
#endif
#include "tcm.h"
#include "tcmutil.h"
#include <tcmfunc.h>

static void printUsage()
{
    printf("TCMGetcapability:\n");
}

int main(int argc, char *argv[])
{
	int ret;
	int i;
   	uint32_t key_index,key_index1;
	uint8_t pin[6] = {0,1,2,3,4,5};
	struct timeval start, end;
	long sign[5], verify[5];


	TCM_setlog(0);      /* turn off verbose output */
//	for (i=1 ; i<argc ; i++) {
//	    if (strcmp(argv[i],"-v") == 0) {
//		TCM_setlog(1);
//	    }
//	    else if (strcmp(argv[i],"-h") == 0) {
//		printUsage();
//		exit(2);
//	    }
//	    else {
//		printf("\n%s is not a valid option\n",argv[i]);
//		printUsage();
//		exit(2);
//	    }
//	}
/*
    TCM_Startup();
    uint32_t type = TCM_CAP_VERSION;
    uint32_t subtype_len = 0;
    uint8_t * subtype = NULL;
	ret = TCM_GetCapability(type, subtype_len, subtype);
	if (0 != ret) {
		printf("TCMGetcapability returned '%s' (%d).\n",
		       TCM_GetErrMsg(ret),
		       ret);
	}
*/

	TCM_ForceClear();
	// Test 706 interface
	ret = Tspi_Init(2);
	if(ret != 0) return ret;

/**********************************************************
/*
/*				LDQ_DEBUG Tspi_CreateSymmKey
/*				LDQ_DEBUG Tspi_ExportKey
/*				LDQ_DEBUG Tspi_DestroyKey
/*				LDQ_DEBUG Tspi_GetPcrValue
/*				LDQ_DEBUG Tspi_SetPcrValue
/*				LDQ_DEBUG Tspi_DelPcrValue
/*
**********************************************************/
//test Tspi_CreateSymmKey
#if 0
	ret = Tspi_CreateSymmKey(&key_index);
	if(ret != 0) return ret;
	ret = Tspi_CreateSymmKey(&key_index1);
	if(ret != 0) return ret;
	printf("LDQ_DEBUG__indexnum = 0x%8.8X\r\n", key_index);
	printf("LDQ_DEBUG__indexnum = 0x%8.8X\r\n", key_index1);
#endif

//test Tspi_ExportKey
#if 0
	uint8_t *key = {NULL};
	key = (uint8_t *)malloc(16);

	key_index = 0x80000001;
	ret = Tspi_ExportKey(&key_index, key);
	printf("LDQ_DEBUG__ret  = %d\r\n", ret);
	if(ret != 0) return ret;
	printf("LDQ_DEBUG__indexnum = 0x%8.8X\r\n", key_index);
	for(int i = 0; i < 16; i++)
	{
		printf("LDQ_DEBUG__key[%d]  = %2.2X\r\n", i, key[i]);
	}
	free(key);
#endif

//test Tspi_DestroyKey
#if 0
	key_index = 0x80000002;
	ret = Tspi_DestroyKey(&key_index);
	printf("LDQ_DEBUG__ret  = %d\r\n", ret);
	if(ret != 0) return ret;	
#endif

//test Tspi_GetPcrValue
#if 0
	uint8_t *pcrvalue = {NULL};
	pcrvalue = (uint8_t *)malloc(32);
	ret = Tspi_GetPcrValue(16, pcrvalue);
	printf("LDQ_DEBUG__ret  = %d\r\n", ret);
	if(ret != 0) return ret;	
	for(int i = 0; i < 32; i++)
	{
		printf("LDQ_DEBUG__PCR[%d]  = %2.2X\r\n", i, pcrvalue[i]);
	}
#endif

//test Tspi_SetPcrValue
#if 0
	uint8_t pcrsetvalue[32] = {
		0,1,2,3,4,5,6,7,8,9,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
		0,1,2,3,4,5,6,7,8,9,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
	ret = Tspi_SetPcrValue(16, pcrsetvalue);
	printf("LDQ_DEBUG__ret  = %d\r\n", ret);
	if(ret != 0) return ret;	
	for(int i = 0; i < 32; i++)
	{
		printf("LDQ_DEBUG__PCRout[%d]  = %2.2X\r\n", i, pcrsetvalue[i]);
	}
#endif

//test Tspi_DelPcrValue
#if 0
	ret = Tspi_DelPcrValue(16);
	printf("LDQ_DEBUG__ret  = %d\r\n", ret);
	if(ret != 0) return ret;	
#endif


/*****************************************************************/

/**************************************************
//User Test
	char name[4] = {8,8,8,8};
	ret = Tspi_AddUser(name,4,1,pin,6);
	if(ret != 0) return ret;

  	ret = Tspi_DelPin(name,4,pin,6);
  	if(ret != 0) return ret;

	uint8_t newpin[8] = {0x8,0x7,0x6,0x5,0x4,0x3,0x2,0x1};
	ret = Tspi_ModifyPin(name,4,pin,6,newpin,8);
  	if(ret != 0) return ret;

  	ret = Tspi_Login(name,4,newpin,8);
	printf( "\n############## Tspi_Login Result = %d \n",ret);
  if(ret != 0) return ret;

******************************************************/

/**************************************************/
//Crypto Interface Test
//	BYTE ranData[32];
	//ret = Tspi_GetRandom(32,ranData);
//	if(ret != 0) return ret;

	
//	uint8_t in[6] = {0x0,0x1,0x2,0x3,0x4,0x5};
//	uint8_t out[32];
	//ret = Tspi_Hash(in,6,out,32);
//	if(ret != 0) return ret;

	uint32_t asyIdx=5;
	Tspi_CreateAsymmKey(&asyIdx);
	printf("\n ############## Tspi_CreateAsymmKey Return Index = %d \n",asyIdx);
	if(ret != 0) return ret;
	
	uint8_t signdata[32] = 
	{0x5,0x5,0x5,0x5,0x5,0x5,0x5,0x5,
	 0x5,0x5,0x5,0x5,0x5,0x5,0x5,0x5,
	0x5,0x5,0x5,0x5,0x5,0x5,0x5,0x5,
	0x5,0x5,0x5,0x5,0x5,0x5,0x5,0x5,};
	uint8_t signvalue[400]={0};
	uint32_t signlen=0;
//	for (int i = 0; i < 5; i++) {
//		for (int j = 0; j < 400; j++)
//			signvalue[j] = 0;
		gettimeofday(&start, NULL);
		ret = Tspi_Signature(signdata, 32, signvalue, &signlen, asyIdx);
		if (ret != 0) return ret;
		gettimeofday(&end, NULL);
//	}

    //ecc_verify test
//    for (int i = 0; i < 5; i++) {
        gettimeofday(&start, NULL);
        ret = Tspi_ECC_Verification(signdata, 32, signvalue, 64, asyIdx); //signvalue lenght = 64;
        printf("\n ############## Tspi_ECC_Verification result = %d \n", ret);
        if (ret != 0) return ret;
        gettimeofday(&end, NULL);
//    }
/******************************************************/
	return ret;
}
