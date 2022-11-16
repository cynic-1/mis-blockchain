
#include "tcm.h"
#include "tcmalg.h"
#include <stdio.h>
#pragma once
#define MAX_BUFSIZE	2048  //4096
#define TAG 193
#define AUTHTAG  194
 
#define TCM_WELL_KNOWN_SECRET \
        {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
         0x00, 0x00 }


#define TCM_WELL_KNOWN_SECRET_NEW \
        {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, \
         0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, \
         0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, \
         0x00, 0x11 }
#if 0
typedef struct TCM_KEY
{
	TCM_STRUCTURE_TAG tag;
	TCM_UINT16 fill;
	TCM_KEY_USAGE keyUsage;
	TCM_KEY_FLAGS keyFlags;
	TCM_AUTH_DATA_USAGE authDataUsage;
	TCM_KEY_PARMS algorithmParms;
	TCM_UINT32 PCRInfoSize;
	TCM_BYTE* PCRInfo;
	TCM_STORE_PUBKEY pubKey;
	TCM_UINT32 encSize;
	TCM_BYTE* encData;
};
#endif



#define TCM_DIGEST_SIZE 32
typedef uint32_t TSM_RESULT;

extern BYTE g_OwnerAuthData[32];
extern BYTE g_smkAuthData[32];
//extern BYTE g_OutBuffer_APCreate[82];


void tcmPrintf(char *title,int iLength,BYTE *a);
void tcmPrintf_internalDebug(char *title, int iLength, BYTE *a);
void HelpInfo();
void Pack32(BYTE* dst, int val);
UINT32 Unpack32(BYTE* src);
void Pack16(BYTE* dst,int val);
//UINT16 Unpack16(BYTE * src );

 
int fu_TCM_APCreate(BYTE entityType[],BYTE entityValue[],BYTE callerNonce[],BYTE entityAuth[] );
int fu_TCM_APTerminate(BYTE handle_APCreateOut[],BYTE entityAuth[],BYTE seq[],BYTE APCreateIncallerNounce[],BYTE callernounceAPCreateOut[],BYTE hmac_key[]);


//const char* itcm_status_to_str(int status);

void GenerateSmkAuthPlain(int value);
//int  GetSmkAuthPlain(TCM_AUTHDATA &smkAuthPlain);
//void GenerateOwnerAuthPlain(int value);
//int GetOwnerAuthPlain(TCM_AUTHDATA &ownerAuthPlain);

 
 
