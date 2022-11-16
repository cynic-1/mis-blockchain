

#include "tcm.h"
#include "tcm_structures.h"
#include "tcmfunc.h"
#include "tcmalg.h"
#include "common.h"
#include "libtddl.h"
#include<time.h>

//#define random(x) (rand()%x)
//extern BYTE g_inBuffer[MAX_BUFSIZE];
extern BYTE g_outBuffer[MAX_BUFSIZE];
extern UINT32 g_outBufferLength;
 int g_iDisplayFlag;

BYTE g_OutBuffer_APCreate[82];

#define DEBUG_FU_INTERNAL 0
#define DEBUG_FU 0
void HelpInfo()
{
	printf("Init Owner and SMK Data	/init type(0 for 32 BYTE 0x00/1 for 32 BYTE 0x11/2 for 32 BYTE 0xFF)\n");
	//printf("Read Owner and SMK Data	/readinitdata\n");
	printf("TCM_Startup_Clear			/s\n");
	printf("TCM_PhysicalEnable			/e\n");
	printf("TCM_PhysicalDisable--------	/d\n");
	printf("TCM_PhysicalDeactivate(False)	/sa\n");
	printf("TCM_PhysicalDeactivate(True)------	/sa\n");
	printf("TCM_ForceClear				/f\n");
	printf("TCM_TakeOwnership			/t\n");
	printf("TCM_NVDefineSpace			/nvdef	/write nvIndex	nvSize for  TCM_NV_WriteValue\n");
	printf("TCM_NVWriteValue			/nvw	nvIndex	offset	nvsize \n");
	printf("TCM_NVReadValue				/nvr	nvIndex	offset	nvsize\n");

}

//#define DEBUG_FU_INTERNAL
void tcmPrintf_internalDebug(char *title, int iLength, BYTE *a)
{
#if DEBUG_FU_INTERNAL
	printf("%s\n", title);
	for (int i = 0; i<iLength; i++)
	{
		printf("%02X ", a[i]);
		if ((i + 1) % 32 == 0)
			printf("\n");
	}
	printf("\n");
#endif 
}
 
void tcmPrintf(char *title,int iLength,BYTE *a)
{
	//printf("length=%d\n", iLength);
	if (g_iDisplayFlag == 0)
	{
#if DEBUG_FU
		printf("%s\n", title);
		for (int i = 0; i < iLength; i++)
		{
			printf("%02X ", a[i]);
			if ((i + 1) % 32 == 0)
				printf("\n");
		}
		printf("\n");
#endif 
	}
}

void Pack32(BYTE* dst, int val)
{
	dst[0] = (BYTE)((val >> 24) & 0xff);
	dst[1] = (BYTE)((val >> 16) & 0xff);
	dst[2] = (BYTE)((val >> 8) & 0xff);
	dst[3] = (BYTE)(val & 0xff);
}
 

UINT32 Unpack32(BYTE* src)
{
	return(((UINT32) src[0]) << 24
		| ((UINT32) src[1]) << 16
		| ((UINT32) src[2]) << 8
		| (UINT32) src[3]);
}

void Pack16(BYTE* dst, int val)
{
	dst[0] = (BYTE)((val >> 8) & 0xff);
	dst[1] = (BYTE)(val & 0xff);
}

/*
int Unpack16(const BYTE* src)
{
	return (((UINT32) src[0]) << 8 | (UINT32) src[1]);
}
*/


int fu_TCM_APCreate(BYTE entityType[],BYTE entityValue[],BYTE callerNonce[],BYTE entityAuth[] )
{ 
	TSM_RESULT ret;
	g_outBufferLength = MAX_BUFSIZE;
	memset(g_outBuffer, 0x00, MAX_BUFSIZE);

	BYTE inBuffer_AP_Create[80]={0x00};
	memset( inBuffer_AP_Create,0x00,sizeof(inBuffer_AP_Create));
	//Tag
	BYTE Tag[]={0x00,0xC1};
	memcpy(inBuffer_AP_Create,Tag,2);

	//size=80
	BYTE size[]={0x00,0x00,0x00,0x50};
	memcpy(inBuffer_AP_Create+2,size,4);

	//commandcode
	BYTE cmdAPCreate[]={0x00,0x00,0x80,0xBF};
	memcpy(inBuffer_AP_Create+2+4,cmdAPCreate,4);

	//entity Type,2B
	memcpy(inBuffer_AP_Create+2+4+4,entityType,2);

	//entityValue,4B
	memcpy(inBuffer_AP_Create+2+4+4+2,entityValue,4);
	
	//callernonce
	memcpy(inBuffer_AP_Create+2+4+4+2+4,callerNonce,32);

	//inMac
	BYTE buf[36]={0x00};	
	memcpy(buf,cmdAPCreate,32);
	memcpy(buf+4,callerNonce,32);	 
	BYTE inMac[32]={0x00};
	memset(inMac,0x00,32);
	tcmPrintf_internalDebug("hmac inBuffer",32,buf);
	tcmPrintf_internalDebug("hmac entityAuth",32,entityAuth);
	tcm_hmac(buf, 36, entityAuth, 32, inMac);
	tcmPrintf_internalDebug("inMac",32,inMac);
	memcpy(inBuffer_AP_Create+2+4+4+2+4+32,inMac,32);
	//printf("------------------APCreate-----------------------\n");
	tcmPrintf_internalDebug("In",sizeof(inBuffer_AP_Create),inBuffer_AP_Create);

	Tddli_Open();
	ret = Tddli_TransmitData( inBuffer_AP_Create,sizeof(inBuffer_AP_Create), g_outBuffer,&g_outBufferLength);	
	Tddli_Close();

	//printf("return Code =%d\n",ret);
	tcmPrintf_internalDebug("Out", g_outBufferLength, g_outBuffer); 
	if( Unpack32(g_outBuffer +6)==0)
	{
		//printf("APCreate Success\n");
	}
	else
	{
		//printf("APCreate failed\n");
		//printf("Error Code=%d,%s\n",Unpack32(g_outBuffer +6),itcm_status_to_str(Unpack32(g_outBuffer +6)));
		return Unpack32(g_outBuffer +6);
	}	
	return  Unpack32(g_outBuffer +6);
}

int fu_TCM_APTerminate(BYTE handle_APCreateOut[],BYTE entityAuth[],BYTE seq[],BYTE APCreateIncallerNounce[],BYTE callernounceAPCreateOut[],BYTE hmac_key[] )
{
	g_outBufferLength = MAX_BUFSIZE;
	memset(g_outBuffer, 0x00, MAX_BUFSIZE);
	TSM_RESULT ret;
	//AP_Terminate
	//printf("**************AP_Terminate *************\n");
	BYTE inBuf_Terminate[46]={ 0x00 };
	BYTE Tag_Terminate[]={0x00,0xC2};
	memcpy(inBuf_Terminate,Tag_Terminate,2);
	BYTE Size_Terminate[]={0x00,0x00,0x00,0x2e};
	memcpy(inBuf_Terminate+2,Size_Terminate,4);
	BYTE CommandCode_Terminate[]={0x00,0x00,0x80,0xC0};
	memcpy(inBuf_Terminate+6,CommandCode_Terminate,4);
	BYTE Handle_Termiante[4]={0x00,0x00,0x00,0x00};
	memcpy(Handle_Termiante,handle_APCreateOut,4);
	memcpy(inBuf_Terminate+10,Handle_Termiante,4);
	tcmPrintf_internalDebug("Handle_Termiante",4,Handle_Termiante);
	//Hmac 32
	//cmd -hash  
	sch_context m_context_Terminate; //=new sch_context();  //sch_context
	BYTE hashTerminate[32]={0x00};
	tcm_sch_starts(&m_context_Terminate); 
	//commandCode 
	tcm_sch_update(&m_context_Terminate,CommandCode_Terminate,4);
	tcm_sch_finish(&m_context_Terminate,hashTerminate);
	tcmPrintf_internalDebug("Terminate HashResult",21,hashTerminate);
	BYTE b1[36]={0x00}; 
	memcpy( b1,hashTerminate,32 ); 
	tcmPrintf_internalDebug("seq",4,seq);
	memcpy(b1+32,seq,4);
	BYTE inMac[32]={0x00};
	BYTE buf3[64];
	BYTE sessionKey1[64];
	memcpy(buf3,APCreateIncallerNounce,32);
	memcpy(buf3+32,callernounceAPCreateOut,32);
	tcm_hmac(buf3, 64, hmac_key, 32, sessionKey1);
	tcm_hmac(b1, 36, sessionKey1, 32, inMac);
	tcmPrintf_internalDebug("Terminate HMAC",32,inMac);
	//printf("Terminate HMAC:\n");
	memcpy(inBuf_Terminate+14,inMac,32); 
	tcmPrintf_internalDebug("In:",46,inBuf_Terminate);
 
	Tddli_Open();
	ret = Tddli_TransmitData(inBuf_Terminate,46, g_outBuffer,&g_outBufferLength);
	Tddli_Close();
 
	tcmPrintf_internalDebug("Out:", g_outBufferLength, g_outBuffer);
	if( Unpack32(g_outBuffer +6)==0)
	{
		//printf("Command Terminate Success\n");
	}
	else
	{
		printf("Command Terminate Failed\n");
		//printf("Error Code=%d,%s\n",Unpack32(g_outBuffer +6),itcm_status_to_str(Unpack32(g_outBuffer +6)));
		return Unpack32(g_outBuffer +6);
	}
	return Unpack32(g_outBuffer +6);
}
 
 
/*
const char* itcm_status_to_str(int status)
{
	static char strbuf[256];
	const char* str = "Unknown error";
	switch (status)
	{
	case TCM_SUCCESS: str = "Success"; break;
	case TCM_AUTHFAIL: str = "Authorization failed"; break;
	case TCM_BADINDEX: str = "Bad index"; break;
	case TCM_BAD_PARAMETER: str = "Bad parameter"; break;
	case TCM_AUDITFAILURE: str = "Audit failure"; break;
	case TCM_CLEAR_DISABLED: str = "Clear disabled"; break;
	case TCM_DEACTIVATED: str = "Deactivated"; break;
	case TCM_DISABLED: str = "Disabled"; break;
	case TCM_DISABLED_CMD: str = "Disabled command"; break;
	case TCM_FAIL: str = "Fail"; break;
	case TCM_BAD_ORDINAL: str = "Bad ordinal"; break;
	case TCM_INSTALL_DISABLED: str = "Install disabled"; break;
	case TCM_INVALID_KEYHANDLE: str = "Invalid key handle"; break;
	case TCM_KEYNOTFOUND: str = "Key not found"; break;
	case TCM_INAPPROPRIATE_ENC: str = "Inappropriate encoding"; break;
	case TCM_MIGRATEFAIL: str = "Migration failed"; break;
	case TCM_INVALID_PCR_INFO: str = "Invalid PCR info"; break;
	case TCM_NOSPACE: str = "No space"; break;
	case TCM_NOSMK: str = "No SMK"; break;
	case TCM_NOTSEALED_BLOB: str = "Not sealed blob"; break;
	case TCM_OWNER_SET: str = "Owner set"; break;
	case TCM_RESOURCES: str = "Resources"; break;
	case TCM_SHORTRANDOM: str = "Short random"; break;
	case TCM_SIZE: str = "Size"; break;
	case TCM_WRONGPCRVAL: str = "Wrong PCR value"; break;
	case TCM_BAD_PARAM_SIZE: str = "Bad parameter size"; break;
	case TCM_SCH_THREAD: str = "SCH thread"; break;
	case TCM_SCH_ERROR: str = "SCH error"; break;
	case TCM_FAILEDSELFTEST: str = "Failed self test"; break;
	case TCM_AUTH2FAIL: str = "Authorization #2 failed"; break;
	case TCM_BADTAG: str = "Bad tag"; break;
	case TCM_IOERROR: str = "I/O error"; break;
	case TCM_ENCRYPT_ERROR: str = "Encrypt error"; break;
	case TCM_DECRYPT_ERROR: str = "Decrypt error"; break;
	case TCM_INVALID_AUTHHANDLE:
		str = "Invalid authorization handle"; break;
	case TCM_NO_ENDORSEMENT: str = "No endorsement"; break;
	case TCM_INVALID_KEYUSAGE: str = "Invalid key usage"; break;
	case TCM_WRONG_ENTITYTYPE: str = "Wrong entity type"; break;
	case TCM_INVALID_POSTINIT: str = "Invalid POST initialization"; break;
	case TCM_INAPPROPRIATE_SIG: str = "Inappropriate signature"; break;
	case TCM_BAD_KEY_PROPERTY: str = "Bad key properties"; break;
	case TCM_BAD_MIGRATION: str = "Bad migration properties"; break;
	case TCM_BAD_SCHEME: str = "Bad signature/encryption scheme"; break;
	case TCM_BAD_DATASIZE: str = "Bad data/blob size"; break;
	case TCM_BAD_MODE: str = "Bad mode parameter"; break;
	case TCM_BAD_PRESENCE: str = "Bad presence state"; break;
	case TCM_BAD_VERSION: str = "Bad capability version"; break;
	case TCM_RETRY: str = "Retry"; break;
		// TCM 1.2 additions
	case TCM_NO_WRAP_TRANSPORT: str = "No wrap transport"; break;
	case TCM_AUDITFAIL_UNSUCCESSFUL:
		str = "Audit fail unsuccessful"; break;
	case TCM_AUDITFAIL_SUCCESSFUL: str = "Audit fail successful"; break;
	case TCM_NOTRESETABLE: str = "Not resetable"; break;
	case TCM_NOTLOCAL: str = "Not local"; break;
	case TCM_BAD_TYPE: str = "Bad type"; break;
	case TCM_INVALID_RESOURCE: str = "Invalid resource"; break;
	case TCM_NOTFIPS: str = "Not FIPS"; break;
	case TCM_INVALID_FAMILY: str = "Invalid family"; break;
	case TCM_NO_NV_PERMISSION: str = "No NV permission"; break;
	case TCM_REQUIRES_SIGN: str = "Requires signature"; break;
	case TCM_KEY_NOTSUPPORTED: str = "Key not supported"; break;
	case TCM_AUTH_CONFLICT: str = "Auth conflict"; break;
	case TCM_AREA_LOCKED: str = "Area locked"; break;
	case TCM_BAD_LOCALITY: str = "Bad locality"; break;
	case TCM_READ_ONLY: str = "Read-only"; break;
	case TCM_PER_NOWRITE: str = "PER no write"; break;
	case TCM_FAMILYCOUNT: str = "Bad family count"; break;
	case TCM_WRITE_LOCKED: str = "Write locked"; break;
	case TCM_BAD_ATTRIBUTES: str = "Bad attributes"; break;
	case TCM_INVALID_STRUCTURE: str = "Invalid structure"; break;
	case TCM_KEY_OWNER_CONTROL: str = "Key owner control"; break;
	case TCM_BAD_COUNTER: str = "Bad counter"; break;
	case TCM_NOT_FULLWRITE: str = "Not full write"; break;
	case TCM_CONTEXT_GAP: str = "Context gap"; break;
	case TCM_MAXNVWRITES: str = "Maximum NV writes"; break;
	case TCM_NOOPERATOR: str = "No operator"; break;
	case TCM_RESOURCEMISSING: str = "Resource missing"; break;
	case TCM_DELEGATE_LOCK: str = "Delegate locked"; break;
	case TCM_DELEGATE_FAMILY: str = "Delegate family invalid"; break;
	case TCM_DELEGATE_ADMIN: str = "Delegation admin disabled"; break;
	case TCM_TRANS_EXCLUSIVE: str = "Transport exclusive"; break;
	case TCM_OWNER_CONTROL: str = "Owner control"; break;
	case TCM_DAA_RESOURCES: str = "DAA resource"; break;
	case TCM_DAA_INPUT_DATA0: str = "DAA data#0 invalid"; break;
	case TCM_DAA_INPUT_DATA1: str = "DAA data#1 invalid"; break;
	case TCM_DAA_ISSUER_SETTINGS:
		str = "DAA issuer settings invalid"; break;
	case TCM_DAA_TCM_SETTINGS:
		str = "DAA TCM settings invalid"; break;
	case TCM_DAA_STAGE: str = "DAA stage invalid"; break;
	case TCM_DAA_ISSUER_VALIDITY: str = "DAA issuer invalid"; break;
	case TCM_DAA_WRONG_W: str = "DAA wrong W"; break;
	case TCM_BAD_HANDLE: str = "Bad Handle"; break;						
	case TCM_NOCONTEXTSPACE: str = "No Context Space"; break;			
	case TCM_BADCONTEXT: str = "Bad Context"; break;					
	case TCM_TOOMANYCONTEXTS: str = "Too Many Contexts"; break;			
	case TCM_MA_TICKET_SIGNATURE: str = "MA Ticket Signature"; break;	
	case TCM_MA_DESTINATION: str = "MA Destination"; break;				
	case TCM_MA_SOURCE: str = "MA Source"; break;
    case TCM_BEGIN : str = "Let's Begin";break;
	case TCM_PERMANENTEK: str = "TCM_PERMANENTEK"; break;
	default:
		//sprintf(strbuf, "Unknown error (0x%x)", status);
		str = strbuf;
		break;
	}
	return str;
}
*/

//-------------------------------------------------------------------
void GenerateSmkAuthPlain(int value)
{
	TCM_AUTHDATA smkAuthPlain;
	uint8_t j;
	//for (int i = 0; i<TCM_DIGEST_SIZE; i++)
	//	smkAuthPlain[i] = rand();
	{
		switch (value)
		{
		case 0:
			for (int i = 0; i < TCM_DIGEST_SIZE; i++)
			{
				smkAuthPlain[i] = 0x11;
			}
			break;
		case 1:
			for (int i = 0; i < TCM_DIGEST_SIZE; i++)
			{
				smkAuthPlain[i] = 0x22;
			}
			break;
		case 2:
			for (int i = 0; i < TCM_DIGEST_SIZE; i++)
			{
				smkAuthPlain[i] = 0xee;
			}
			break;
		//case 3:
		//	for (int i = 0; i < TCM_DIGEST_SIZE; i++)
		//	{
		//		smkAuthPlain[i] = rand();
		//	}
		defalut:
			
			break;
		}
	}

	FILE *fp;
	fp = fopen("smkAuthPlain.log", "wb");

	for (j = 0; j<TCM_DIGEST_SIZE; j++)
		fprintf(fp, "%c", smkAuthPlain[j]);

	fclose(fp);
}
//-------------------------------------------------------------------
/*
int  GetSmkAuthPlain(TCM_AUTHDATA &smkAuthPlain)

{
	FILE *fp;

	fp = fopen("smkAuthPlain.log", "rb");

	if (fp == NULL)

		return -1;

	for (TCM_BYTE i = 0; i<TCM_DIGEST_SIZE; i++)

		fscanf(fp, "%c", &smkAuthPlain[i]);

	fclose(fp);

	return 0;
}
*/
//-------------------------------------------------------------------
void GenerateOwnerAuthPlain(int value)
{
	TCM_AUTHDATA ownerAuthPlain;
	uint8_t j=0;
	//for (int i = 0; i < TCM_DIGEST_SIZE; i++)
	{
		switch (value) 
		{
		case 0:
			for (int i = 0; i < TCM_DIGEST_SIZE; i++)
			{
				ownerAuthPlain[i] = 0x00;
			}			
			break;
		case 1:
			for (int i = 0; i < TCM_DIGEST_SIZE; i++)
			{
				ownerAuthPlain[i] = 0x11;
			}
			break;
		case 2:
			for (int i = 0; i < TCM_DIGEST_SIZE; i++)
			{
				ownerAuthPlain[i] = 0xFF;
			}
			break;

		//case 3:
		//	for (int i = 0; i < TCM_DIGEST_SIZE; i++)
		//	{
		//		ownerAuthPlain[i] = rand();
		//	}
		//	break;

		defalut:			
			break;
		} 
	}
		

	FILE *fp;
	fp = fopen("OwnerAuthPlain.log", "wb");
	for (j = 0; j<TCM_DIGEST_SIZE; j++)
		fprintf(fp, "%c", ownerAuthPlain[j]);
	fclose(fp);

}
//-------------------------------------------------------------------
/*
int GetOwnerAuthPlain(TCM_AUTHDATA &ownerAuthPlain)
{

	FILE *fp;
	fp = fopen("OwnerAuthPlain.log", "rb");
	if (fp == NULL)
		return -1;
	for (TCM_BYTE i = 0; i<TCM_DIGEST_SIZE; i++)
		fscanf(fp, "%c", &ownerAuthPlain[i]);
	fclose(fp);
	return 0;

}
*/

 
 
