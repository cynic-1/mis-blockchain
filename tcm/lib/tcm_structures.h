#ifndef _TCM_STRUCTURES_H_
#define _TCM_STRUCTURES_H_

#include <stdint.h>

//#include "tpm/tpm_emulator.h"
//#include "crypto/rsa.h"
//#include "tcm_emulator.h"
//#include "tpm/tpm_structures.h"

/*
 * Basic Data Types 
 */
#ifndef BYTE
#define BYTE uint8_t
#endif
typedef uint8_t  BYTE;
typedef unsigned char TCM_BOOL;
typedef uint16_t UINT16;

#ifndef UINT32
#define UINT32 uint32_t
#endif
//typedef uint32_t UINT32;
//typedef uint64_t UINT64;

#ifndef UINT64
#define UINT64 uint64_t
#endif

#ifndef BOOL
#define BOOL BYTE
#endif
//typedef BYTE     BOOL;

#define TRUE     0x01
#define FALSE    0x00

/*
 * New
 */
#define TCM_NONCE_SIZE                 32
#define TCM_HASH_SIZE                  32
#define TCM_AUTHDATA_SIZE              32

#define TCM_U16_SIZE                   2
#define TCM_U32_SIZE                   4

//#define TCM_PARAMSIZE_OFFSET           TCM_U16_SIZE
#define TCM_RETURN_OFFSET              ( TCM_U16_SIZE + TCM_U32_SIZE )
#define TCM_DATA_OFFSET                ( TCM_RETURN_OFFSET + TCM_U32_SIZE )

/*
 * TCM Helper Data Types 
 */
typedef BYTE	TCM_AUTH_DATA_USAGE;
typedef BYTE	TCM_PAYLOAD_TYPE;
typedef BYTE	TCM_ENTITY_TYPE;
typedef UINT16	TCM_TAG;
typedef UINT16	TCM_STRUCTURE_TAG;
typedef UINT16	TCM_KEY_USAGE;
typedef UINT16	TCM_ENC_SCHEME;
typedef UINT16	TCM_SIG_SCHEME;
typedef UINT32	TCM_COMMAND_CODE;
typedef UINT32	TCM_RESULT;
typedef UINT32	TCM_AUTHHANDLE;
typedef UINT32	TCM_KEY_HANDLE;
typedef UINT32	TCM_HANDLE;
typedef UINT32	TCM_KEY_FLAGS;
typedef UINT32	TCM_ALGORITHM_ID;
typedef UINT32	TCM_PCRINDEX;

/*
 * Structure Tags 
 * are defined together with the dedicated structures.
 */

/*
 * TCM_AUTH_DATA_USAGE
 */	
#define TCM_AUTH_NEVER					0x00	//����Ҫ��Ȩ���ݵ�ʵ��ʹ�÷�ʽ
#define TCM_AUTH_ALWAYS					0x01	//����ʹ����Ȩ���ݵ�ʵ��ʹ�÷�ʽ
#define TCM_AUTH_PRIV_USE_ONLY			0x03	//��˽�����ݱ�����Ȩ���ݵ�ʵ��ʹ�÷�ʽ

/*
 * TCM_PAYLOAD_TYPE 
 * This specifies the type of payload in various messages.
 */
#define TCM_PT_SYM						0x00	//�Գ���Կ����
#define TCM_PT_ASYM						0x01	//�ǶԳ���Կ����
#define TCM_PT_BIND						0x02	//������������
#define TCM_PT_SEAL						0x05	//��װ��������
#define TCM_PT_SYM_MIGRATE				0x08	//�Գ�Ǩ������
#define TCM_PT_ASYM_MIGRATE				0x09	//�ǶԳ�Ǩ������
		/* 0x10 - 0xFF ����*/

/*
 * TCM_ENTITY_TYPE 
 * This specifies the types of entity and ADIP encryption schemes
 * that are supported by the TCM.
 */
#define TCM_ET_KEYHANDLE				0x01	//��Կ���
#define TCM_ET_OWNER					0x02	//0x40000001	TCM������
#define TCM_ET_DATA						0x03	//����
#define TCM_ET_SMK						0x04	//0x40000000	SMK 
#define TCM_ET_KEY						0x05	//��Կ
#define TCM_ET_REVOKE					0x06	//0x40000002	�ɳ�����Կ
#define TCM_ET_KEYXOR					0x10	//��������㷨������Ȩ����Կ
#define TCM_ET_KEYSMS4					0x11	//����SMS4�ԳƼӽ��ܵ���Կ (�Գ���Կ)
#define TCM_ET_NONE						0x12	//��ȨЭ����ʵ�崴��
#define TCM_ET_AUTHDATA_ID				0x13	//��Ȩ���ݱ�ʶ
#define TCM_ET_AUTHDATA					0x14	//��Ȩ����

/*
 * TCM_SESSION_TYPE
 */
#define TCM_ST_INVALID					0x00	//��Ч�Ự
#define TCM_ST_AP						0x01	//AP�Ự

/*
 * TCM_TAG,Command Tags
 * Indicate the construction of the command either as input or as output.
 */
#define TCM_TAG_RQU_COMMAND				0x00C1	//û����Ȩ������
#define TCM_TAG_RQU_AUTH1_COMMAND		0x00C2	//��Ҫһ����Ȩ������
#define TCM_TAG_RQU_AUTH2_COMMAND		0x00C3	//��Ҫ������Ȩ������
#define TCM_TAG_RSP_COMMAND				0x00C4	//û����Ȩ�������
#define TCM_TAG_RSP_AUTH1_COMMAND		0x00C5	//��Ҫһ����Ȩ�������
#define TCM_TAG_RSP_AUTH2_COMMAND		0x00C6	//��Ҫ������Ȩ�������

/*
 * TCM_STRUCTURE_TAG
 */
#define TCM_TAG_PERMANENT_DATA			0x0022	//TCM_PERMANENT_DATA
#define TCM_TAG_STANY_DATA				0x0024	//TCM_STANY_DATA
#define TCM_TAG_SIGNINFO				0x0005	//TCM_SIGN_INFO
#define TCM_TAG_PCR_INFO				0x0006	//TCM_PCR_INFO
#define TCM_TAG_STORED_DATA				0x0016	//TCM_STORED_DATA
#define TCM_TAG_KEY						0x0015	//TCM_KEY
#define TCM_TAG_QUOTE_INFO				0x0036	//TCM_QUOTE_INFO

/*
 * TCM_KEY_USAGE
 */
#define TCM_ECCKEY_SIGNING				0x0010	//����ECC�㷨��ǩ����Կ
#define TCM_ECCKEY_STORAGE				0x0011	//����ECC�㷨�Ĵ洢��Կ
#define TCM_ECCKEY_IDENTITY				0x0012	//������Կ
#define TCM_ECCKEY_BIND					0x0014	//����ECC�㷨�ļ�����Կ
#define TCM_ECCKEY_MIGRATE				0x0016	//����ECC�㷨����Ǩ�Ƶ���Կ
#define TCM_ECCKEY_PEK					0x0017	//����ECC�㷨���ɵ�PEK��Կ
#define TCM_SMS4KEY_STORAGE				0x0018	//����SMS4�㷨�Ĵ洢��Կ
#define TCM_SMS4KEY_BIND				0x0019	//����SMS4�㷨�ļ�����Կ
#define TCM_SMS4KEY_MIGRATE				0x001A	//����SMS4�㷨����Ǩ�Ƶ���Կ

/*
 * TCM_ENC_SCHEME
 */
#define TCM_ES_ECC						0x0006	//ECC���ܱ���
#define TCM_ES_ECCNONE					0x0004	//�������ڼ���
#define TCM_ES_SMS4_CBC					0x0008	//SMS4�Գ�CBC����
#define TCM_ES_SMS4_ECB					0x000A	//SMS4�Գ�ECB����

/*
 * TCM_SIG_SCHEME
 */
    // TCM_SIG_SCHEME signature schemes

#define TCM_SS_ECCNONE					0x0001	//��������ǩ��
#define TCM_SS_ECC						0x0005	//����ǩ��

// TCM_NV_ATTRIBUTES values 
#define TCM_NV_PER_READ_STCLEAR  (1UL << 31)
#define TCM_NV_PER_AUTH_READ	 (1UL << 18)
#define TCM_NV_PER_OWNER_READ    (1UL << 17)
#define TCM_NV_PER_PPREAD		 (1UL << 16)
#define TCM_NV_PER_GLOBALLOCK    (1UL << 15)
#define TCM_NV_PER_WRITE_STCLEAR (1UL << 14)
#define TCM_NV_PER_WRITEDEFINE   (1UL << 13)
#define TCM_NV_PER_WRITEALL      (1UL << 12)
#define TCM_NV_PER_AUTHWRITE     (1UL << 2) 
#define TCM_NV_PER_OWNERWRITE    (1UL << 1) 
#define TCM_NV_PER_PPWRITE       (1UL << 0) 
#define TCM_NV_INDEX_LOCK		 0xFFFFFFFF 

/*
 * TCM_COMMAND_CODE     Ordinals
 * The command ordinals provide the index value for each command.
 * TCM_COMMAND_CODE=TCM_PROTECTED_ORDINAL+���ж���ı��
 */
#define TCM_PROTECTED_ORDINAL			0x00008000
#define TCM_ORD_APCreate				0x000080BF	//191	//0x000000BF
#define TCM_ORD_APTerminate				0x000080C0	//192	//0x000000C0
#define TCM_ORD_Startup					0x00008099
#define TCM_ORD_PhysicalEnable			0x0000806F
#define TCM_ORD_PhysicalSetDeactivated	0x00008072
#define TCM_ORD_ForceClear				0x0000805D
#define TCM_ORD_OwnerClear				0x0000805B
#define TCM_ORD_TakeOwnership			0x0000800D
#define TCM_ORD_GetCapability			0x00008065
#define TCM_ORD_ReadPubek 				0x0000807C
#define TCM_ORD_CreateWrapKey			0x0000801F
#define	TCM_ORD_LoadKey					0x000080EF
#define TCM_ORD_EvictKey				0x00008022
#define TCM_ORD_GetPubKey				0x00008021
#define TCM_ORD_SMS4Encrypt				0x000080C5
#define TCM_ORD_SMS4Decrypt				0x000080C6
// #define TCM_ORD_ECCEncrypt			
#define TCM_ORD_ECCDecrypt				0x000080EE		
#define TCM_ORD_Sign					0x0000803C					
#define	TCM_ORD_Extend					0x00008014			
#define	TCM_ORD_PcrRead					0x00008015
#define TCM_ORD_SCHStart				0x000080EA
#define TCM_ORD_SCHUpdate				0x000080EB
#define TCM_ORD_SCHComplete				0x000080EC
#define TCM_ORD_SCHCompleteExtend		0x000080ED
#define TCM_ORD_FlushSpecific 			0x000080BA
#define TCM_ORD_PcrRead 				0x00008015
#define TCM_ORD_Extend 					0x00008014
#define TCM_ORD_GetRandom				0x00008046
#define TCM_ORD_PcrReset				0x000080C8

// wrong definitions below, cannot used in hardware tcm
// related functions may be not defined in tcm, only enable some to avoid compile errors.

// #define TCM_ORD_CreateWrapKey			31	//0x0000001F
// #define TCM_ORD_LoadKey					239	//0x000000EF
// #define TCM_ORD_EvictKey                230
#define TCM_ORD_GetKeyHandle            231
// #define TCM_ORD_GetPubKey				33	//0x00000021
// #define TCM_ORD_WrapKey					189	//0x000000BD
// #define TCM_ORD_CertifyKey				50	//0x00000032
// #define TCM_ORD_SMS4Encrypt				197	//0x000000C5
// #define TCM_ORD_SMS4Decrypt				198	//0x000000C6
// #define TCM_ORD_ECCDecrypt				238	//0x000000EE
#define TCM_ORD_ECCEncrypt				133
// #define TCM_ORD_Sign					60	//0x0000003C
#define TCM_ORD_Verify					134
// #define TCM_ORD_Extend					20	//0x00000014
// #define TCM_ORD_PCRRead					21	//0x00000015
// #define TCM_ORD_Quote					22	//0x00000016
// #define TCM_ORD_PCR_Reset				200	//0x000000C8
// #define TCM_ORD_Seal					23	//0x00000017
// #define TCM_ORD_Unseal					24	//0x00000018
// #define TCM_ORD_SCHStart				234	//0x000000EA
// #define TCM_ORD_SCHUpdate				235	//0x000000EB
// #define TCM_ORD_SCHComplete				236	//0x000000EC
// #define TCM_ORD_SCHCompleteExtend		237	//0x000000ED
// #define TCM_ORD_GetRandom				70	//0x00000046

// TCM_PROTOCOL_ID protocol id values
#define TCM_PID_OIAP 	0x0001 // The OIAP protocol.                   
#define TCM_PID_OSAP 	0x0002 // The OSAP protocol.                   
#define TCM_PID_ADIP 	0x0003; // The ADIP protocol.                   
#define TCM_PID_ADCP 	0X0004; // The ADCP protocol.                   
#define TCM_PID_OWNER 	0X0005; // The protocol for taking ownership of a TCM.
#define TCM_PID_DSAP 	0x0006; //  The DSAP protocol                    
#define TCM_PID_TRANSPORT 	0x0007; // The transport protocol
#define TCM_PID_AP  0x0008;     

// TCM 1.1 Capability Tags
#define TCPA_CAP_VERSION  0x00000006;

// TCM_CAPABILITY_AREA for TCM_GetCapability (TCM 1.2)
#define TCM_CAP_ORD  0x00000001;
#define TCM_CAP_ALG  0x00000002;
#define TCM_CAP_PID  0x00000003;
#define TCM_CAP_FLAG  0x00000004;
#define TCM_CAP_PROPERTY  0x00000005;
#define TCM_CAP_VERSION  0x00000006;
#define TCM_CAP_KEY_HANDLE  0x00000007;
#define TCM_CAP_CHECK_LOADED  0x00000008;
#define TCM_CAP_SYM_MODE  0x00000009;
#define TCM_CAP_KEY_STATUS  0x0000000C;
#define TCM_CAP_NV_LIST  0x0000000D;
#define TCM_CAP_MFR  0x00000010;
#define TCM_CAP_NV_INDEX  0x00000011;
#define TCM_CAP_TRANS_ALG  0x00000012;
#define TCM_CAP_HANDLE  0x00000014;
#define TCM_CAP_TRANS_ES  0x00000015;
#define TCM_CAP_AUTH_ENCRYPT  0x00000017;
#define TCM_CAP_SELECT_SIZE  0x00000018;
#define TCM_CAP_VERSION_VAL  0x0000001A;

// TCM_CAP_PROPERTY Subcap Values for TCM_GetCapability
#define TCM_CAP_PROP_PCR  0x00000101; //
#define TCM_CAP_PROP_DIR  0x00000102; //
#define TCM_CAP_PROP_MANUFACTURER  0x00000103; //
#define TCM_CAP_PROP_KEYS  0x00000104; //
#define TCM_CAP_PROP_MIN_COUNTER  0x00000107; //
#define TCM_CAP_PROP_AUTHSESS  0x0000010A; //
#define TCM_CAP_PROP_TRANSESS  0x0000010B; //
#define TCM_CAP_PROP_COUNTERS  0x0000010C; //
#define TCM_CAP_PROP_MAX_AUTHSESS  0x0000010D; //
#define TCM_CAP_PROP_MAX_TRANSESS  0x0000010E; //
#define TCM_CAP_PROP_MAX_COUNTERS  0x0000010F; //
#define TCM_CAP_PROP_MAX_KEYS  0x00000110; //
#define TCM_CAP_PROP_OWNER  0x00000111; //
#define TCM_CAP_PROP_CONTEXT  0x00000112; //
#define TCM_CAP_PROP_MAX_CONTEXT  0x00000113; //
#define TCM_CAP_PROP_FAMILYROWS  0x00000114; //
#define TCM_CAP_PROP_TIS_TIMEOUT  0x00000115; //
#define TCM_CAP_PROP_STARTUP_EFFECT  0x00000116; //
#define TCM_CAP_PROP_DELEGATE_ROW  0x00000117; //
#define TCM_CAP_PROP_DAA_MAX  0x00000119; //
#define CAP_PROP_SESSION_DAA  0x0000011A; //
#define TCM_CAP_PROP_CONTEXT_DIST  0x0000011B; //
#define TCM_CAP_PROP_DAA_uintERRUPT  0x0000011C; //
#define TCM_CAP_PROP_SESSIONS  0X0000011D; //
#define TCM_CAP_PROP_MAX_SESSIONS  0x0000011E; //
#define TCM_CAP_PROP_CMK_RESTRICTION  0x0000011F; //
#define TCM_CAP_PROP_DURATION  0x00000120; //
#define TCM_CAP_PROP_ACTIVE_COUNTER  0x00000122; //
#define TCM_CAP_PROP_MAX_NV_AVAILABLE  0x00000123; //
#define TCM_CAP_PROP_INPUT_BUFFER  0x00000124; //

#define TCM_CAP_FLAG_PERMANENT  0x00000108;
#define TCM_CAP_FLAG_VOLATILE  0x00000109;

// TCM Resource types
#define TCM_RT_KEY  0x00000001; // The handle is a key handle and is the result of a LoadKey type operation    
#define TCM_RT_AUTH  0x00000002; // The handle is an authorization handle. Auth handles come from TCM_OIAP, TCM_OSAP and TCM_DSAP     
#define TCM_RT_HASH  0X00000003; // Reserved for hashes                
#define TCM_RT_TRANS  0x00000004; // The handle is for a transport session. Transport handles come from TCM_EstablishTransport       
#define TCM_RT_CONTEXT  0x00000005; // Resource wrapped and held outside the TCM using the context save/restore commands       
#define TCM_RT_COUNTER  0x00000006; // Reserved for counters                
#define TCM_RT_DELEGATE  0x00000007; // The handle is for a delegate row. These are the uinternal rows held in NV storage by the TCM
#define TCM_RT_DAA_TCM  0x00000008; // The value is a DAA TCM specific blob           
#define TCM_RT_DAA_V0  0x00000009; // The value is a DAA V0 parameter            
#define TCM_RT_DAA_V1  0x0000000A; // The value is a DAA V1 parameter      

// TCM error code constant
#define TCM_BASE  0x0
#define TCM_SUCCESS TCM_BASE
#define TCM_E_AUTHFAIL  0x00000001
#define TCM_E_BADINDEX  0x00000002
#define TCM_E_BAD_PARAMETER  0x00000003
#define TCM_E_AUDITFAILURE  0x00000004
#define TCM_E_CLEAR_DISABLED  0x00000005
#define TCM_E_DEACTIVATED  0x00000006
#define TCM_E_DISABLED  0x00000007
#define TCM_E_DISABLED_CMD  0x00000008
#define TCM_E_FAIL  0x00000009
#define TCM_E_BAD_ORDINAL  0x0000000a
#define TCM_E_INSTALL_DISABLED  0x0000000b
#define TCM_E_INVALID_KEYHANDLE  0x0000000c
#define TCM_E_KEYNOTFOUND  0x0000000d
#define TCM_E_INAPPROPRIATE_ENC  0x0000000e
#define TCM_E_MIGRATEFAIL  0x0000000f
#define TCM_E_INVALID_PCR_INFO  0x00000010
#define TCM_E_NOSPACE  0x00000011
#define TCM_E_NOSRK  0x00000012
#define TCM_E_NOTSEALED_BLOB  0x00000013
#define TCM_E_OWNER_SET  0x00000014
#define TCM_E_RESOURCES  0x00000015
#define TCM_E_SHORTRANDOM  0x00000016
#define TCM_E_SIZE  0x00000017
#define TCM_E_WRONGPCRVAL  0x00000018
#define TCM_E_BAD_PARAM_SIZE  0x00000019
#define TCM_E_SHA_THREAD  0x0000001a
#define TCM_E_SHA_ERROR  0x0000001b
#define TCM_E_FAILEDSELFTEST  0x0000001c
#define TCM_E_AUTH2FAIL  0x0000001d
#define TCM_E_BADTAG  0x0000001e
#define TCM_E_IOERROR  0x0000001f
#define TCM_E_ENCRYPT_ERROR  0x00000020
#define TCM_E_DECRYPT_ERROR  0x00000021
#define TCM_E_INVALID_AUTHHANDLE  0x00000022
#define TCM_E_NO_ENDORSEMENT  0x00000023
#define TCM_E_INVALID_KEYUSAGE  0x00000024
#define TCM_E_WRONG_ENTITYTYPE  0x00000025
#define TCM_E_INVALID_POSTINIT  0x00000026
#define TCM_E_INAPPROPRIATE_SIG  0x00000027
#define TCM_E_BAD_KEY_PROPERTY  0x00000028
#define TCM_E_BAD_MIGRATION  0x00000029
#define TCM_E_BAD_SCHEME  0x0000002a
#define TCM_E_BAD_DATASIZE  0x0000002b
#define TCM_E_BAD_MODE  0x0000002c
#define TCM_E_BAD_PRESENCE  0x0000002d
#define TCM_E_BAD_VERSION  0x0000002e
#define TCM_E_NO_WRAP_TRANSPORT  0x0000002f
#define TCM_E_AUDITFAIL_UNSUCCESSFUL  0x00000030
#define TCM_E_AUDITFAIL_SUCCESSFUL  0x00000031
#define TCM_E_NOTRESETABLE  0x00000032
#define TCM_E_NOTLOCAL  0x00000033
#define TCM_E_BAD_TYPE  0x00000034
#define TCM_E_INVALID_RESOURCE  0x00000035
#define TCM_E_NOTFIPS  0x00000036
#define TCM_E_INVALID_FAMILY  0x00000037
#define TCM_E_NO_NV_PERMISSION  0x00000038
#define TCM_E_REQUIRES_SIGN  0x00000039
#define TCM_E_KEY_NOTSUPPORTED  0x0000003a
#define TCM_E_AUTH_CONFLICT  0x0000003b
#define TCM_E_AREA_LOCKED  0x0000003c
#define TCM_E_BAD_LOCALITY  0x0000003d
#define TCM_E_READ_ONLY  0x0000003e
#define TCM_E_PER_NOWRITE  0x0000003f
#define TCM_E_FAMILYCOUNT  0x00000040
#define TCM_E_WRITE_LOCKED  0x00000041
#define TCM_E_BAD_ATTRIBUTES  0x00000042
#define TCM_E_INVALID_STRUCTURE  0x00000043
#define TCM_E_KEY_OWNER_CONTROL  0x00000044
#define TCM_E_BAD_COUNTER  0x00000045
#define TCM_E_NOT_FULLWRITE  0x00000046
#define TCM_E_CONTEXT_GAP  0x00000047
#define TCM_E_MAXNVWRITES  0x00000048
#define TCM_E_NOOPERATOR  0x00000049
#define TCM_E_RESOURCEMISSING  0x0000004a
#define TCM_E_DELEGATE_LOCK  0x0000004b
#define TCM_E_DELEGATE_FAMILY  0x0000004c
#define TCM_E_DELEGATE_ADMIN  0x0000004d
#define TCM_E_TRANSPORT_NOTEXCLUSIVE  0x0000004e
#define TCM_E_OWNER_CONTROL  0x0000004f
#define TCM_E_DAA_RESOURCES  0x00000050
#define TCM_E_DAA_INPUT_DATA0  0x00000051
#define TCM_E_DAA_INPUT_DATA1  0x00000052
#define TCM_E_DAA_ISSUER_SETTINGS  0x00000053
#define TCM_E_DAA_TCM_SETTINGS  0x00000054
#define TCM_E_DAA_STAGE  0x00000055
#define TCM_E_DAA_ISSUER_VALIDITY  0x00000056
#define TCM_E_DAA_WRONG_W  0x00000057
#define TCM_E_BAD_HANDLE  0x00000058
#define TCM_E_BAD_DELEGATE  0x00000059
#define TCM_E_BADCONTEXT  0x0000005a
#define TCM_E_TOOMANYCONTEXTS  0x0000005b
#define TCM_E_MA_TICKET_SIGNATURE  0x0000005c
#define TCM_E_MA_DESTINATION  0x0000005d
#define TCM_E_MA_SOURCE  0x0000005e
#define TCM_E_MA_AUTHORITY  0x0000005f
#define TCM_E_PERMANENTEK  0x00000061
#define TCM_E_BAD_SIGNATURE  0x00000062
#define TCM_E_NOCONTEXTSPACE  0x00000063
#define TDDL_E_ALREADY_OPENED  0x00000081
#define TDDL_E_ALREADY_CLOSED  0x00000082
#define TDDL_E_INSUFFICIENT_BUFFER  0x00000083
#define TDDL_E_COMMAND_COMPLETED  0x00000084
#define TDDL_E_COMMAND_ABORTED  0x00000085
#define TDDL_E_IOERROR  0x00000087
#define TDDL_E_BADTAG  0x00000088
#define TDDL_E_COMPONENT_NOT_FOUND  0x00000089
#define TCM_E_RETRY  0x00000800
#define TCM_E_NEEDS_SELFTEST  0x00000801
#define TCM_E_DOING_SELFTEST  0x00000802
#define TCM_E_DEFEND_LOCK_RUNNING  0x00000803


#define TCM_NON_FATAL           0x00000800

/*
 * TCM_KEY_HANDLE    Reserved Key Handles 
 * These values specify specific keys or specific actions for the TCM.
 */
#define TCM_KH_SMK						0x40000000	//SMK��Կ���
#define TCM_KH_OWNER					0x40000001	//TCM�����߾��
#define TCM_KH_REVOKE					0x40000002	//�ɳ���EK���
#define TCM_KH_TRANSPORT				0x40000003	//��������Ự���
#define TCM_KH_OPERATOR					0x40000004	//��������Ȩ���
#define TCM_KH_EK						0x40000006	//EK���

/*
 * TCM_KEY_FLAGS
 */
#define TCM_KEY_FLAG_MIGRATABLE			0x00000002	//��Ǩ����Կ
#define TCM_KEY_FLAG_VOLATILE			0x00000004	//��ʧ����Կ��������ʱ����Ҫ���¼���
#define TCM_KEY_FLAG_PCR_IGNORE			0x00000008	//TRUEʱ���ڻ�ȡ��Կʱ�����PCR
													//FLASEʱ���ڻ�ȡ��Կʱ���PCR
/*
 * TCM_ALGORITHM_ID 
 * This table defines the types of algorithms which may be supported by the TCM.
 */	
#define TCM_ALG_KDF						0x00000007	//KDF�㷨
#define TCM_ALG_XOR						0x0000000A	//XOR�㷨
#define TCM_ALG_ECC						0x0000000B	//256ECC�㷨
#define TCM_ALG_SMS4					0x0000000C	//SMS4�㷨
#define TCM_ALG_SCH						0x0000000D	//SCH�㷨
#define TCM_ALG_HMAC					0x0000000E	//HMAC�㷨

/*
 * TCM Basic Structures
 */

/*
 * TCM_DIGEST
 * The digest value reports the result of a hash operation.
 */
typedef struct tdTCM_DIGEST {
  BYTE digest[32];//ժҪ��Ϣ
} TCM_DIGEST;

/* Redefinitions */
typedef TCM_DIGEST TCM_COMPOSITE_HASH;
typedef TCM_DIGEST TCM_HMAC;
typedef TCM_DIGEST TCM_PCRVALUE;

/*
 * TCM_NONCE
 * A random value that provides protection from replay and other attacks.
 */
typedef struct tdTCM_NONCE{
	BYTE NONCE[32];	//32�ֽڵ������
}TCM_NONCE;

/*
 * TCM_AUTHDATA 
 * Information that is saved or passed to provide proof of ownership of an
 * entity. 
 */
typedef BYTE TCM_AUTHDATA[32];

/* Redefinitions */
typedef TCM_AUTHDATA TCM_SECRET;
typedef TCM_AUTHDATA TCM_ENCAUTH;


/*
 * TCM_SIGN_INFO Structure
 * To provide the mechanism to quote the current values of a list of PCRs.
 */
typedef struct tdTCM_SIGN_INFO{
	TCM_STRUCTURE_TAG tag;	//TCM_TAG_SIGNINFO
	BYTE fixed[4];	//�̶�ֵ
	TCM_NONCE replay;	//���طŹ��������
	UINT32 dataLen;	//��ǩ�����ݳ���
	BYTE* data;	//��ǩ������
} TCM_SIGN_INFO;


/*
 * Number of PCRs of the TCM (must be a multiple of eight)
 */
#define TCM_NUM_PCR 24

/*
 * TCM_PCR_SELECTION
 * Provides a standard method of specifying a list of PCR registers.
 * Note: An error is reported if sizeOfSelect > sizeof(pcrSelect).
 */
typedef struct tdTCM_PCR_SELECTION{
	UINT16 sizeOfSelect;	//pcrSelect�Ĵ�С	2Byte
	BYTE pcrSelect[TCM_NUM_PCR/8];	//ÿ��bitλ��ʾ��Ӧ��PCR��ѡ���δ��ѡ��
} TCM_PCR_SELECTION;
#define sizeof_TCM_PCR_SELECTION(s) (2 + s.sizeOfSelect)

/*
 * TCM_PCR_COMPOSITE
 * The composite structure provides the index and value of the PCR register
 * to be used when creating the value that SEALS an entity to the composite.
 */
typedef struct tdTCM_PCR_COMPOSITE{
	TCM_PCR_SELECTION select;	//PCRѡ����Ϣ
	UINT32 valueSize;	//pcrValue�Ĵ�С
	TCM_PCRVALUE pcrValue[TCM_NUM_PCR];	//ѡ���PCRֵ
} TCM_PCR_COMPOSITE;
#define sizeof_TCM_PCR_COMPOSITE(s) (sizeof_TCM_PCR_SELECTION(s.select) \
	+ 4 + s.valueSize)

/*
 * TCM_PCR_INFO
 * Contains the information related to the wrapping of a key or the sealing
 * of data, to a set of PCRs.
 */
typedef struct tdTCM_PCR_INFO{
	TCM_STRUCTURE_TAG tag;
	TCM_PCR_SELECTION creationPCRSelection;
	TCM_PCR_SELECTION releasePCRSelection;
	TCM_COMPOSITE_HASH digestAtCreation;
	TCM_COMPOSITE_HASH digestAtRelease;
} TCM_PCR_INFO;
#define sizeof_TCM_PCR_INFO(s) (2  \
	+ sizeof_TCM_PCR_SELECTION(s.creationPCRSelection) \
	+ sizeof_TCM_PCR_SELECTION(s.releasePCRSelection) + 32 + 32)

/*
 * Storage Structures
 */

/*
 * TCM_STORED_DATA 
 * The definition of this structure is necessary to ensure
 * the enforcement of security properties.
 */
typedef struct tdTCM_STORED_DATA{
	TCM_STRUCTURE_TAG tag;	//TCM_TAG_STORED_DATA
	TCM_ENTITY_TYPE et;	//���ݿ�����
	UINT32 sealInfoSize;	//sealInfo�Ĵ�С
	TCM_PCR_INFO sealInfo;	//TCM_PCR_INFO�ṹ����
	UINT32 encDataSize;	//encData�Ĵ�С
	BYTE* encData;	//���ܵ�TCM_SEALED_DATA�ṹ����
} TCM_STORED_DATA;
#define sizeof_TCM_STORED_DATA(s) (2 + 1 + 4 + s.sealInfoSize \
	+ 4 + s.encDataSize)
#define free_TCM_STORED_DATA(s) { \
	if (s.encDataSize > 0) tcm_free(s.encData); }

/*
 * TCM_SEALED_DATA
 * This structure contains confidential information related
 * to sealed data, including the data itself.
 */
typedef struct tdTCM_SEALED_DATA{
	TCM_PAYLOAD_TYPE payload;		//TCM_PT_SEAL
	TCM_SECRET authData;	//��Ȩ����
	TCM_NONCE TCMProof;	//ƽ̨Ψһ��ʶTCM_PERMANENT_DATA->TCMProof
	TCM_DIGEST storedDigest;	//��encDataSize��encData���TCM_STORED_DATA�ṹ���ݵ�ժҪ��Ϣ
	UINT32 dataSize;	//Data�Ĵ�С
	BYTE* data;	//����װ������
} TCM_SEALED_DATA;
#define sizeof_TCM_SEALED_DATA(s) (1 + 32 + 32 + 32 + 4 + s.dataSize)
#define free_TCM_SEALED_DATA(s) { if (s.dataSize > 0) tcm_free(s.data); }


/*
 * TCM_SYMMETRIC_KEY
 * Describes a symmetric key.
 */
typedef struct tdTCM_SYMMETRIC_KEY {
	TCM_ALGORITHM_ID algId;	//�Գ��㷨ID
	TCM_ENC_SCHEME encScheme;	//����ģʽ
	UINT16 size;	//�Գ���Կ���ݳ���
	BYTE* data;	//�Գ���Կ����
} TCM_SYMMETRIC_KEY;
#define sizeof_TCM_SYMMETRIC_KEY(s) (4 + 2 + 2 + s.size)
#define free_TCM_SYMMETRIC_KEY(s) { if (s.size > 0) tcm_free(s.data); }

/*
 * TCM_BOUND_DATA
 * This structure is used by a TCM_UnBind command in a consistency check.
 */
typedef struct tdTCM_BOUND_DATA {
	TCM_PAYLOAD_TYPE payload;	//TCM_PT_BIND
	BYTE* payloadData;	//����
} TCM_BOUND_DATA;

/*
 * TCM_KEY complex
 */

/*
 * TCM_ECC_ASYMKEY_PARAMETERS
 * This structure describes the parameters of an TCM ECC asymmetric key
 */
typedef struct tdTCM_ECC_ASYMKEY_PARMS{
	UINT32 keyLength;	//��Կ����	4Byte
} TCM_ECC_ASYMKEY_PARMS;

/*
 * TCM_SYMMETRIC_KEY_PARMS
 * This structure describes the parameters of an TCM symmetric key
 */
typedef struct tdTCM_SYMMETRIC_KEY_PARMS{
	UINT32 keyLength;	//��Կ���س���
	UINT32 blockSize;	//�����С
	UINT32 ivSize;	//��ʼ��������
	BYTE* IV;	//��ʼ����
} TCM_SYMMETRIC_KEY_PARMS;
#define sizeof_TCM_SYMMETRIC_KEY_PARMS(s) (4 + 4 + 4 + s.ivSize)
#define free_TCM_SYMMETRIC_KEY_PARMS(s) { \
	if (s.ivSize > 0) tcm_free(s.ivSize); }

/*
 * TCM_KEY_PARMS
 * This structure describes the parameters of an TCM key
 */
typedef struct tdTCM_KEY_PARMS{
	TCM_ALGORITHM_ID algorithmID;
	TCM_ENC_SCHEME encScheme;
	TCM_SIG_SCHEME sigScheme;
	UINT32 parmSize;
	union {
		BYTE* raw;
		TCM_ECC_ASYMKEY_PARMS ecc;
		TCM_SYMMETRIC_KEY_PARMS skp;
	} parms;
} TCM_KEY_PARMS;
#define sizeof_TCM_KEY_PARMS(s) (4 + 2 + 2 + 4 + s.parmSize)
#define free_TCM_KEY_PARMS(s) { if (s.parmSize > 0) { \
	switch (s.algorithmID)	{ \
		case TCM_ALG_SMS4:  free_TCM_SYMMETRIC_KEY_PARMS(s.parms.skp); break; \
		default: tcm_free(s.parms.raw); } } }

/*
 * TCM_STORE_PUBKEY
 * This structure can be used in conjunction with a corresponding
 * TCM_KEY_PARMS to construct a public key which can be unambiguously used.
 */
typedef struct tdTCM_STORE_PUBKEY{
	UINT32 keyLength;	//��Կ����	4Byte
	BYTE* key;	//��Կ	max 65Byte��1(04)+32+32
} TCM_STORE_PUBKEY;
#define sizeof_TCM_STORE_PUBKEY(s) (4 + s.keyLength)
#define free_TCM_STORE_PUBKEY(s) { if (s.keyLength > 0) tcm_free(s.key); }

/*
 * TCM_KEY
 * The TCM_KEY structure provides a mechanism to transport the entire
 * asymmetric key pair. The private portion of the key is always encrypted.
 */
//#define TCM_TAG_KEY12 0x0028
typedef struct tdTCM_KEY{
	TCM_STRUCTURE_TAG tag;
	UINT16 fill;
	TCM_KEY_USAGE keyUsage;
	TCM_KEY_FLAGS keyFlags;
	TCM_AUTH_DATA_USAGE authDataUsage;
	TCM_KEY_PARMS algorithmParms;
	UINT32 PCRInfoSize;
	BYTE* PCRInfo;
	TCM_STORE_PUBKEY pubKey;
	UINT32 encDataSize;
	BYTE* encData;
} TCM_KEY;
#define sizeof_TCM_KEY(s) (2 + 2 + 2 + 4 + 1 \
  + sizeof_TCM_KEY_PARMS(s.algorithmParms) \
  + 4 + s.PCRInfoSize + sizeof_TCM_STORE_PUBKEY(s.pubKey) \
  + 4 + s.encDataSize)
#define free_TCM_KEY(s) { if (s.encDataSize > 0) tcm_free(s.encData); \
  free_TCM_KEY_PARMS(s.algorithmParms); free_TCM_STORE_PUBKEY(s.pubKey); }

/*
 * TCM_PUBKEY
 * Public portion of an asymmetric key pair.
 */
typedef struct tdTCM_PUBKEY{
	TCM_KEY_PARMS algorithmParms;	//��Կ����
	TCM_STORE_PUBKEY pubKey;		//��Կ
} TCM_PUBKEY;
#define sizeof_TCM_PUBKEY(s) (sizeof_TCM_KEY_PARMS(s.algorithmParms) \
  + sizeof_TCM_STORE_PUBKEY(s.pubKey))
#define free_TCM_PUBKEY(s) { free_TCM_KEY_PARMS(s.algorithmParms); \
  free_TCM_STORE_PUBKEY(s.pubKey); }

/*
 * TCM_STORE_PRIVKEY
 * This structure can be used in conjunction with a corresponding TCM_PUBKEY
 * to construct a private key which can be unambiguously used.
 */
typedef struct tdTCM_STORE_PRIVKEY{
	UINT32 keyLength;	//˽Կ����	4Byte
	BYTE* key;	//˽Կ����	32Byte
} TCM_STORE_PRIVKEY;
#define sizeof_TCM_STORE_PRIVKEY(s) (4 + s.keyLength)
#define free_TCM_STORE_PRIVKEY(s) { if (s.keyLength > 0) tcm_free(s.key); }

/*
 * TCM_STORE_ASYMKEY
 * The TCM_STORE_ASYMKEY structure provides the area to identify the
 * confidential information related to a key.
 */
typedef struct tdTCM_STORE_ASYMKEY{
	TCM_PAYLOAD_TYPE payload;
	TCM_SECRET usageAuth;
	TCM_SECRET migrationAuth;
	TCM_DIGEST pubDataDigest;
	TCM_STORE_PRIVKEY privKey;
} TCM_STORE_ASYMKEY;
#define sizeof_TCM_STORE_ASYMKEY(s) (1 + 32 + 32 + 32 \
  + sizeof_TCM_STORE_PRIVKEY(s.privKey))
#define free_TCM_STORE_ASYMKEY(s) { free_TCM_STORE_PRIVKEY(s.privKey); }

/*
 * TCM_STORE_SYMKEY
 */
typedef struct tdTCM_STORE_SYMKEY{
	TCM_PAYLOAD_TYPE payload;
	TCM_SECRET usageAuth;
	TCM_SECRET migrationAuth;
	UINT16 size;
	BYTE* data;
} TCM_STORE_SYMKEY;
#define sizeof_TCM_STORE_SYMKEY(s) (1 + 32 + 32 + 2 + s.size)
#define free_TCM_STORE_SYMKEY(s) { if (s.size > 0) tcm_free(s.data);  }

/*
 * Signed Structures
 */

/*
 * TCM_AUTH
 * Authorization Protocol Input/Output Parameter
 */
typedef struct tdTCM_AUTH {
	TCM_AUTHHANDLE authHandle;
	UINT32 nonce;
	TCM_AUTHDATA auth;
	/* additional NOT marshalled parameters */
	TCM_SECRET secret;
	TCM_COMMAND_CODE ordinal;
} TCM_AUTH;

/*
 * TCM_CERTIFY_INFO Structure
 * This structure provides the mechanism to provide a signature with a TCM
 * identity key on information that describes that key.
 */
typedef struct tdTCM_CERTIFY_INFO{
	TCM_KEY_USAGE keyUsage;	//��Կ��;
	TCM_KEY_FLAGS keyFlags;	//��Կ���ԣ��Ƿ��Ǩ�Ƶ�
	TCM_AUTH_DATA_USAGE authDataUsage;	//�Ƿ���Ҫ��Ȩ����
	TCM_KEY_PARMS algorithmParms;	//�㷨����
	TCM_DIGEST pubkeyDigest;	//��ԿժҪ
	TCM_NONCE data;	//���طŹ�������
	BOOL parentPCRStatus;	//��������Կ�Ƿ��PCR��
	UINT32 PCRInfoSize;	//PCR��Ϣ����
	TCM_PCR_INFO PCRInfo;	//PCR��Ϣ
} TCM_CERTIFY_INFO;
#define sizeof_TCM_CERTIFY_INFO(s) (2 + 4 + 1 \
  sizeof_TCM_KEY_PARMS(s.algorithmParms) + 32 + 32 + 1 + 4 \
  + s.PCRInfoSize)
#define free_TCM_CERTIFY_INFO(s) { free_TCM_KEY_PARMS(s.algorithmParms); }

/*
 * TCM_QUOTE_INFO Structure
 * This structure provides the mechanism for the TCM to quote the
 * current values of a list of PCRs.
 */
typedef struct tdTCM_QUOTE_INFO{
	TCM_STRUCTURE_TAG tag;	//TCM_TAG_QUOTE_INFO
	BYTE fixed[4];	//�̶�ֵ��QUT��
	TCM_NONCE externalData;	//32�ֽڷ��طŹ�������
	TCM_PCR_INFO info;	//PCR��Ϣ
} TCM_QUOTE_INFO;
#define sizeof_TCM_QUOTE_INFO(s) (2 + 4 + 32 + \
  sizeof_TCM_PCR_INFO(s.info))


/*
 * Internal Data Held By TCM
 */

/*
 * TCM_ASYMKEY 
 */
typedef struct tdTCM_ASYMKEY{
	BYTE privKey[32];
	BYTE pubKey[65]; 	//��Կ	1(04)+32+32
} TCM_ASYMKEY;

/*
 * TCM_SYMKEY 
 */
typedef struct tdTCM_SYMKEY{
	BYTE key[16];
} TCM_SYMKEY;

/*
 * TCM_KEY_DATA
 * This structure contains the data for stored keys.
 */
typedef struct tdTCM_KEY_DATA {
	TCM_PAYLOAD_TYPE payload;
	TCM_KEY_USAGE keyUsage;
	TCM_KEY_FLAGS keyFlags;
	TCM_AUTH_DATA_USAGE authDataUsage;
	TCM_ENC_SCHEME encScheme;
	TCM_SIG_SCHEME sigScheme;
	TCM_SECRET usageAuth;
	TCM_SECRET migrationAuth;
	TCM_PCR_INFO pcrInfo;
	BOOL parentPCRStatus;
	union {
		TCM_ASYMKEY asymKey;
		TCM_SYMKEY symKey;
	} parms; 

} TCM_KEY_DATA;

#define sizeof_TCM_KEY_DATA(s) (1 + 2 + 4 + 1 + 2 + 2 + 32 + 32 \
  + sizeof_TCM_PCR_INFO(s.pcrInfo)  \
  + 1 + 32 + 65)
//#define free_TCM_KEY_DATA(s) { tpm_rsa_release_private_key(&s.key); }  

/*
 * TCM_PERMANENT_DATA 
 * This structure contains the data fields that are permanently held in
 * the TCM and not affected by TCM_Startup(any).
 *
 * This is an informative structure and not normative.
 */
#define TCM_MAX_KEYS                    10
/*
#define TCM_TAG_PERMANENT_DATA          0x0022
#define TCM_MAX_COUNTERS                4
#define TCM_DELEGATE_KEY                TCM_KEY
#define TCM_MAX_NV_WRITE_NOOWNER        64
#define TCM_MAX_KEYS                    10
#define TCM_SYM_KEY_SIZE                32
#define TCM_MAX_NV_BUF_SIZE             1024
#define TCM_MAX_NVS                     20
#define TCM_NUM_TIS_TIMEOUTS            4
#define TCM_NUM_CMD_DURATIONS           3
*/
typedef struct tdTCM_PERMANENT_DATA {
	TCM_STRUCTURE_TAG tag;  
	TCM_NONCE TCMProof;
	TCM_SECRET ownerAuth;
	TCM_KEY_DATA endorsementKey;  
	TCM_KEY_DATA smk;
	TCM_PCRVALUE pcrValue[TCM_NUM_PCR];
} TCM_PERMANENT_DATA;
static inline int sizeof_TCM_PERMANENT_DATA(TCM_PERMANENT_DATA *s) {
	int size = 2 + 2*32;
	size += sizeof_TCM_KEY_DATA(s->endorsementKey);
	size += sizeof_TCM_KEY_DATA(s->smk);
	size += TCM_NUM_PCR*32;
	return size;
}

/*
 * TCM_SESSION_DATA
 * This structure contains the data for authorization and transport sessions.
 */
typedef struct tdTCM_SESSION_DATA {
	BYTE type;
	UINT32 nonce;
	TCM_SYMMETRIC_KEY sessionKey;
	TCM_SECRET sharedSecret;
	TCM_HANDLE handle;
	TCM_ENTITY_TYPE entityType;
}TCM_SESSION_DATA; 
#define sizeof_TCM_SESSION_DATA(s) (1 + 4 + (4 + 2 + s.sessionKey.size) + 32 + 4 + 1)	

/*
 * TCM_STANY_DATA 
 * Most of the data in this structure resets on TCM_Startup(ST_State).
 *
 * This is an informative structure and not normative.
 */
#define TCM_MAX_SESSIONS          3
typedef struct tdTCM_STANY_DATA {
	TCM_STRUCTURE_TAG tag;
	TCM_KEY_DATA keys[TCM_MAX_KEYS];
	TCM_SESSION_DATA sessions[TCM_MAX_SESSIONS];
} TCM_STANY_DATA;
#define sizeof_TCM_STANY_DATA(s) (2  \
	+ sizeof_TCM_KEY_DATA(s.keys[0]) * TCM_MAX_KEYS \
	+ sizeof_TCM_SESSION_DATA(s.sessions[0]) * TCM_MAX_SESSIONS )

/*
 * TCM_DATA
 * Internal data of the TCM
 */
typedef struct tdTCM_DATA {
  struct {
    //TCM_PERMANENT_FLAGS flags;
    TCM_PERMANENT_DATA data;
  } permanent;
/*  struct {
    TCM_STCLEAR_FLAGS flags;
    TCM_STCLEAR_DATA data;
  } stclear;*/
  struct {
    //TCM_STANY_FLAGS flags;
    TCM_STANY_DATA data;
  } stany;
} TCM_DATA;


/*
 * TCM communication packets
 */

/*
 * TCM_REQUEST 
 * TCM command request
 */
typedef struct tdTCM_REQUEST {
	TCM_TAG tag;
	UINT32 size;
	TCM_COMMAND_CODE ordinal;
	BYTE *param;
	UINT32 paramSize;
	TCM_AUTH auth1;
	TCM_AUTH auth2;
}TCM_REQUEST;


/*
 * TCM_RESPONSE
 * TCM command response
 */
typedef struct tdTCM_RESPONSE {
	TCM_TAG tag;
	UINT32 size;
	TCM_RESULT result;
	BYTE *param;
	UINT32 paramSize;
	TCM_AUTH *auth1;
	TCM_AUTH *auth2;
} TCM_RESPONSE;

/*
 * TCM_VER struct
 */
#define TCM_MAJOR       0x01

#if defined TCM_V12
#define TCM_MINOR       0x02
#endif

#if defined TCM_V11
#define TCM_MINOR       0x01
#endif

typedef struct tdTCM_STRUCT_VER { 
    BYTE major;         /* This SHALL indicate the major version of the structure. MUST be 0x01 */
    BYTE minor;         /* This SHALL indicate the minor version of the structure. MUST be 0x01 */
    BYTE revMajor;      /* This MUST be 0x00 on output, ignored on input */
    BYTE revMinor;      /* This MUST be 0x00 on output, ignored on input */
} TCM_STRUCT_VER; 


#define TCM_MEMORY_ALIGNMENT_MANDATORY 1

#endif /* _TCM_STRUCTURES_H_ */
