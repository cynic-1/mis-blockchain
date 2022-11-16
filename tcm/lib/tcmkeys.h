#ifndef TCMKEYS_H
#define TCMKEYS_H
#include "tcm.h"
#include "tcm_structures.h"
//#include <openssl/rsa.h>

#ifndef TCM_MAXIMUM_KEY_SIZE
#define TCM_MAXIMUM_KEY_SIZE  4096
#endif


#define TCM_SIZED_BUFFER_EMB(SIZE_OF_BUFFER,uniq,name) \
struct uniq { \
    uint32_t size; \
    BYTE buffer[SIZE_OF_BUFFER]; \
} name


typedef struct tdTCM_RSA_KEY_PARMS_EMB {
    uint32_t keyLength;
    uint32_t numPrimes;
    uint32_t exponentSize;
    BYTE   exponent[3];
} TCM_RSA_KEY_PARMS_EMB;


typedef struct tdTCM_SYMMETRIC_KEY_PARMS_EMB {
    uint32_t keyLength;
    uint32_t blockSize;
    uint32_t ivSize;
    BYTE   IV[256];
} TCM_SYMMETRIC_KEY_PARMS_EMB;

typedef struct tdTCM_KEY_PARMS_EMB {
    TCM_ALGORITHM_ID algorithmID; 	/* This SHALL be the key algorithm in use */
    TCM_ENC_SCHEME encScheme; 	/* This SHALL be the encryption scheme that the key uses to encrypt
                                   information */
    TCM_SIG_SCHEME sigScheme; 	/* This SHALL be the signature scheme that the key uses to perform
                                   digital signatures */
    union {
        TCM_RSA_KEY_PARMS_EMB       rsaKeyParms;
        TCM_SYMMETRIC_KEY_PARMS_EMB symKeyParms;
    } u;
} TCM_KEY_PARMS_EMB;


typedef struct tdTCM_STORE_PUBKEY_EMB {
    uint32_t keyLength;
    BYTE   modulus[TCM_MAXIMUM_KEY_SIZE/8];
} TCM_STORE_PUBKEY_EMB;


typedef struct tdTCM_KEY_EMB {
    TCM_STRUCT_VER ver;
    TCM_KEY_USAGE keyUsage;
    TCM_KEY_FLAGS keyFlags;
    TCM_AUTH_DATA_USAGE authDataUsage;
    TCM_KEY_PARMS_EMB algorithmParms;
    TCM_SIZED_BUFFER_EMB(256,
                         pcrInfo_TCM_KEY_EMB, pcrInfo);
    TCM_STORE_PUBKEY_EMB pubKey;
    TCM_SIZED_BUFFER_EMB(1024, encData_TCM_KEY_EMB, encData);
} TCM_KEY_EMB;


typedef struct tdTCM_KEY12_EMB { 
    TCM_STRUCTURE_TAG tag;
    uint16_t fill;
    TCM_KEY_USAGE keyUsage;
    TCM_KEY_FLAGS keyFlags;
    TCM_AUTH_DATA_USAGE authDataUsage;
    TCM_KEY_PARMS_EMB algorithmParms;
    TCM_SIZED_BUFFER_EMB(256,
                         pcrInfo_TCM_KEY12_EMB, pcrInfo);
    TCM_STORE_PUBKEY_EMB pubKey;
    TCM_SIZED_BUFFER_EMB(1024, encData_TCM_KEY12_EMB, encData);
} TCM_KEY12_EMB; 

typedef struct pubkeydata
{
   TCM_KEY_PARMS_EMB algorithmParms;
   TCM_STORE_PUBKEY_EMB pubKey;
   TCM_SIZED_BUFFER_EMB(256,
                        pcrInfo_pubkeydata, pcrInfo);
} pubkeydata;
   
typedef struct keydata
{
   union {
       TCM_STRUCT_VER      ver;
       TCM_STRUCTURE_TAG   tag;       // 1
   } v;
   TCM_KEY_USAGE       keyUsage;      // 2
   TCM_KEY_FLAGS       keyFlags;      // 3
   TCM_AUTH_DATA_USAGE authDataUsage; // 4
   pubkeydata     pub;
   TCM_SIZED_BUFFER_EMB(1024, encData_keydata, encData);
} keydata;


#endif
