#ifndef __TPM2_SERVER_CONFIG_H
#define __TPM2_SERVER_CONFIG_H
#include "stdint.h"

//NULL definition
#ifndef NULL
#define NULL					(0)
#endif

typedef uint8_t					UINT8;
typedef uint8_t					BYTE;
typedef int8_t					INT8;
typedef int						BOOL;
typedef uint16_t				UINT16;
typedef int16_t					INT16;
typedef uint32_t				UINT32;
typedef int32_t					INT32;
typedef uint64_t				UINT64;
typedef int64_t					INT64;

typedef enum
{
	false = 0,
	true,
} bool;

typedef struct
{
	UINT16         size;
	BYTE           buffer[1];
} TPM2B;

#define BYTES_PER_LINE			24

#endif // __TPM2_SERVER_CONFIG_H
