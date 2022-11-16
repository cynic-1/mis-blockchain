#ifndef LIB_TDDL_H_
#define LIB_TDDL_H_

typedef unsigned char BYTE;
typedef unsigned char UINT8;
typedef unsigned short UINT16;
typedef unsigned int UINT32;

#ifndef UINT64
#if __linux__
typedef unsigned long long UINT64;
#endif
#endif

typedef signed char INT8;
typedef signed short INT16;
typedef signed int INT32;

#ifndef INT64
#if __linux__
typedef signed long long INT64;
#endif
#endif

typedef UINT32 TSS_RESULT;

#ifdef __cplusplus
extern "C" {
#endif
TSS_RESULT Tddli_Open();
TSS_RESULT Tddli_TransmitData(  BYTE* in,
								UINT32 insize,
								BYTE* out,
								UINT32 *outsize);
TSS_RESULT Tddli_Close();

#ifdef __cplusplus
}
#endif

#endif
