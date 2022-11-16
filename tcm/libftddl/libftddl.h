#ifndef FTDI_SPI_LIBTIS_H_
#define FTDI_SPI_LIBTIS_H_

#define MAX_BUFFER_SIZE			2048

typedef  unsigned char			BYTE;  
typedef  unsigned char			UINT8;
typedef  unsigned short			UINT16;
typedef  unsigned int			UINT32;
#if __linux__
typedef  unsigned long			UINT64;
#endif

typedef  signed char			INT8;
typedef  signed short			INT16;
typedef  signed int				INT32;
#if __linux__
typedef  signed long			INT64;
#endif

typedef  UINT32					TSS_RESULT;

TSS_RESULT  Tddli_Open();
TSS_RESULT  Tddli_TransmitData(	BYTE* in, 
								UINT32 insize, 
								BYTE* out, 
								UINT32* outsize);
TSS_RESULT  Tddli_Close();

#endif  // FTDI_SPI_LIBTIS_H_
