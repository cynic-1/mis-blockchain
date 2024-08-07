/* Definition for IOCTL */
#define IOCTL_IO_SET_REGISTER		_IOW(0xD0, 11, int) //IO set register for bar0
#define IOCTL_IO_READ_REGISTER		_IOW(0xD0, 12, int) //IO read register for bar0
#define IOCTL_MEM_SET_REGISTER		_IOW(0xD0, 13, int) //MEM set register for bar1 and bar5
#define IOCTL_MEM_READ_REGISTER		_IOW(0xD0, 14, int) //MEM read register for bar1 and bar5
#define IOCTL_SET_TX_DMA_REG		_IOW(0xD0, 15, int) //Set some data for tx reg.
#define IOCTL_SET_RX_DMA_REG		_IOW(0xD0, 16, int) //Set some data for rx reg.
#define IOCTL_TX_DMA_WRITE		_IOW(0xD0, 17, int) //Write the data into tx dma
#define IOCTL_RX_DMA_READ		_IOW(0xD0, 18, int) //Read the data from rx dma
#define IOCTL_SET_SEMA_INTERRUPT	_IOW(0xD0, 19, int) //Set sema for interrupt

typedef enum _MMAP_BAR
{
	BAR1,
	BAR5
} MMAP_BAR;

/* Register */
typedef struct _SPI_REG 
{
	unsigned char	Offset;
	unsigned char	Value;
} SPI_REG, *PSPI_REG;
typedef struct _MMAP_SPI_REG
{
	MMAP_BAR	Bar;		/* For MEM mapped 0:bar1 1:bar5 */
	unsigned long 	Offset;
	unsigned long	Value;
} MMAP_SPI_REG, *PMMAP_SPI_REG;

/* DMA Buffer */
typedef struct _SPI_DMA
{
	unsigned long	Length;
	unsigned char	Buffer[128*1024];
} SPI_DMA, *PSPI_DMA;


