/*
 * SpiDriver.h
 *
 *  Created on: Dec 14, 2018
 *      Author: root
 */

#ifndef SPIDRIVER_H_
#define SPIDRIVER_H_

/*
 *
 * Register (I/O mapped)
 * BAR0
 */
#define REG_SPI_CMR		0x000
#define REG_SPI_CSS		0x001
#define REG_SPI_BRR		0x004
#define REG_SPI_DS		0x005
#define REG_SPI_DT		0x006
#define REG_SPI_SDAOF	0x007
#define REG_SPI_STOF0	0x008
#define REG_SPI_STOF1	0x009
#define REG_SPI_STOF2	0x00A
#define REG_SPI_STOF3	0x00B
#define REG_SPI_STOF4	0x00C
#define REG_SPI_STOF5	0x00D
#define REG_SPI_STOF6	0x00E
#define REG_SPI_STOF7	0x00F
#define REG_SPI_SDFL0	0x010
#define REG_SPI_SDFL1	0x011
#define REG_SPI_SSOL	0x012
#define REG_SPI_SDCR	0x013
#define REG_SPI_MISR	0x014

/* SPI Common Reg. BAR1*/
#define REG_SWRST		0x238

/* SPI DMA. BAR1. NO USER*/

//GPIO BAR5
#define REG_GPIO_DATA	0x3C0
#define REG_GPIO_DIR	0x3C4
#define REG_GPIO_EM		0x3C8
#define REG_GPIO_OD		0x3CC
#define REG_GPIO_PU		0x3D0
#define REG_GPIO_EDS	0x3D4
#define REG_GPIO_EDE	0x3D8
#define REG_GPIO_CTR	0x3DC

#define EXT_CLOCK				25000000//25MHZ

typedef enum _spi_mode_
{
	EM_SPI_MODE0 = 0x00,//MODE0
	EM_SPI_MODE1 = 0x04,//MODE1
	EM_SPI_MODE2 = 0x02,//MODE2
	EM_SPI_MODE3 = 0x06,//MODE3
}emSPIMODE;//SPI MODE

typedef enum _spi_clock_source_
{
	EM_SCS_125M,//125MHz from internal PLL.
	EM_SCS_100M,//100MHz from PCIe reference clock
	EM_SCS_EXT,//extern clock
}emSCS;// spi clock source

typedef enum _spi_chip_select_
{
	EM_SPICS0,//
	EM_SPICS1,//
	EM_SPICS2,//
	EM_SPICS3,//
	EM_SPICS4,//
	EM_SPICS5,//
	EM_SPICS6,//
	EM_SPICS7,//
}emSPICS;// spi Chip Select

typedef struct _device_information_
{
	char name[256];
	int handle;
	int commevent;
}stDI;//device information

stDI ScanDevice(char *portname);
stDI OpenSPI(stDI dev,unsigned int freq);
int CloseSPI(stDI dev);
void ResetSPI(int handle);
unsigned char GetSPIStatus(int handle, char clear);
void StartSPI(int handle, char interrupt);
unsigned long ReadWriteSpiData(int handle, unsigned char *txdata, unsigned long dlen, unsigned char *txrxdata, unsigned long rxlen);


int ReadSPIMemCfgReg(int handle, uint offset, ulong* RegValue);
int WriteSPIMemCfgReg(int handle, uint offset, ulong RegValue);
int ReadSPIIOCfgReg(int handle, uint offset, unsigned char* RegValue);
int WriteSPIIOCfgReg(int handle, uint offset, unsigned char RegValue);
int GetGPIOReg(int handle, uint offset, ulong* RegValue);
int SetGPIOReg(int handle, uint offset, ulong RegValue);

void Delayms(unsigned int dly);

#endif /* SPIDRIVER_H_ */
