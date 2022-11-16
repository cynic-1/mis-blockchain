/*
 * SpiDriver.c
 *
 *  Created on: Dec 14, 2018
 *      Author: root
 */
#include <stdio.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/types.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include "ioctl.h"
#include "SpiDriver.h"
#include "ax99100_spi.h"

unsigned long SetSPIClock(int handle, emSCS source, unsigned long freq, char diven);
int SetSPIFIFODepth(int handle, unsigned char depth);
unsigned long SetSPIDevice(int handle, emSPIMODE mode, char lsb, char autocs, char weakup, char enspi);
void SetSPIChipSelect(int handle, emSPICS cs, char ede, char valid);

stDI handlelist[16]= {{"",-1}};
unsigned long handlenum = 0;

stDI ScanDevice(char *portname)
{
	int handle = -1;
	char  tmpname[256] = { 0 };
	int i,num=sizeof(handlelist)/sizeof(stDI);

	handlenum = 0;
	for(i = 0;i < num;i++)
	{
		memset(handlelist[i].name, '\0', sizeof(handlelist[i].name));
		handlelist[i].handle = -1;
		handlelist[i].commevent = -1;
	}

	handle = open(portname, O_RDWR);
	if (handle != -1)
	{
		sprintf(handlelist[0].name, "%s", portname);
		handlelist[0].handle = handle;
		close(handle);
		return handlelist[0];
	}

	for (i = 0;i < num;i++)
	{
		memset(tmpname, '\0', sizeof(tmpname));
		sprintf(tmpname, "%s%d", portname, i);
		handle = open(tmpname, O_RDWR);
		if (handle != -1)
		{
			sprintf(handlelist[handlenum].name, "%s%d", portname, i);
			handlelist[handlenum].handle = handle;
			handlenum++;
			close(handle);
			break;
		}
	}

	return handlelist[0];
}

stDI OpenSPI(stDI dev,unsigned int freq)
{
	int handle = -1;
	unsigned long data;
//	unsigned char temp;

	dev = ScanDevice(dev.name);
	if (dev.handle != -1)
	{
		/* Open Device */
		handle = open(dev.name, O_RDWR);
		dev.handle = handle;
		dev.commevent=-1;
		if(handle != -1)
		{
			data = 0;
			GetGPIOReg(handle,REG_GPIO_DIR,&data);
			data &= ~(1<<16);
			SetGPIOReg(handle,REG_GPIO_DIR,data);

			//en led
			GetGPIOReg(handle,REG_GPIO_DATA,&data);
			data &= ~(1<<16);
			SetGPIOReg(handle,REG_GPIO_DATA,data);

			//reset
			ResetSPI(handle);
			Delayms(10);
			SetSPIDevice(handle, EM_SPI_MODE0, 0, 0, 0, 0);
			SetSPIClock(handle, EM_SCS_100M, freq, 1);//100MHz from PCIe reference clock. Divide Enable,
			SetSPIFIFODepth(handle,8);//FIFO
			SetSPIDevice(handle, EM_SPI_MODE0, 0, 1, 0, 1);
			SetSPIChipSelect(handle, EM_SPICS0, 0, 0);
		}
	}
	return dev;
}

int CloseSPI(stDI dev)
{
	unsigned long data = 0;
	if(dev.handle != -1)
	{
		GetGPIOReg(dev.handle,REG_GPIO_DIR,&data);
		data &= ~(1<<16);
		SetGPIOReg(dev.handle,REG_GPIO_DIR,data);

		GetGPIOReg(dev.handle,REG_GPIO_DATA,&data);
		data |= (1<<16);
		SetGPIOReg(dev.handle,REG_GPIO_DATA,data);
		close(dev.handle);
	}
	return dev.handle;
}

/* Register read/write */
/* MEM mapping - READ*/
int ReadSPIMemCfgReg(int handle, uint offset, ulong* RegValue)
{
	MMAP_SPI_REG reg;

	reg.Offset	= offset;
	reg.Value	= 0;
	reg.Bar		= BAR1;

	if (ioctl(handle, IOCTL_MEM_READ_REGISTER, &reg) < 0) {
		printf("IOCTL_MEM_READ_REGISTER failed!!!\n");
		return -1;
	}

	*RegValue	= reg.Value;
	return 0;
}

/* MEM mapping - WRITE*/
int WriteSPIMemCfgReg(int handle, uint offset, ulong RegValue)
{
	MMAP_SPI_REG reg;

	reg.Offset	= offset;
	reg.Value	= RegValue;
	reg.Bar		= BAR1;

	if (ioctl(handle, IOCTL_MEM_SET_REGISTER, &reg) < 0) {
		printf("IOCTL_MEM_SET_REGISTER failed!!!\n");
		return -1;
	}
	return 0;
}

/* IO mapping - READ*/
int ReadSPIIOCfgReg(int handle, uint offset, unsigned char* RegValue)
{
	SPI_REG reg;

	reg.Offset	= offset;
	reg.Value	= 0;

	if (ioctl(handle, IOCTL_IO_READ_REGISTER, &reg) < 0) {
		printf("IOCTL_IO_READ_REGISTER failed!!!\n");
		return -1;
	}

	*RegValue	= reg.Value;
	return 0;
}
/* IO mapping - WRITE*/
int WriteSPIIOCfgReg(int handle, uint offset, unsigned char RegValue)
{
	SPI_REG reg;

	reg.Offset	= offset;
	reg.Value	= RegValue;

	if (ioctl(handle, IOCTL_IO_SET_REGISTER, &reg) < 0) {
		printf("IOCTL_IO_SET_REGISTER failed!!!\n");
		return -1;
	}
	return 0;
}

/* Register read/write */
/* GPIO mapping - READ*/
int GetGPIOReg(int handle, uint offset, ulong* RegValue)
{
	MMAP_SPI_REG reg;

	reg.Offset	= offset;
	reg.Value	= 0;
	reg.Bar		= BAR5;

	if (ioctl(handle, IOCTL_MEM_READ_REGISTER, &reg) < 0) {
		printf("IOCTL_MEM_READ_REGISTER failed(GPIO)!!!\n");
		return -1;
	}

	*RegValue	= reg.Value;
	return 0;
}

/* GPIO mapping - WRITE*/
int SetGPIOReg(int handle, uint offset, ulong RegValue)
{
	MMAP_SPI_REG reg;

	reg.Offset	= offset;
	reg.Value	= RegValue;
	reg.Bar		= BAR5;

	if (ioctl(handle, IOCTL_MEM_SET_REGISTER, &reg) < 0) {
		printf("IOCTL_MEM_SET_REGISTER failed(GPIO)!!!\n");
		return -1;
	}
	return 0;
}
//=============================================================================
//spi
void ResetSPI(int handle)
{
	WriteSPIMemCfgReg(handle,REG_SWRST,1);
}

unsigned char GetSPIStatus(int handle, char clear)
{
	unsigned char reg = 0;
	ReadSPIIOCfgReg(handle, REG_SPI_MISR, &reg);
	if (clear)
		WriteSPIIOCfgReg(handle, REG_SPI_MISR, 3);
	return reg;
}

void StartSPI(int handle, char interrupt)
{
	unsigned char reg = 0x0C;
	if (interrupt)
		reg |= 0xC0;
	WriteSPIIOCfgReg(handle, REG_SPI_SDCR, reg);
}

unsigned long ReadWriteSpiData(int handle, unsigned char *txdata, unsigned long dlen, unsigned char *txrxdata, unsigned long rxlen)
{
	unsigned char fifo = REG_SPI_STOF0;
	unsigned char value;
	unsigned char dump = 0;
	unsigned long i, slen, rlen, len, fifolen;

	WriteSPIIOCfgReg(handle, REG_SPI_CMR, 0xB0);
	len = dlen;
	for (i = 0, len = dlen, slen = 0;len;)
	{
//		WriteSPIIOCfgReg(handle, REG_SPI_CMR, 0xB0);
		fifolen = len;
		if (len >= 8)
			fifolen = 8;

		fifo = REG_SPI_STOF0;
		for (i = 0;i < fifolen;i++)
		{
			WriteSPIIOCfgReg(handle, fifo++, txdata[slen + i]);
		}
		value = ((fifolen - 1) & 0x7) << 4 | 0x6;
		WriteSPIIOCfgReg(handle, REG_SPI_SSOL, value);
		value = 0x0C;
		WriteSPIIOCfgReg(handle, REG_SPI_SDCR, value);
		do
		{
		} while (GetSPIStatus(handle, 0) == 0);
		//read fifo data.
		fifo = REG_SPI_STOF0;
		for (i = 0;i < fifolen;i++)
		{
			ReadSPIIOCfgReg(handle, fifo++, &txrxdata[slen + i]);
		}

		GetSPIStatus(handle, 1);

		len -= fifolen;
		slen += fifolen;
	}
//	WriteSPIIOCfgReg(handle, REG_SPI_CMR, 0xB0);
	len = 0;
	rlen = dlen;//继续接收数据
	if (rxlen > dlen)
		len = rxlen - dlen;
	else
		rlen = rxlen;//返回实际数据，如果rxlen < dlen

	for (i = 0;len;)
	{
	 	fifolen = len;
		if (len >= 8)
			fifolen = 8;

		fifo = REG_SPI_STOF0;
		for (i = 0;i < fifolen;i++)
		{
			WriteSPIIOCfgReg(handle, fifo++, dump);
		}
		value = ((fifolen - 1) & 0x7) << 4 | 0x6;
		WriteSPIIOCfgReg(handle, REG_SPI_SSOL, value);
		value = 0x0C;
		WriteSPIIOCfgReg(handle, REG_SPI_SDCR, value);
		do
		{
		} while (GetSPIStatus(handle, 0) == 0);
		//read fifo data.
		fifo = REG_SPI_STOF0;
		for (i = 0;i < fifolen;i++)
		{
			ReadSPIIOCfgReg(handle, fifo++, &txrxdata[rlen + i]);
		}

		GetSPIStatus(handle,1);

		len -= fifolen;
		rlen += fifolen;
	}

// 	ReadSPIIOCfgReg(handle, REG_SPI_CMR, &value);
	return rlen;
}

unsigned long SetSPIClock(int handle, emSCS source, unsigned long freq, char diven)
{
	unsigned char temp;
//	unsigned char div;
	unsigned long val = 0;
	//SCLK Frequency = (SPI clock source Frequency) / (Divider)

	temp = ((unsigned char)source) & 0x3;
	if (diven == 1)
	{
		WriteSPIIOCfgReg(handle, REG_SPI_CSS, temp);
		temp |= 0x04;
//		div = ((unsigned char)source) & 0x3;
		if (source == EM_SCS_125M)
		{
			if (freq > 125000000)
				return 125;
			val = 125000000 / freq;
			if (val > 255)
				return 256;
		}
		else
			if (source == EM_SCS_100M)
			{
				if (freq > 100000000)
					return 100;
				val = 100000000 / freq;
				if (val > 255)
					return 256;
			}
			else
				if (source == EM_SCS_EXT)
				{
					if (freq > EXT_CLOCK)
						return EXT_CLOCK / 1000000;
					val = EXT_CLOCK / freq;
					if (val > 255)
						return 256;
				}
		WriteSPIIOCfgReg(handle, REG_SPI_BRR, (unsigned char)val);
	}
	WriteSPIIOCfgReg(handle, REG_SPI_CSS, temp);
	return 0;
}

int SetSPIFIFODepth(int handle, unsigned char depth)
{
	unsigned char reg = 0;
	if (depth > 8)
		depth = 8;
	depth -= 1;
	ReadSPIIOCfgReg(handle, REG_SPI_SSOL, &reg);
	reg &= ~0x70;
	reg |= (depth & 0x7) << 4;
	WriteSPIIOCfgReg(handle, REG_SPI_SSOL, reg);
	return (depth + 1);
}

unsigned long SetSPIDevice(int handle, emSPIMODE mode, char lsb, char autocs, char weakup, char enspi)
{
	unsigned char value = 0x00;
	value |= (unsigned char)mode;
	if (lsb == 1)
		value |= 0x08;
	if (weakup == 1)
		value |= 0x40;
	if (enspi == 1)
		value |= 0x91;
	if (autocs == 1)
	{
		value |= 0x20;
		value &= ~0x01;
	}

	return WriteSPIIOCfgReg(handle, REG_SPI_CMR, value);
}

void SetSPIChipSelect(int handle, emSPICS cs, char ede, char valid)
{
	unsigned char reg = 0;
	unsigned char temp = 0;
	ReadSPIIOCfgReg(handle, REG_SPI_SSOL, &reg);
	reg &= ~0xF;
	temp = ((unsigned char)cs) & 0x7;
	if(ede == 1)
	{
		reg |= 0x08;//Ƭѡ0
		reg |= temp;
	}
	else
	{
		switch (temp)
		{
		case 0:
		default:
			reg |= 0x06;
			break;
		case 1:
			reg |= 0x05;
			break;
		case 2:
			reg |= 0x03;
			break;
		}
	}
	WriteSPIIOCfgReg(handle, REG_SPI_SSOL, reg);

	ReadSPIIOCfgReg(handle, REG_SPI_CMR, &reg);
	reg |= 1;
	if (valid == 1)
		reg &= ~1;
	WriteSPIIOCfgReg(handle, REG_SPI_CMR, reg);
}

void Delayms(unsigned int dly)
{
	unsigned int i,j;
	for(i = 0;i < dly;i++)
	{
		for(j=0;j < 20;j++)
			;
	}
}
