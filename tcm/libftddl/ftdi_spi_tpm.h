// Copyright 2015 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TRUNKS_TRUNKS_FTDI_SPI_H_
#define TRUNKS_TRUNKS_FTDI_SPI_H_

#include "config.h"
#include "SpiDriver.h"

extern stDI spidev;

int FtdiSpiInit(stDI dev,unsigned int bitrate, int enable_debug);
void FtdiStop(void);
size_t FtdiSendCommandAndWait(uint8_t *tpm_command, size_t command_size);
unsigned long SwapByte(unsigned long src,char type);
int ch_spi_write(stDI dev, void* vdata, int size);
unsigned char* ch_spi_read(stDI dev, int size);
uint8_t* ch_spi_transfer(stDI dev, uint8_t* data, int size);

unsigned long WriteTPMRegister(unsigned long addr, unsigned long rlen, unsigned char *indata);
unsigned long ReadTPMRegister(unsigned long addr, unsigned long rlen, unsigned char *outdata);

#endif  // TRUNKS_TRUNKS_FTDI_SPI_H_
