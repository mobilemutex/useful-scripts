/*
 * Copyright (c) 2026, mobilemutex
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef FLASHOS_H
#define FLASHOS_H

#define U8  unsigned char
#define U16 unsigned short
#define U32 unsigned long

#define I8  signed char
#define I16 signed short
#define I32 signed long

#define ONCHIP     1  // Device is on chip

struct SECTOR_INFO {
  U32 SectorSize;       // Sector Size in bytes
  U32 SectorStartAddr;  // Start address of sector
};

struct FlashDevice {
   U16 AlgoVer;         // Algo version. Must be 0x0101
   U8  Name[128];       // Flash device name
   U16 Type;            // Flash device type
   U32 BaseAddr;        // Flash base address
   U32 TotalSize;       // Total flash device size in Bytes
   U32 PageSize;        // Page Size
   U32 Reserved;        // Reserved, should be 0
   U8  ErasedVal;       // Erased value
   U32 TimeoutProg;     // Program page timeout in ms
   U32 TimeoutErase;    // Erase sector timeout in ms
   struct SECTOR_INFO SectorInfo[8];
};

//
// Flash programming functions
//
extern int Init(U32 Addr, U32 Freq, U32 Func);
extern int UnInit(U32 Func);
extern int EraseChip(void);
extern int EraseSector(U32 Addr);
extern int ProgramPage(U32 Addr, U32 Sz, U8 *pBuf);
extern U32 Verify(U32 Addr, U32 Sz, U8 *pBuf);

#endif // FLASHOS_H

// Optional Read function (not part of CMSIS spec, but useful for completeness)
extern int Read(U32 Addr, U32 Sz, U8 *pBuf);
