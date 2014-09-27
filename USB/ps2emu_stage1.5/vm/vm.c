#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <ps2emu/ps2emu.h>
#include <ps2emu/libc.h>
#include <ps2emu/patch.h>

#include "../../ps2emu_stage2/common/common.h"

#include "vm.h"

#if defined(PS2HWEMU)
#include "rom_hwemu.h"
#include "opcodes_hwemu.c"
#elif defined(PS2GXEMU)
#include "rom_gxemu.h"
#include "opcodes_gxemu.c"
#elif defined(PS2SOFTEMU)
#include "rom_softemu.h"
#include "opcodes_softemu.c"
#endif

#define ROM_KEYS_LEN	251
#define SWAP16(x) ((((x)&0xff)<<8) | (((x)>>8)&0xff))
//#define swap32(x) ((((x) & 0xff) << 24) | (((x) & 0xff00) << 8) | (((x) & 0xff0000) >> 8) | (((x) >> 24) & 0xff))


//static const unsigned int RomSize = 65536;
static const unsigned int RamSize = 512;
static const unsigned int XRamSize = 65536;

enum Flag { P, USER, OV, RS0, RS1, F0, AC, CY };

static const int InvalidData = 11;
static const int LineLength = 80;
static const int RecordTypeLength = 3;

static const unsigned short ACC = 0x0160;
static const unsigned short PSW = 0x0150;
static const unsigned short B = 0x0170;
static const unsigned short SP = 0x0101;
static const unsigned short P0 = 0x0100;
static const unsigned short P1 = 0x0110;
static const unsigned short P2 = 0x0120;
static const unsigned short P3 = 0x0130;
static const unsigned short DPL = 0x0102;
static const unsigned short DPH = 0x0103;

static char *RAM;
static char *XRAM;
static unsigned short PC;
static unsigned char IR;
static unsigned short tempDPTR;
static int progEnd, rebooted;

static char *rom;
static uint8_t *rom_keys;


unsigned int instrCount;
unsigned int cycleCount;

#ifdef DEBUG

static INLINE uint64_t get_ticks(void)
{
	unsigned int tbl, tbu0, tbu1;
	do 
	{
		__asm__ __volatile__( "mftbu %0":"=r"( tbu0 ) );
		__asm__ __volatile__( "mftb %0":"=r"( tbl ) );
		__asm__ __volatile__( "mftbu %0":"=r"( tbu1 ) );
	} while (tbu0 != tbu1);
	
	return (((uint64_t) tbu0 ) << 32) | tbl;
}

#endif

static uint32_t swap32(uint32_t data)
{
	return ((((data) & 0xff) << 24) | (((data) & 0xff00) << 8) | (((data) & 0xff0000) >> 8) | (((data) >> 24) & 0xff));
}

static uint64_t swap64(uint64_t data)
{
	uint64_t ret = (data << 56) & 0xff00000000000000ULL;
	ret |= ((data << 40) & 0x00ff000000000000ULL);
	ret |= ((data << 24) & 0x0000ff0000000000ULL);
	ret |= ((data << 8) & 0x000000ff00000000ULL);
	ret |= ((data >> 8) & 0x00000000ff000000ULL);
	ret |= ((data >> 24) & 0x0000000000ff0000ULL);
	ret |= ((data >> 40) & 0x000000000000ff00ULL);
	ret |= ((data >> 56) & 0x00000000000000ffULL);
	return ret;
}

static char XRAM_Read(unsigned int address)
{
#ifdef DEBUG
	//DPRINTF("Read to address %x: %x\n", address, XRAM[address]&0xFF);
#endif
	
	if (address == PS3_RAM)
	{
		char *ptr = (char *)(uint64_t)swap32(*(uint32_t *)&XRAM[PS3_ADDRESS]);
		return *ptr;
	}
	/*else if (address == CYCLE_COUNT)
	{
		*(uint32_t *)&XRAM[CYCLE_COUNT] = SWAP32(cycleCount);
		DPRINTF("Cycle count: %x\n", cycleCount);		
	}
	else if (address == INST_COUNT) 
	{
		*(uint32_t *)&XRAM[INST_COUNT] = swap32(instrCount);
		DPRINTF("Instr count: %x\n", instrCount);
	}
	else if (address == VM_TICK)
	{
		*(uint64_t *)&XRAM[VM_TICK] = swap64(get_ticks());
	}*/
	else if (address >= ROM_RW)
	{
		return rom[address-ROM_RW];
	}
	
	return XRAM[address];
}

static inline void XRAM_Write(unsigned int address, char value)
{
#ifdef DEBUG
	if (address >= 0x2000 && address < 0x2800)
		DPRINTF("Write to address %x: %02x\n", address, value&0xFF);
#endif
	
	XRAM[address] = value;
	
	if (address == PS3_RAM)
	{
		char *ptr = (char *)(uint64_t)swap32(*(uint32_t *)&XRAM[PS3_ADDRESS]);
		*ptr = value;
	}
	/*else if (address == CYCLE_COUNT+3)
	{
		cycleCount = swap32(*(uint32_t *)&XRAM[CYCLE_COUNT]);
	}
	else if (address == INST_COUNT+3)
	{
		instrCount = swap32(*(uint32_t *)&XRAM[INST_COUNT]);
	}*/
	else if (address == PS3_CALL && value)
	{
		uint64_t r3 = swap64(*(uint64_t *)&XRAM[PS3_PARAM1]);
		uint64_t r4 = swap64(*(uint64_t *)&XRAM[PS3_PARAM2]);
		uint64_t r5 = swap64(*(uint64_t *)&XRAM[PS3_PARAM3]);
		uint64_t r6 = swap64(*(uint64_t *)&XRAM[PS3_PARAM4]);
		uint64_t r7 = swap64(*(uint64_t *)&XRAM[PS3_PARAM5]);
		uint64_t r8 = swap64(*(uint64_t *)&XRAM[PS3_PARAM6]);
		uint64_t r9 = swap64(*(uint64_t *)&XRAM[PS3_PARAM7]);
		uint64_t r10 = swap64(*(uint64_t *)&XRAM[PS3_PARAM8]);
		
		{		
			uint64_t (* func)();
			f_desc_t desc;
		
			desc.addr = (void *)(uint64_t)swap32(*(uint32_t *)&XRAM[PS3_ADDRESS]);
			desc.toc = (void *)(uint64_t)swap32(*(uint32_t *)&XRAM[PS3_TOC]);
		
			DPRINTF("Call to %p:  %lx %lx %lx %lx %lx\n", desc.addr, r3, r4, r5, r6, r7);				
		
			func = (void *)&desc;
			*(uint64_t *)&XRAM[PS3_RESULT] = swap64(func(r3, r4, r5, r6, r7, r8, r9, r10));
		}		
	}
	else if (address == VM_REBOOT+1)
	{
		rom = &ROM[SWAP16(*(uint16_t *)&XRAM[VM_REBOOT])];
		rom_keys = (uint8_t *)(uint64_t)swap32(*(uint32_t *)&XRAM[PS3_ADDRESS]);
		rebooted = 1;			
	}
	else if (address == VM_TERMINATE && value)
	{
		progEnd = 1;
	}
	else if (address >= ROM_RW)
	{
		rom[address-ROM_RW] = value;
	}
}

static char ROM_Read(unsigned int address)
{
	return rom[address] ^ rom_keys[address%ROM_KEYS_LEN];
}

void INLINE I8051_Init(uint64_t r3, uint64_t r4, uint64_t r5, uint64_t r6)
{
	PC = 0;
	instrCount = 0;
	cycleCount = 0;
	progEnd = 0;
	
	RAM = malloc(RamSize);
	XRAM = malloc(XRamSize);
	
#ifdef DEBUG
	if (!RAM || !XRAM)
	{
		fatal("Memory allocation error.\n");		
	}
#endif
	
	memset(RAM, 0, RamSize);
	memset(XRAM, 0, XRamSize);
	
	rom = ROM;
	rom_keys = (uint8_t *)XRAM+0x6000;
	
#if defined(PS2HWEMU)

	for (uint64_t i = 0; i < ROM_KEYS_LEN; i++)
	{
		rom_keys[i] = (((i*(i-0x763ABBULL))^0x71B12828B8ULL)>>((i^0x5c)%19)) - (((i*0x7E0E9974A83641D0ULL)^(0xBD787B740FE19D02ULL-i))/((i+104)*(i+1)));
	}
	
#elif defined(PS2GXEMU)
	
	for (uint64_t i = 0; i < ROM_KEYS_LEN; i++)
	{
		rom_keys[i] = (((i+0x3e778ULL)*0x1FF9DULL)>>(i&0xF)) + ((i*0x200F)/((i+1)*(i+1)));		
	}
	
#elif defined(PS2SOFTEMU)

	for (uint64_t i = 0; i < ROM_KEYS_LEN; i++)
	{
		rom_keys[i] = (((i-0x763ABBULL)*0xF7CAA3B1ULL)>>((i^0x13)&0xF)) + (((i*0x1A44E5E613CE7400ULL)^0x0A59A7A134228F04ULL)/((i+1)*(i+1)));
	}

#endif
	
	*(uint64_t *)&XRAM[VM_SAVED_PARAM1] = swap64(r3);
	*(uint64_t *)&XRAM[VM_SAVED_PARAM2] = swap64(r4);
	*(uint64_t *)&XRAM[VM_SAVED_PARAM3] = swap64(r5);
	*(uint64_t *)&XRAM[VM_SAVED_PARAM4] = swap64(r6);
}

void INLINE I8051_End()
{
	memset(RAM, 0, RamSize);
	memset(XRAM, 0, XRamSize);
	free(RAM);
	free(XRAM);
}

uint8_t I8051_GetRegisterBank() 
{
	return 8 * ((RAM[PSW] & 0x18) >> 3);
}

void INLINE I8051_SetBit(char *thisByte, unsigned char thisBit) 
{    
	*thisByte = *thisByte | (0x01 << thisBit);
}

void INLINE I8051_ClearBit(char *thisByte, unsigned char thisBit) 
{
	*thisByte = *thisByte & ~(0x01 << thisBit);
}

uint8_t INLINE I8051_GetBit(char thisByte, unsigned char thisBit) 
{
	return( (thisByte & (0x01 << thisBit)) >> thisBit);
}

int INLINE I8051_Simulate(void) 
{
	unsigned short tempProduct = 0;
	unsigned short jumpAddr;
	short tempAdd;
	unsigned char directAddr = 0;
	unsigned char regNum;
	unsigned char rotateBit;
	unsigned char lowerNibble;
	unsigned char tempACC;
	char temp;
	char popData;
    
	int carry3;
	int carry6;
	int carry7;
	int borrow3;
	int borrow6;
	int borrow7;

	{
		// initialize 8051 internal RAM
		// initialize SFR
		RAM[ACC] = 0x00;
		RAM[PSW] = 0x00;
		RAM[P0] = 0xFF;
		RAM[P1] = 0xFF;
		RAM[P2] = 0xFF;
		RAM[P3] = 0xFF;
		RAM[B] = 0x00;
		RAM[SP] = 0x07;
		RAM[DPH] = 0x00;
		RAM[DPL] = 0x00;
		
		*(uint32_t *)&XRAM[XRAM_ADDR] = swap32((uint64_t)XRAM & 0xFFFFFFFF);
		*(uint32_t *)&XRAM[ROM_ADDR] = swap32((uint64_t)rom & 0xFFFFFFFF);
	
		// program Loaded emulate program
		while(!progEnd) 
		{	    
			//if( PC >= sizeof(ROM)) PC = 0;
			if (rebooted)
			{
				rebooted = 0;
				PC = 0;
				memset(RAM, 0, RamSize);
				memset(XRAM, 0, 0x6000);
				RAM[ACC] = 0x00;
				RAM[PSW] = 0x00;
				RAM[P0] = 0xFF;
				RAM[P1] = 0xFF;
				RAM[P2] = 0xFF;
				RAM[P3] = 0xFF;
				RAM[B] = 0x00;
				RAM[SP] = 0x07;
				RAM[DPH] = 0x00;
				RAM[DPL] = 0x00;
				tempDPTR = 0;
				tempProduct = 0;
				directAddr = 0;
				*(uint32_t *)&XRAM[ROM_ADDR] = swap32((uint64_t)rom & 0xFFFFFFFF);							
			}
			
			/*if (CODE[PC] == 0)
				DPRINTF("No code!!!!!!! PC = %x\n", PC);*/
	    
			// get instruction
			IR = ROM_Read(PC++);

			// increment number of instructions executed
			instrCount++;
			
			//(A) <- (A) ^ (direct)		  
			if (IR == XRL2)
			{		
				IR = ROM_Read(PC++) ^ XRL2_X;
				RAM[ACC] ^= RAM[IR < 128 ? IR : (IR+128)];
				//cycleCount += 8;
			}		
		
			//(A) <- (A) & ((Ri))
			else if ((IR&0xFE) == ANL3)
			{		    
				regNum = IR & 0x01;
				RAM[ACC] &= RAM[(unsigned short)RAM[I8051_GetRegisterBank()+regNum]];
				//cycleCount += 12;
			}
		
			//(A) <- (A) | (Rn)
			else if ((IR&0xF8) == ORL1)
			{		
				regNum = IR & 0x07;
				RAM[ACC] |= RAM[I8051_GetRegisterBank()+regNum];
				//cycleCount += 10;
			}
		
			//(A) <- (A) | (direct)		  
			else if (IR == ORL2)
			{		
				IR = ROM_Read(PC++) ^ ORL2_X;
				RAM[ACC] |= RAM[IR < 128 ? IR : (IR+128)];
				//cycleCount += 8;
			}								
		
			// (C) <- (C) | (bit)
			else if (IR == ORL7)
			{		
				IR = ROM_Read(PC++) ^ ORL7_X;
				if( I8051_GetBit(RAM[((IR & 0xF8) < 128) ? (((IR & 0xF8)>>3)+32) : (128 + (IR & 0xF8))], (IR & 0x07)) ) 
				{
					I8051_SetBit(&RAM[PSW], CY);
				}
		   
				//cycleCount += 12;
			}
			
			//(A) <- (A) ^ ((Ri))
			else if ((IR&0xFE) == XRL3)
			{		
				regNum = IR & 0x01;
				RAM[ACC] ^= RAM[(unsigned short)RAM[I8051_GetRegisterBank()+regNum]];
				//cycleCount += 16;
			}		
					
			//(A) <- (A) & (#data)
			else if (IR == ANL4)
			{		
				IR = ROM_Read(PC++) ^ ANL4_X;
				RAM[ACC] &= (char)IR;
				//cycleCount += 19;
			}	
			
			// Rotate Right (A)
			else if (IR == RR)
			{		    
				rotateBit = I8051_GetBit(RAM[ACC], 0);
				RAM[ACC] = (unsigned char)RAM[ACC] >> 1;
				if( rotateBit == 0x01 ) 
				{
					I8051_SetBit(&RAM[ACC], 7);
				}
				else 
				{
					I8051_ClearBit(&RAM[ACC], 7);
				}
		    
				//cycleCount += 36;
			}			
		
			//(A) <- (A) ^ (Rn)
			else if ((IR & 0xF8) == XRL1)
			{		
				regNum = IR & 0x07;
				RAM[ACC] ^= RAM[I8051_GetRegisterBank()+regNum];
				//cycleCount += 16;
			}			
			
			// (direct) <- (direct) & (A)
			else if (IR == ANL5)
			{		
				IR = ROM_Read(PC++) ^ ANL5_X;
				RAM[IR < 128 ? IR : (IR+128)] &= RAM[ACC];
				//cycleCount += 4;
			}		
			
			// (direct) <- (direct) ^ (A)
			else if (IR == XRL5)
			{		
				IR = ROM_Read(PC++) ^ XRL5_X;
				RAM[IR < 128 ? IR : (IR+128)] ^= RAM[ACC];
				//cycleCount += 12;
			}
			
			// Ri <- A
			else if ((IR&0xFE) == MOV13)
			{		    
				regNum = IR & 0x01;
				RAM[(unsigned short)RAM[I8051_GetRegisterBank()+regNum]] = RAM[ACC];
				//cycleCount += 20;
			}			
		
			//(A) <- (A) & (Rn)
			else if ((IR&0xF8) == ANL1)
			{		    
				regNum = IR & 0x07;
				RAM[ACC] &= RAM[I8051_GetRegisterBank()+regNum];
				//cycleCount += 8;
			}
			
			//(direct) <- (direct) & (#data)
			else if (IR == ANL6)
			{		
				directAddr = ROM_Read(PC++) ^ ANL6_X1;
				IR = ROM_Read(PC++) ^ ANL6_X2;
				RAM[directAddr < 128 ? directAddr : (directAddr+128)] &= (char)IR;
				//cycleCount += 8;
			}
		
			// CLR (bit)
			else if (IR == CLR3)
			{
				IR = ROM_Read(PC++) ^ CLR3_X;
				I8051_ClearBit(&RAM[((IR & 0xF8) < 128) ? (((IR & 0xF8)>>3)+32) : (128 + (IR & 0xF8))], (IR & 0x07));
				//cycleCount += 12;
			}
		
			// SETB (C)
			else if (IR == SETB1)
			{		
				I8051_SetBit(&RAM[PSW], CY);
				//cycleCount += 8;
			}
			
			//(A) <- (A) | (#data)
			else if (IR == ORL4)
			{		
				IR = ROM_Read(PC++) ^ ORL4_X;
				RAM[ACC] |= (char)IR;
				//cycleCount += 24;
			}	
		
			// SETB (bit)
			else if (IR == SETB2)
			{		
				IR = ROM_Read(PC++) ^ SETB2_X;
				I8051_SetBit(&RAM[((IR & 0xF8) < 128) ? (((IR & 0xF8)>>3)+32) : (128 + (IR & 0xF8))], (IR & 0x07));
				//cycleCount += 16;
			}			
		
			// (direct) <- (direct) | (A)
			else if (IR == ORL5)
			{		
				IR = ROM_Read(PC++) ^ ORL5_X;
				RAM[IR < 128 ? IR : (IR+128)] |= RAM[ACC];
				//cycleCount += 36;
			}
			
			// CJNE (Rn), (#data), (rel)
			else if ((IR&0xF8) == CJNE3)
			{		    
				regNum = IR & 0x07;
				IR = ROM_Read(PC++) ^ CJNE3_X1;
				directAddr = IR;
				if( RAM[I8051_GetRegisterBank()+regNum] != (char)IR ) 
				{
					IR = ROM_Read(PC++) ^ CJNE3_X2;
					PC += (char)IR;
				}
				else 
				{
					PC++;
				}
				if( (unsigned char)RAM[I8051_GetRegisterBank()+regNum] < (unsigned char)directAddr ) 
				{
					I8051_SetBit(&RAM[PSW], CY);
				}
				else 
				{
					I8051_ClearBit(&RAM[PSW], CY);
				}
				//cycleCount += 40;
			}
		
			// CPL (C)
			else if (IR == CPL2)
			{
				if(I8051_GetBit(RAM[PSW], CY) == 0x01 ) 
				{
					I8051_ClearBit(&RAM[PSW], CY);
				}
				else 
				{
					I8051_SetBit(&RAM[PSW], CY);
				}
				//cycleCount += 8;
			}		
			
			// (C) <- (C) & /(bit)
			else if (IR == ANL8)
			{		
				IR = ROM_Read(PC++) ^ ANL8_X;
				if (I8051_GetBit(RAM[((IR & 0xF8) < 128) ? (((IR & 0xF8)>>3)+32) : (128 + (IR & 0xF8))], (IR & 0x07)) ) 
				{
					I8051_ClearBit(&RAM[PSW], CY);
				}
	  
				//cycleCount += 16;
			}
		    
			// Rotate Left (A)
			else if (IR == RL)
			{
		    
				rotateBit = I8051_GetBit(RAM[ACC], 7);
				RAM[ACC] = (unsigned char)RAM[ACC] << 1;
				if( rotateBit == 0x01 ) 
				{
					I8051_SetBit(&RAM[ACC], 0);
				}
				else 
				{
					I8051_ClearBit(&RAM[ACC], 0);
				}
				//cycleCount += 24;
			}
			
			// SUBB A, (#data)
			else if (IR == SUBB4)
			{
		    
				borrow3 = 0;
				borrow6 = 0;
				borrow7 = 0;
				IR = ROM_Read(PC++) ^ SUBB4_X;
				if( (unsigned char)(RAM[ACC] & 0x0F) < (unsigned char)((IR & 0x0F) + (char)I8051_GetBit(RAM[PSW], CY)) ) 
				{
					borrow3 = 1;
				}
				if( (unsigned char)(RAM[ACC] & 0x7F) < (unsigned char)((IR & 0x7F) + (char)I8051_GetBit(RAM[PSW], CY)) ) 
				{
					borrow6 = 1;
				}
				if( (unsigned short)(unsigned char)RAM[ACC] < ((unsigned short)IR + (unsigned short)I8051_GetBit(RAM[PSW], CY)) ) 
				{
					borrow7 = 1;
				}
				RAM[ACC] = (unsigned short)(unsigned char)RAM[ACC] - ((unsigned short)IR + (unsigned short)I8051_GetBit(RAM[PSW], CY));
				if( borrow3 ) I8051_SetBit(&RAM[PSW], AC);
				else I8051_ClearBit(&RAM[PSW], AC);
				if( borrow7 ) I8051_SetBit(&RAM[PSW], CY);
				else I8051_ClearBit(&RAM[PSW], CY);
				if( (borrow6 && !borrow7) || (!borrow6 && borrow7) ) 
					I8051_SetBit(&RAM[PSW], OV);
				else I8051_ClearBit(&RAM[PSW], OV);
				//cycleCount += 24;
			}
			
			//(direct) <- (direct) ^ (#data)
			else if (IR == XRL6)
			{		
				directAddr = ROM_Read(PC++) ^ XRL6_X1;
				IR = ROM_Read(PC++) ^ XRL6_X2;
				RAM[directAddr < 128 ? directAddr : (directAddr+128)] ^= (char)IR;
				//cycleCount += 16;
			}
			
			// MOV bit, (C)
			else if (IR == MOV17)
			{		    
				IR = ROM_Read(PC++) ^ MOV17_X;
				if(I8051_GetBit(RAM[PSW], CY) == 0x01 ) 
				{
					I8051_SetBit(&RAM[((IR & 0xF8) < 128) ? (((IR & 0xF8)>>3)+32) : (128 + (IR & 0xF8))], (IR & 0x07));
				}
				else 
				{
					I8051_ClearBit(&RAM[((IR & 0xF8) < 128) ? (((IR & 0xF8)>>3)+32) : (128 + (IR & 0xF8))], (IR & 0x07));
				}
				//cycleCount += 8;
			}
			
			//(A) <- (A) | ((Ri))
			else if ((IR&0xFE) == ORL3)
			{		
				regNum = IR & 0x01;
				RAM[ACC] |= RAM[(unsigned short)RAM[I8051_GetRegisterBank()+regNum]];
				//cycleCount += 4;
			}
			
			// MOVC (A), @A+DPTR
			else if (IR == MOVC1)
			{		    
				//((unsigned char*)&tempDPTR)[1] = RAM[DPH];
				//((unsigned char*)&tempDPTR)[0] = RAM[DPL];
				tempDPTR = ((unsigned char)RAM[DPH] << 8);
				tempDPTR |= (unsigned char)RAM[DPL];
				RAM[ACC] = ROM_Read((unsigned short)(unsigned char)RAM[ACC]+tempDPTR);
				//cycleCount += 16;
			}		
		    
			// Rotate Left Thru Carry(A)
			else if (IR == RLC)
			{		   
				rotateBit = I8051_GetBit(RAM[ACC], 7);
				RAM[ACC] = (unsigned char)RAM[ACC] << 1;		    
				if (I8051_GetBit(RAM[PSW], CY) == 0x01 ) 
				{
					I8051_SetBit(&RAM[ACC], 0);
				}
				else 
				{
					I8051_ClearBit(&RAM[ACC], 0);
				}
				if( rotateBit == 0x01 ) 
				{
					I8051_SetBit(&RAM[PSW], CY);
				}
				else 
				{
					I8051_ClearBit(&RAM[PSW], CY);
				}
				//cycleCount += 16;
			}				
			
			// CPL (bit)
			else if (IR == CPL3)
			{		
				IR = ROM_Read(PC++) ^ CPL3_X;
				if(I8051_GetBit(RAM[((IR & 0xF8) < 128) ? (((IR & 0xF8)>>3)+32) : (128 + (IR & 0xF8))], (IR & 0x07)) == 0x01) 
				{
					I8051_ClearBit(&RAM[((IR & 0xF8) < 128) ? (((IR & 0xF8)>>3)+32) : (128 + (IR & 0xF8))], (IR & 0x07));
				}
				else 
				{
					I8051_SetBit(&RAM[((IR & 0xF8) < 128) ? (((IR & 0xF8)>>3)+32) : (128 + (IR & 0xF8))], (IR & 0x07));
				}
				//cycleCount += 16;
			}
			
			// (C) <- (C) | /(bit)		  
			else if (IR == ORL8)
			{		
				IR = ROM_Read(PC++) ^ ORL8_X;
				if( !I8051_GetBit(RAM[((IR & 0xF8) < 128) ? (((IR & 0xF8)>>3)+32) : (128 + (IR & 0xF8))], (IR & 0x07)) ) 
				{
					I8051_SetBit(&RAM[PSW], CY);
				}
		  
				//cycleCount += 8;
			}
			
			//(A) <- (A) & (direct)		  
			else if (IR == ANL2)
			{		    
				IR = ROM_Read(PC++) ^ ANL2_X;
				RAM[ACC] &= RAM[IR < 128 ? IR : (IR+128)];
				//cycleCount += 8;
			}
		    
			// Rotate Right Thru Carry(A)
			else if (IR == RRC)
			{		    
				rotateBit = I8051_GetBit(RAM[ACC], 0);
				RAM[ACC] = (unsigned char)RAM[ACC] >> 1;
				if(I8051_GetBit(RAM[PSW], CY) == 0x01 ) 
				{
					I8051_SetBit(&RAM[ACC], 7);
				}
				else 
				{
					I8051_ClearBit(&RAM[ACC], 7);
				}
				if( rotateBit == 0x01 ) 
				{
					I8051_SetBit(&RAM[PSW], CY);
				}
				else 
				{
					I8051_ClearBit(&RAM[PSW], CY);
				}
				//cycleCount += 16;
			}							
		    
			// LCALL addr16
			else if (IR == LCALL)
			{		    
				//((unsigned char*)&jumpAddr)[1] = ROM[PC++];
				//((unsigned char*)&jumpAddr)[0] = ROM[PC++];
				jumpAddr = ((unsigned char)(ROM_Read(PC++) ^ LCALL_X1) << 8);
				jumpAddr |= (unsigned char)ROM_Read(PC++) ^ LCALL_X2;

				RAM[SP] = (unsigned char)RAM[SP] + 1;
				//RAM[(unsigned char)RAM[SP]]  = ((unsigned char*)&PC)[0];
				RAM[(unsigned char)RAM[SP]] = PC&0xFF;
				RAM[SP] = (unsigned char)RAM[SP] + 1;
				//RAM[(unsigned char)RAM[SP]]  = ((unsigned char*)&PC)[1];
				RAM[(unsigned char)RAM[SP]] = (PC >> 8)&0xFF;
				PC = jumpAddr;
				//cycleCount += 32;			
			}			
			
			// INC (Rn)
			else if ((IR&0xF8) == INC2)
			{		    
				regNum = IR & 0x07;
				RAM[I8051_GetRegisterBank()+regNum]++;
				//cycleCount += 8;
			}
			
			// A <- #data
			else if (IR == MOV4)
			{		    
				IR = ROM_Read(PC++) ^ MOV4_X;
				RAM[ACC] = (char)IR;
				//cycleCount += 1;
			}
		    
			// DA (A)
			else if (IR == DA)
			{
				if( (RAM[ACC] & 0x0F) > 9 || I8051_GetBit(RAM[PSW], AC) == 0x01 ) 
				{
					tempAdd = RAM[ACC] + 0x06;
					RAM[ACC] = (char)tempAdd;
					if(((tempAdd >> 8)&0xFF) != 0 ) 
					{
						I8051_SetBit(&RAM[PSW], CY);
					}
				}
				if( ((RAM[ACC] & 0xF0) >> 4) > 9 || I8051_GetBit(RAM[PSW], CY) == 0x01 ) 
				{
					tempAdd = RAM[ACC] + 0x60;
					RAM[ACC] = (char)tempAdd;
					if(((tempAdd >> 8)&0xFF) != 0 )
					{
						I8051_SetBit(&RAM[PSW], CY);
					}
				}
				//cycleCount += 12;
			}			
			
			// LJMP addr16
			else if (IR == LJMP)
			{		    
				//((unsigned char*)&jumpAddr)[1] = ROM[PC++];
				//((unsigned char*)&jumpAddr)[0] = ROM[PC++];
				jumpAddr = ((unsigned char)(ROM_Read(PC++) ^ LJMP_X1) << 8);
				jumpAddr |= (unsigned char)ROM_Read(PC++) ^ LJMP_X2;

				PC = jumpAddr;
				//cycleCount += 16;
			}		
		    
			// CJNE (A), (direct), (rel)
			else if (IR == CJNE1)
			{		    
				IR = ROM_Read(PC++) ^ CJNE1_X1;
				directAddr = IR;
				if( RAM[ACC] != RAM[IR < 128 ? IR : (IR+128)] ) 
				{
					IR = ROM_Read(PC++) ^ CJNE1_X2;
					PC += (char)IR;
				}
				else 
				{
					PC++;
				}
				if( (unsigned char)RAM[ACC] < (unsigned char)RAM[directAddr < 128 ? directAddr: (directAddr+128)] ) 
				{
					I8051_SetBit(&RAM[PSW], CY);
				}
				else 
				{
					I8051_ClearBit(&RAM[PSW], CY);
				}
				//cycleCount += 16;
			}
			
			// DEC ((Ri))
			else if ((IR&0xFE) == DEC4)
			{		    
				regNum = IR & 0x01;
				RAM[(unsigned short)RAM[I8051_GetRegisterBank()+regNum]]--;
				//cycleCount += 7;
			}	
			
			// CLR (C)
			else if (IR == CLR2)
			{		
				I8051_ClearBit(&RAM[PSW], CY);
				//cycleCount += 24;
			}
		    
			else if (IR == CJNE2)
			{		   
				IR = ROM_Read(PC++) ^ CJNE2_X1;
				directAddr = IR;
				if( RAM[ACC] != (char)IR ) 
				{
					IR = ROM_Read(PC++) ^ CJNE2_X2;
					PC += (char)IR;
				}
				else 
				{
					PC++;
				}
				if( (unsigned char)RAM[ACC] < (unsigned char)directAddr ) 
				{
					I8051_SetBit(&RAM[PSW], CY);
				}
				else 
				{
					I8051_ClearBit(&RAM[PSW], CY);
				}
				//cycleCount += 32;
			}					
			
			// ACALL addr11
			else if ((IR&0x1F) == ACALL)
			{		  
				//((unsigned char*)&jumpAddr)[0] = ROM[PC++];
				//((unsigned char*)&jumpAddr)[1] = (PC & 0xF800) | ((IR & 0xE0) >> 5);
		    
				jumpAddr = (unsigned char)ROM_Read(PC++) ^ ACALL_X;
				jumpAddr |= (((PC&0xF800) | ((IR & 0xE0) >> 5)) << 8);
				
				RAM[SP] = (unsigned char)RAM[SP] + 1;
				//RAM[(unsigned char)RAM[SP]]  = ((unsigned char*)&PC)[0];
				RAM[(unsigned char)RAM[SP]] = PC&0xFF;
				RAM[SP] = (unsigned char)RAM[SP] + 1;
				//RAM[(unsigned char)RAM[SP]]  = ((unsigned char*)&PC)[1];
				RAM[(unsigned char)RAM[SP]]  = (PC >> 8)&0xFF;
				PC = jumpAddr;
				//cycleCount += 8;
			}			
			
			// XCHD (A), ((Ri))
			else if ((IR&0xFE) == XCHD)
			{		    
				regNum = IR & 0x01;
				temp = RAM[ACC] & 0x0F;
				RAM[ACC] = (RAM[ACC] & 0xF0) | (RAM[(unsigned short)RAM[I8051_GetRegisterBank()+regNum]] & 0x0F);
				RAM[(unsigned short)RAM[I8051_GetRegisterBank()+regNum]] = (RAM[(unsigned short)RAM[I8051_GetRegisterBank()+regNum]] & 0xF0 ) | temp;
				//cycleCount += 12;
			}			
		    
			// DEC (Rn)
			else if ((IR&0xF8) == DEC2)
			{		  
				regNum = IR & 0x07;
				RAM[I8051_GetRegisterBank()+regNum]--;
				//cycleCount += 5;
			}			
			
			// SJMP (rel)
			else if (IR == SJMP)
			{		    
				IR = ROM_Read(PC++) ^ SJMP_X;
				PC += (char)IR;
				//cycleCount += 4;
			}
		    
			// DIV (A)/(B)
			else if (IR == DIV)
			{		    
				if( RAM[B] == 0x00 ) 
				{
					I8051_SetBit(&RAM[PSW], OV);
				}
				else 
				{
					I8051_ClearBit(&RAM[PSW], OV);
					tempACC = RAM[ACC];
					RAM[ACC] = tempACC/RAM[B];
					RAM[B] = tempACC%RAM[B];
				}		    
				I8051_ClearBit(&RAM[PSW], CY);
				//cycleCount += 24;
			}
			
			// JNZ (rel)
			else if (IR == JNZ)
			{
		    
				if( RAM[ACC] != 0x00 ) 
				{
					IR = ROM_Read(PC++) ^ JNZ_X;
					PC += (char)IR;
				}
				else 
				{
					PC++;
				}
				//cycleCount += 16;
			}
			
			// XCH (A), (Rn)
			else if ((IR&0xF8) == XCH1)
			{		    
				regNum = IR & 0x07;
				temp = RAM[ACC];
				RAM[ACC] = RAM[I8051_GetRegisterBank()+regNum];
				RAM[I8051_GetRegisterBank()+regNum] = temp;
				//cycleCount += 8;
			}	
		    
			// INC (direct)
			else if (IR == INC3)
			{		    
				IR = ROM_Read(PC++) ^ INC3_X;
				RAM[IR < 128 ? IR : (IR+128)]++;
				//cycleCount += 20;
			}			
			
			// MOVC (A), @A+PC
			else if (IR == MOVC2)
			{		    
				RAM[ACC] = ROM_Read((unsigned char)RAM[ACC]+PC);
				//cycleCount += 36;
			}
			
			// JC (rel)
			else if (IR == JC)
			{
		    
				if(I8051_GetBit(RAM[PSW], CY) == 0x01 ) 
				{
					IR = ROM_Read(PC++) ^ JC_X;
					PC += (char)IR;
				}
				else 
				{
					PC++;
				}
				//cycleCount += 16;
			}
			
			// XCH (A), (direct)
			else if (IR == XCH2)
			{		    
				IR = ROM_Read(PC++) ^ XCH2_X;
				temp = RAM[ACC];
				RAM[ACC] = RAM[IR < 128 ? IR : (IR+128)];
				RAM[IR < 128 ? IR : (IR+128)] = temp;
				//cycleCount += 8;
			}	
			
			// DEC (A)
			else if (IR == DEC1)
			{		    
				RAM[ACC]--;
				//cycleCount += 8;
			}
			
			// Rn <- A
			else if ((IR&0xF8) == MOV5)
			{		    
				regNum = IR & 0x07;
				RAM[I8051_GetRegisterBank()+regNum] = RAM[ACC];
				//cycleCount += 36;
			}
			
			// JNB (bit), (rel)
			else if (IR == JNB)
			{
		    
				IR = ROM_Read(PC++) ^ JNB_X1;
				if(I8051_GetBit(RAM[((IR & 0xF8) < 128) ? (((IR & 0xF8)>>3)+32) : (128 + (IR & 0xF8))], (IR & 0x07)) != 0x01 ) 
				{
					IR = ROM_Read(PC++) ^ JNB_X2;
					PC += (char)IR;
				}
				else 
				{
					PC++;
				}
				//cycleCount += 16;
			}			
			
			// Swap nibbles(A)
			else if (IR == SWAP)
			{		    
				lowerNibble = RAM[ACC] & 0x0F;
				RAM[ACC] = (RAM[ACC] >> 4) & 0x0F;
				RAM[ACC] |= ((lowerNibble << 4) & 0xF0);
				//cycleCount += 8;
			}
		    
			// NOP
			/*else if (IR == NOP)
			{		    
				// no code
				//cycleCount += 12;
			}*/
		    
			// DJNZ (Rn), (rel)  
			else if ((IR&0xF8) == DJNZ1)
			{		    
				regNum = IR & 0x07;
		    
				RAM[I8051_GetRegisterBank()+regNum] = (unsigned char)RAM[I8051_GetRegisterBank()+regNum] - 1;
				if( RAM[I8051_GetRegisterBank()+regNum] != 0x00 ) 
				{
					IR = ROM_Read(PC++) ^ DJNZ1_X;
					PC += (char)IR;					
				}
				else 
				{
					PC++;
				}
				//cycleCount += 16;
			}			
			
			// ADDC A, (direct)
			else if (IR == ADDC2)
			{
		    
				carry3 = 0;
				carry6 = 0;
				carry7 = 0;
				IR = ROM_Read(PC++) ^ ADDC2_X;

				tempAdd = (RAM[ACC] & 0x0F) + (RAM[IR <128 ? IR : (IR+128)] & 0x0F) + (char)I8051_GetBit(RAM[PSW], CY);
				if( (tempAdd & 0x0010) == 0x0010 ) carry3 = 1;
				tempAdd += (RAM[ACC] & 0x70) + (RAM[IR <128 ? IR : (IR+128)] & 0x70);
				if( (tempAdd & 0x0080) == 0x0080 ) carry6 = 1;
				tempAdd += (RAM[ACC] & 0x80) + (RAM[IR <128 ? IR : (IR+128)] & 0x80);
				if( (tempAdd & 0x0100) == 0x0100 ) carry7 = 1;
				RAM[ACC] = (unsigned char)(tempAdd & 0x00FF);
				if( carry3 ) I8051_SetBit(&RAM[PSW], AC);
				else I8051_ClearBit(&RAM[PSW], AC);
				if( carry7 ) I8051_SetBit(&RAM[PSW], CY);
				else I8051_ClearBit(&RAM[PSW], CY);
				if( (carry6 && !carry7) || (!carry6 && carry7) ) 
					I8051_SetBit(&RAM[PSW], OV);
				else I8051_ClearBit(&RAM[PSW], OV);
				//cycleCount += 8;
			}			
			
			// CJNE ((Ri)), (#data), (rel)
			else if ((IR&0xFE) == CJNE4)
			{		    
				regNum = IR & 0x01;
				IR = ROM_Read(PC++) ^ CJNE4_X1;
				directAddr = IR;
				if( RAM[(unsigned short)RAM[I8051_GetRegisterBank()+regNum]] != (char)IR ) 
				{
					IR = ROM_Read(PC++) ^ CJNE4_X2;
					PC += (char)IR;
				}
				else 
				{
					PC++;
				}
		    
				if( (unsigned char)RAM[(unsigned short)RAM[I8051_GetRegisterBank()+regNum]] < (unsigned char)directAddr ) 
				{
					I8051_SetBit(&RAM[PSW], CY);
				}
				else 
				{
					I8051_ClearBit(&RAM[PSW], CY);
				}
				//cycleCount += 12;
			}			
		    
			// MUL (A), (B)
			else if (IR == MUL)
			{		    
				tempProduct = (unsigned char)RAM[ACC] * (unsigned char)RAM[B];
				if( tempProduct > 255 ) 
				{
					I8051_SetBit(&RAM[PSW], OV);
				}
				else 
				{
					I8051_ClearBit(&RAM[PSW], OV);
				}
				I8051_ClearBit(&RAM[PSW], CY);
				//RAM[ACC] = ((unsigned char*)&tempProduct)[0];
				//RAM[B] = ((unsigned char*)&tempProduct)[1];
				RAM[ACC] = tempProduct&0xFF;
				RAM[B] = (tempProduct>>8)&0xFF;
				//cycleCount += 16;
			}
		    
			// POP (direct)
			else if (IR == POP)
			{		    
				IR = ROM_Read(PC++) ^ POP_X;
				popData = RAM[(unsigned char)RAM[SP]];
				RAM[SP] = (unsigned char)RAM[SP] - 1;
				RAM[IR < 128 ? IR : (IR+128)] = popData;
				//cycleCount += 8;
			}
			
			// MOVX (A), @RI
			else if ((IR&0xFE) == MOVX1)
			{
				regNum = IR & 0x01;
				RAM[ACC] = XRAM_Read(RAM[I8051_GetRegisterBank()+regNum]);
				//cycleCount += 24;
			}
			
			// ADDC A, ((Ri))
			else if ((IR&0xFE) == ADDC3)
			{
		    
				carry3 = 0;
				carry6 = 0;
				carry7 = 0;
				regNum = IR & 0x01;
				tempAdd = (RAM[ACC] & 0x0F) + (RAM[(unsigned short)RAM[I8051_GetRegisterBank()+regNum]] & 0x0F) + (char)I8051_GetBit(RAM[PSW], CY);
				if( (tempAdd & 0x0010) == 0x0010 ) carry3 = 1;
				tempAdd += (RAM[ACC] & 0x70) + (RAM[(unsigned short)RAM[I8051_GetRegisterBank()+regNum]] & 0x70);
				if( (tempAdd & 0x0080) == 0x0080 ) carry6 = 1;
				tempAdd += (RAM[ACC] & 0x80) + (RAM[(unsigned short)RAM[I8051_GetRegisterBank()+regNum]] & 0x80);
				if( (tempAdd & 0x0100) == 0x0100 ) carry7 = 1;
				RAM[ACC] = (unsigned char)(tempAdd & 0x00FF);
				if( carry3 ) I8051_SetBit(&RAM[PSW], AC);
				else I8051_ClearBit(&RAM[PSW], AC);
				if( carry7 ) I8051_SetBit(&RAM[PSW], CY);
				else I8051_ClearBit(&RAM[PSW], CY);
				if( (carry6 && !carry7) || (!carry6 && carry7) ) 
					I8051_SetBit(&RAM[PSW], OV);
				else I8051_ClearBit(&RAM[PSW], OV);
				//cycleCount += 24;
			}
			
			// INC ((Ri))
			else if ((IR&0xFE) == INC4)
			{		    
				regNum = IR & 0x01;
				RAM[(unsigned short)RAM[I8051_GetRegisterBank()+regNum]]++;
				//cycleCount += 16;
			}
			
			// JZ (rel)
			else if (IR == JZ)
			{
		    
				if( RAM[ACC] == 0x00 ) 
				{
					IR = ROM_Read(PC++) ^ JZ_X;
					PC += (char)IR;
				}
				else 
				{
					PC++;
				}
				//cycleCount += 8;
			}
			
			// CPL (A)
			else if (IR == CPL1)
			{		
				RAM[ACC] = ~RAM[ACC];
				//cycleCount += 16;
			}
			
			// INC (DPTR)
			else if (IR == INC5)
			{		    
				//((unsigned char*)&tempDPTR)[1] = RAM[DPH];
				//((unsigned char*)&tempDPTR)[0] = RAM[DPL];
				tempDPTR = ((unsigned char)RAM[DPH] << 8);
				tempDPTR |= (unsigned char)RAM[DPL];
				tempDPTR++;
				//RAM[DPH] = ((unsigned char*)&tempDPTR)[1];
				//RAM[DPL] = ((unsigned char*)&tempDPTR)[0];
				RAM[DPH] = (tempDPTR >> 8)&0xFF;
				RAM[DPL] = tempDPTR&0xFF;
				//cycleCount += 16;
			}
			
			// A <- @Ri
			else if ((IR&0xFE) == MOV3)
			{		    
				regNum = IR & 0x01;
				RAM[ACC] = RAM[(unsigned short)RAM[I8051_GetRegisterBank()+regNum]];
				//cycleCount += 24;
			}
			
			// DEC (direct)
			else if (IR == DEC3)
			{		    
				IR = ROM_Read(PC++) ^ DEC3_X;
				RAM[IR < 128 ? IR : (IR+128)]--;
				//cycleCount += 8;
			}
		    
			// JMP @A+DPTR
			else if (IR == JMP)
			{		   
				//((unsigned char*)&tempDPTR)[1] = RAM[DPH];
				//((unsigned char*)&tempDPTR)[0] = RAM[DPL];
				tempDPTR = ((unsigned char)RAM[DPH] << 8);
				tempDPTR |= (unsigned char)RAM[DPL];
				tempDPTR += (unsigned char)RAM[ACC];
				PC = (unsigned short)tempDPTR;
				//cycleCount += 16;
			}
		    
			// Return
			else if (IR == RET)
			{		    
				//((unsigned char*)&PC)[1] = RAM[(unsigned char)RAM[SP]];
				PC = ((unsigned char)RAM[(unsigned char)RAM[SP]] << 8);
				RAM[SP] = (unsigned char)RAM[SP] - 1;
				//((unsigned char*)&PC)[0] = RAM[(unsigned char)RAM[SP]];
				PC |= (unsigned char)RAM[(unsigned char)RAM[SP]];
				RAM[SP] = (unsigned char)RAM[SP] - 1;
				//cycleCount += 8;
			}			
			
			// (C) <- (C) & (bit)
			else if (IR == ANL7)
			{		
				IR = ROM_Read(PC++) ^ ANL7_X;
				if( !I8051_GetBit(RAM[((IR & 0xF8) < 128) ? (((IR & 0xF8)>>3)+32) : (128 + (IR & 0xF8))], (IR & 0x07)) ) 
				{
					I8051_ClearBit(&RAM[PSW], CY);
				}
		    
				//cycleCount += 8;
			}	
			
			// JBC (bit), (rel)
			else if (IR == JBC)
			{
		    
				IR = ROM_Read(PC++) ^ JBC_X1;
				if(I8051_GetBit(RAM[((IR & 0xF8) < 128) ? (((IR & 0xF8)>>3)+32) : (128 + (IR & 0xF8))], (IR & 0x07)) == 0x01 ) 
				{
					I8051_ClearBit(&RAM[((IR & 0xF8) < 128) ? (((IR & 0xF8)>>3)+32) : (128 + (IR & 0xF8))], (IR & 0x07));
					IR = ROM_Read(PC++) ^ JBC_X2;
					PC += (char)IR;
				}
				else 
				{
					PC++;
				}
				//cycleCount += 8;
			}
			
			// DJNZ (direct), (rel)  
			else if (IR == DJNZ2)
			{		    
				//regNum = IR & 0x07;
				IR = ROM_Read(PC++) ^ DJNZ2_X1;
				RAM[IR < 128 ? IR : (IR+128)] = (unsigned char)RAM[IR < 128 ? IR : (IR+128)] - 1;
				if( RAM[IR < 128 ? IR : (IR+128)] != 0x00 ) 
				{
					IR = ROM_Read(PC++) ^ DJNZ2_X2;
					PC += (char)IR;					
				}
				else 
				{
					PC++;
				}
				//cycleCount += 12;
			}
			
			// Ri <- direct
			else if ((IR&0xFE) == MOV14)
			{		    
				regNum = IR & 0x01;
				IR = ROM_Read(PC++) ^ MOV14_X;
				RAM[(unsigned short)RAM[I8051_GetRegisterBank()+regNum]] = RAM[(IR<128) ? IR : (IR+128)];
				//cycleCount += 23;
			}
			
			// XCH (A), ((Ri))
			else if ((IR&0xFE) == XCH3)
			{		    
				regNum = IR & 0x01;
				temp = RAM[ACC];
				RAM[ACC] = RAM[(unsigned short)RAM[I8051_GetRegisterBank()+regNum]];
				RAM[(unsigned short)RAM[I8051_GetRegisterBank()+regNum]] = temp;
				//cycleCount += 12;
			}	
		    
			// A <- Rn
			else if ((IR&0xF8) == MOV1)
			{		    
				regNum = IR & 0x07;
				RAM[ACC] = RAM[I8051_GetRegisterBank()+regNum];
				//cycleCount += 24;
			}
		    
			// A <- direct
			else if (IR == MOV2)
			{		    
				IR = ROM_Read(PC++) ^ MOV2_X;
				RAM[ACC] = RAM[IR < 128 ? IR : (IR + 128)];
				//cycleCount += 8;
			}			
		    
			// Rn <- direct
			else if ((IR&0xF8) == MOV6)
			{		    
				regNum = IR & 0x07;
				IR = ROM_Read(PC++) ^ MOV6_X;
				RAM[I8051_GetRegisterBank()+regNum] = RAM[ (IR < 128) ? IR : (IR + 128)]; 
				//cycleCount += 20;
			}
		    
			// Rn <- #data
			else if ((IR&0xF8) == MOV7)
			{		    
				regNum = IR & 0x07;
				IR = ROM_Read(PC++) ^ MOV7_X;
				RAM[I8051_GetRegisterBank()+regNum] = (char)IR;
				//cycleCount += 11;
			}
			
			// INC (A)
			else if (IR == INC1)
			{		    
				RAM[ACC]++;
				//cycleCount += 8;
			}	
			
			// JB (bit), (rel)
			else if (IR == JB)
			{		    
				IR = ROM_Read(PC++) ^ JB_X1;
				if(I8051_GetBit(RAM[((IR & 0xF8) < 128) ? (((IR & 0xF8)>>3)+32) : (128 + (IR & 0xF8))], (IR & 0x07)) == 0x01 ) 
				{
					IR = ROM_Read(PC++) ^ JB_X2;
					PC += (char)IR;
				}
				else 
				{
					PC++;
				}
				//cycleCount += 36;
			}			
		    
			// direct <- direct
			else if (IR == MOV10)
			{		    
				directAddr = ROM_Read(PC++) ^ MOV10_X1;
				IR = ROM_Read(PC++) ^ MOV10_X2;
				RAM[(IR<128) ? IR : (IR+128)] = RAM[(directAddr < 128) ? directAddr : (directAddr+128)];
				//cycleCount += 12;
			}
			
			// AJMP addr11
			else if ((IR&0x1F) == AJMP)
			{		    
				//((unsigned char*)&jumpAddr)[0] = ROM[PC++];
				//((unsigned char*)&jumpAddr)[1] = (PC & 0xF800) | ((IR & 0xE0) >> 5);
				jumpAddr = (unsigned char)ROM_Read(PC++) ^ AJMP_X;
				jumpAddr |= (((PC & 0xF800) | ((IR & 0xE0) >> 5)) << 8);

				PC = jumpAddr;
				//cycleCount += 4;
			}
		    
			// direct <- #data
			else if (IR == MOV12)
			{		    
				directAddr = ROM_Read(PC++) ^ MOV12_X1;
				IR = ROM_Read(PC++) ^ MOV12_X2;
				RAM[(directAddr<128) ? directAddr : (directAddr+128)] = (char)IR;
				//cycleCount += 20;
			}			
		    
			// @Ri, #data
			else if ((IR&0xFE) == MOV15)
			{		    
				regNum = IR & 0x01;
				IR = ROM_Read(PC++) ^ MOV15_X;
				RAM[(unsigned short)RAM[I8051_GetRegisterBank()+regNum]] = (char)IR;
				//cycleCount += 12;
			}
			
			// PUSH (direct)
			else if (IR == PUSH)
			{		    
				IR = ROM_Read(PC++) ^ PUSH_X;
				RAM[SP] = (unsigned char)RAM[SP] + 1;
				RAM[(unsigned char)RAM[SP]] = RAM[IR < 128 ? IR : (IR+128)];
				//cycleCount += 8;
			}
		    
			// MOV (C), bit
			else if (IR == MOV16)
			{		    
				IR = ROM_Read(PC++) ^ MOV16_X;
				if(I8051_GetBit(RAM[((IR & 0xF8) < 128) ? (((IR & 0xF8)>>3)+32) : (128 + (IR & 0xF8))], (IR & 0x07)) == 0x01 ) 
				{
					I8051_SetBit(&RAM[PSW], CY);
				}
				else 
				{
					I8051_ClearBit(&RAM[PSW], CY);
				}
				//cycleCount += 16;
			}
			
			// direct <- Rn
			else if ((IR&0xF8) == MOV9)
			{		    
				regNum = IR & 0x07;
				IR = ROM_Read(PC++) ^ MOV9_X;
				RAM[(IR<128) ? IR : (IR+128)] = RAM[I8051_GetRegisterBank()+regNum];
				//cycleCount += 8;
			}
			
			// JNC (rel)
			else if (IR == JNC)
			{
		    
				if(I8051_GetBit(RAM[PSW], CY) == 0x00 ) 
				{
					IR = ROM_Read(PC++) ^ JNC_X;
					PC += (char)IR;
				}
				else 
				{
					PC++;
				}
				//cycleCount += 16;
			}
		    
			// MOV DPTR, data16
			else if (IR == MOV18)
			{		    
				RAM[DPH] = ROM_Read(PC++) ^ MOV18_X1;
				RAM[DPL] = ROM_Read(PC++) ^ MOV18_X2;
				//cycleCount += 12;
			}			
		    
			// MOVX @RI, A
			else if ((IR&0xFE) == MOVX3)
			{
				regNum = IR & 0x01;
				XRAM_Write(RAM[I8051_GetRegisterBank()+regNum], RAM[ACC]);
				//cycleCount += 16;
			}
		  
			// MOVX @DPTR, A
			else if (IR ==  MOVX4)
			{
				//((unsigned char*)&tempDPTR)[1] = RAM[DPH];
				//((unsigned char*)&tempDPTR)[0] = RAM[DPL];
				tempDPTR = ((unsigned char)RAM[DPH] << 8);
				tempDPTR |= (unsigned char)RAM[DPL];

				XRAM_Write(tempDPTR, RAM[ACC]);
				//cycleCount += 24;
			}
			
			//(direct) <- (direct) | (#data)
			else if (IR == ORL6)
			{		
				directAddr = ROM_Read(PC++) ^  ORL6_X1;
				IR = ROM_Read(PC++) ^ ORL6_X2;
				RAM[directAddr < 128 ? directAddr : (directAddr+128)] |= (char)IR;
				//cycleCount += 12;
			}

			// ADD A, (Rn)
			else if ((IR&0xF8) == ADD1)
			{		    

				carry3 = 0;
				carry6 = 0;
				carry7 = 0;
				regNum = IR & 0x07;

				tempAdd = (RAM[ACC] & 0x0F) + (RAM[I8051_GetRegisterBank()+regNum] & 0x0F);
				if( (tempAdd & 0x0010) == 0x0010 ) carry3 = 1;
				tempAdd += ((RAM[ACC] & 0x70) + (RAM[I8051_GetRegisterBank()+regNum] & 0x70));
				if( (tempAdd & 0x0080) == 0x0080 ) carry6 = 1;
				tempAdd += ((RAM[ACC] & 0x80) + (RAM[I8051_GetRegisterBank()+regNum] & 0x80));
				if( (tempAdd & 0x0100) == 0x0100 ) carry7 = 1;
				RAM[ACC] = tempAdd;
				if( carry3 ) I8051_SetBit(&RAM[PSW], AC);
				else I8051_ClearBit(&RAM[PSW], AC);
				if( carry7 ) I8051_SetBit(&RAM[PSW], CY);
				else I8051_ClearBit(&RAM[PSW], CY);
				if( (carry6 && !carry7) || (!carry6 && carry7) ) 
					I8051_SetBit(&RAM[PSW], OV);
				else I8051_ClearBit(&RAM[PSW], OV);
				//cycleCount += 16;
			}
			
			// direct <- ((Ri))
			else if ((IR&0xFE) == MOV11)
			{		    
				regNum = IR & 0x01;
				IR = ROM_Read(PC++) ^ MOV11_X;
				RAM[(IR <128) ? IR : (IR+128)] = RAM[(unsigned short)RAM[I8051_GetRegisterBank()+regNum]];
				//cycleCount += 16;
			}		
		    
			// ADD A, (direct)
			else if (IR == ADD2)
			{		    
				carry3 = 0;
				carry6 = 0;
				carry7 = 0;
				IR = ROM_Read(PC++) ^ ADD2_X;


				tempAdd = (RAM[ACC] & 0x0F) + (RAM[IR <128 ? IR : (IR+128)] & 0x0F);
				if( (tempAdd & 0x0010) == 0x0010 ) carry3 = 1;
				tempAdd += ((RAM[ACC] & 0x70) + (RAM[IR <128 ? IR : (IR+128)] & 0x70));
				if( (tempAdd & 0x0080) == 0x0080 ) carry6 = 1;
				tempAdd += ((RAM[ACC] & 0x80) + (RAM[IR <128 ? IR : (IR+128)] & 0x80));
				if( (tempAdd & 0x0100) == 0x0100 ) carry7 = 1;
				RAM[ACC] = tempAdd;
				if( carry3 ) I8051_SetBit(&RAM[PSW], AC);
				else I8051_ClearBit(&RAM[PSW], AC);
				if( carry7 ) I8051_SetBit(&RAM[PSW], CY);
				else I8051_ClearBit(&RAM[PSW], CY);
				if( (carry6 && !carry7) || (!carry6 && carry7) ) 
					I8051_SetBit(&RAM[PSW], OV);
				else I8051_ClearBit(&RAM[PSW], OV);
				//cycleCount += 8;
			}			
			
			// direct <- A
			else if (IR == MOV8)
			{		    
				IR = ROM_Read(PC++) ^ MOV8_X;
				RAM[(IR < 128) ? IR : (IR+128)] = RAM[ACC];
				//cycleCount += 4;
			}
			
			// CLR (A)
			else if (IR == CLR1)
			{		
				RAM[ACC] = 0x00;
				//cycleCount += 8;
			}
			
			// MOVX (A), @DPTR
			else if (IR == MOVX2)
			{
				//((unsigned char*)&tempDPTR)[1] = RAM[DPH];
				//((unsigned char*)&tempDPTR)[0] = RAM[DPL];
				tempDPTR = ((unsigned char)RAM[DPH] << 8);
				tempDPTR |= (unsigned char)RAM[DPL];

				RAM[ACC] = XRAM_Read(tempDPTR);
				//cycleCount += 7;
			}
		    
			// ADD A, (#data)
			else if (IR == ADD4)
			{		    
				carry3 = 0;
				carry6 = 0;
				carry7 = 0;
				IR = ROM_Read(PC++) ^ ADD4_X;

				tempAdd = (RAM[ACC] & 0x0F) + ((char)IR & 0x0F);
				if( (tempAdd & 0x0010) == 0x0010 ) carry3 = 1;
				tempAdd += ((RAM[ACC] & 0x70) + ((char)IR & 0x70));
				if( (tempAdd & 0x0080) == 0x0080 ) carry6 = 1;
				tempAdd += ((RAM[ACC] & 0x80) + ((char)IR & 0x80));
				if( (tempAdd & 0x0100) == 0x0100 ) carry7 = 1;
				RAM[ACC] = tempAdd;
				if( carry3 ) I8051_SetBit(&RAM[PSW], AC);
				else I8051_ClearBit(&RAM[PSW], AC);
				if( carry7 ) I8051_SetBit(&RAM[PSW], CY);
				else I8051_ClearBit(&RAM[PSW], CY);
				if( (carry6 && !carry7) || (!carry6 && carry7) ) 
					I8051_SetBit(&RAM[PSW], OV);
				else I8051_ClearBit(&RAM[PSW], OV);
				//cycleCount += 8;
			}		
		    
			// ADDC A, (Rn)
			else if ((IR&0xF8) == ADDC1)
			{
		    
				carry3 = 0;
				carry6 = 0;
				carry7 = 0;
				regNum = IR & 0x07;
				tempAdd = (RAM[ACC] & 0x0F) + (RAM[I8051_GetRegisterBank()+regNum] & 0x0F) + (char)I8051_GetBit(RAM[PSW], CY);
				if( (tempAdd & 0x0010) == 0x0010 ) carry3 = 1;
				tempAdd += (RAM[ACC] & 0x70) + (RAM[I8051_GetRegisterBank()+regNum] & 0x70);
				if( (tempAdd & 0x0080) == 0x0080 ) carry6 = 1;
				tempAdd += (RAM[ACC] & 0x80) + (RAM[I8051_GetRegisterBank()+regNum] & 0x80);
				if( (tempAdd & 0x0100) == 0x0100 ) carry7 = 1;
				RAM[ACC] = (unsigned char)(tempAdd & 0x00FF);
				if( carry3 ) I8051_SetBit(&RAM[PSW], AC);
				else I8051_ClearBit(&RAM[PSW], AC);
				if( carry7 ) I8051_SetBit(&RAM[PSW], CY);
				else I8051_ClearBit(&RAM[PSW], CY);
				if( (carry6 && !carry7) || (!carry6 && carry7) ) 
					I8051_SetBit(&RAM[PSW], OV);
				else I8051_ClearBit(&RAM[PSW], OV);
				//cycleCount += 16;
			}			
		    
			// ADDC A, (#data)
			else if (IR == ADDC4)
			{		    
				carry3 = 0;
				carry6 = 0;
				carry7 = 0;
				IR = ROM_Read(PC++) ^ ADDC4_X;

				tempAdd = (RAM[ACC] & 0x0F) + (IR & 0x0F) + I8051_GetBit(RAM[PSW], CY);
				if( (tempAdd & 0x0010) == 0x0010 ) carry3 = 1;
				tempAdd += ((RAM[ACC] & 0x70) + ((char)IR & 0x70));
				if( (tempAdd & 0x0080) == 0x0080 ) carry6 = 1;
				tempAdd += ((RAM[ACC] & 0x80) + ((char)IR & 0x80));
				if( (tempAdd & 0x0100) == 0x0100 ) carry7 = 1;
				RAM[ACC] = (unsigned char)(tempAdd & 0x00FF);
				if( carry3 ) I8051_SetBit(&RAM[PSW], AC);
				else I8051_ClearBit(&RAM[PSW], AC);
				if( carry7 ) I8051_SetBit(&RAM[PSW], CY);
				else I8051_ClearBit(&RAM[PSW], CY);
				if( (carry6 && !carry7) || (!carry6 && carry7) ) 
					I8051_SetBit(&RAM[PSW], OV);
				else I8051_ClearBit(&RAM[PSW], OV);
				//cycleCount += 12;		  
			}
		    
			// SUBB (A), (Rn)
			else if ((IR&0xF8) == SUBB1)
			{		    
		 
				borrow3 = 0;
				borrow6 = 0;
				borrow7 = 0;
				regNum = IR & 0x07;
		  
				if( (unsigned char)(RAM[ACC] & 0x0F) < (unsigned char)((RAM[I8051_GetRegisterBank()+regNum] & 0x0F) + (char)I8051_GetBit(RAM[PSW], CY)) ) 
				{
					borrow3 = 1;
				} 
				if( (unsigned char)(RAM[ACC] & 0x7F) < (unsigned char)((RAM[I8051_GetRegisterBank()+regNum] & 0x7F) + (char)I8051_GetBit(RAM[PSW], CY)) ) 
				{
					borrow6 = 1;
				}
				if( (unsigned short)(unsigned char)RAM[ACC] < ((unsigned short)(unsigned char)RAM[I8051_GetRegisterBank()+regNum] + (unsigned short)I8051_GetBit(RAM[PSW], CY)) )
				{
					borrow7 = 1;
				}
				RAM[ACC] = (unsigned short)(unsigned char)RAM[ACC] - ((unsigned short)(unsigned char)RAM[I8051_GetRegisterBank()+regNum] + (unsigned short)I8051_GetBit(RAM[PSW], CY));
				if( borrow3 ) I8051_SetBit(&RAM[PSW], AC);
				else I8051_ClearBit(&RAM[PSW], AC);
				if( borrow7 ) I8051_SetBit(&RAM[PSW], CY);
				else I8051_ClearBit(&RAM[PSW], CY);
				if( (borrow6 && !borrow7) || (!borrow6 && borrow7) ) 
					I8051_SetBit(&RAM[PSW], OV);
				else I8051_ClearBit(&RAM[PSW], OV);
				//cycleCount += 16;
			}
		    
			// SUBB (A), direct
			else if (IR == SUBB2)
			{
		    
				borrow3 = 0;
				borrow6 = 0;
				borrow7 = 0;
				IR = ROM_Read(PC++) ^ SUBB2_X;

				if( (unsigned char)(RAM[ACC] & 0x0F) < (unsigned char)((RAM[IR <128 ? IR : (IR+128)] & 0x0F) + (char)I8051_GetBit(RAM[PSW], CY)) ) 
				{
					borrow3 = 1;
				}
				if( (unsigned char)(RAM[ACC] & 0x7F) < (unsigned char)((RAM[IR <128 ? IR : (IR+128)] & 0x7F) + (char)I8051_GetBit(RAM[PSW], CY)) ) 
				{
					borrow6 = 1;
				}
				if( (unsigned short)(unsigned char)RAM[ACC] < ((unsigned short)(unsigned char)RAM[IR <128 ? IR : (IR+128)] + (unsigned short)I8051_GetBit(RAM[PSW], CY)) ) 
				{
					borrow7 = 1;
				}
				RAM[ACC] = (unsigned short)(unsigned char)RAM[ACC] - ((unsigned short)RAM[IR <128 ? IR : (IR+128)] + (unsigned short)I8051_GetBit(RAM[PSW], CY));
				if( borrow3 ) I8051_SetBit(&RAM[PSW], AC);
				else I8051_ClearBit(&RAM[PSW], AC);
				if( borrow7 ) I8051_SetBit(&RAM[PSW], CY);
				else I8051_ClearBit(&RAM[PSW], CY);
				if( (borrow6 && !borrow7) || (!borrow6 && borrow7) ) 
					I8051_SetBit(&RAM[PSW], OV);
				else I8051_ClearBit(&RAM[PSW], OV);
				//cycleCount += 20;
			}
			
			//(A) <- (A) ^ (#data)
			else if (IR == XRL4)
			{		
				IR = ROM_Read(PC++) ^ XRL4_X;
				RAM[ACC] ^= (char)IR;
				//cycleCount += 16;
			}
		    
			// SUBB (A), ((Ri))
			else if ((IR&0xFE) == SUBB3)
			{
		    
				borrow3 = 0;
				borrow6 = 0;
				borrow7 = 0;
				regNum = IR & 0x01;

				if( (unsigned char)(RAM[ACC] & 0x0F) < (unsigned char)((RAM[(unsigned short)RAM[I8051_GetRegisterBank()+regNum]] & 0x0F) + (char)I8051_GetBit(RAM[PSW], CY)) ) 
				{
					borrow3 = 1;
				}
				if( (unsigned char)(RAM[ACC] & 0x7F) < (unsigned char)((RAM[(unsigned short)RAM[I8051_GetRegisterBank()+regNum]] & 0x7F) + (char)I8051_GetBit(RAM[PSW], CY)) )
				{
					borrow6 = 1;
				}
				if( (unsigned short)(unsigned char)RAM[ACC] < ((unsigned short)(unsigned char)RAM[(unsigned short)RAM[I8051_GetRegisterBank()+regNum]] + (unsigned short)I8051_GetBit(RAM[PSW], CY)) ) 
				{
					borrow7 = 1;
				}
				RAM[ACC] = (unsigned short)(unsigned char)RAM[ACC] - ((unsigned short)(unsigned char)RAM[(unsigned short)RAM[I8051_GetRegisterBank()+regNum]] + (unsigned short)I8051_GetBit(RAM[PSW], CY));
				if( borrow3 ) I8051_SetBit(&RAM[PSW], AC);
				else I8051_ClearBit(&RAM[PSW], AC);
				if( borrow7 ) I8051_SetBit(&RAM[PSW], CY);
				else I8051_ClearBit(&RAM[PSW], CY);
				if( (borrow6 && !borrow7) || (!borrow6 && borrow7) ) 
					I8051_SetBit(&RAM[PSW], OV);
				else I8051_ClearBit(&RAM[PSW], OV);
				//cycleCount += 12;

			}
			
			// ADD A, ((Ri))
			else if ((IR&0xFE) == ADD3)
			{		    
				carry3 = 0;
				carry6 = 0;
				carry7 = 0;
				regNum = IR & 0x01;

				tempAdd = (RAM[ACC] & 0x0F) + 
				(RAM[(unsigned short)RAM[I8051_GetRegisterBank()+regNum]] & 0x0F);
				if( (tempAdd & 0x0010) == 0x0010 ) carry3 = 1;
				tempAdd += ((RAM[ACC] & 0x70) +	(RAM[(unsigned short)RAM[I8051_GetRegisterBank()+regNum]] & 0x70));
				if( (tempAdd & 0x0080) == 0x0080 ) carry6 = 1;
				tempAdd += ((RAM[ACC] & 0x80) + (RAM[(unsigned short)RAM[I8051_GetRegisterBank()+regNum]] & 0x80));
				if( (tempAdd & 0x0100) == 0x0100 ) carry7 = 1;
				RAM[ACC] = tempAdd;
				if( carry3 ) I8051_SetBit(&RAM[PSW], AC);
				else I8051_ClearBit(&RAM[PSW], AC);
				if( carry7 ) I8051_SetBit(&RAM[PSW], CY);
				else I8051_ClearBit(&RAM[PSW], CY);
				if( (carry6 && !carry7) || (!carry6 && carry7) ) 
					I8051_SetBit(&RAM[PSW], OV);
				else I8051_ClearBit(&RAM[PSW], OV);
				//cycleCount += 20;

			}			
		    
			else
			{
				
			}			
		}
	
		return 1;
	}
} 

int main(uint64_t r3, uint64_t r4, uint64_t r5, uint64_t r6)
{
#ifdef DEBUG
	debug_init();
	DPRINTF("ps2emu stage 1.5 says hello. %lx %lx %lx %lx\n", r3, r4, r5, r6);	
#endif

#ifdef DEBUG
	uint64_t ticks = get_ticks();
#endif

	I8051_Init(r3, r4, r5, r6);
	I8051_Simulate();
	I8051_End();	
	
#ifdef DEBUG
	DPRINTF("Elapsed ticks: %ld\n", get_ticks()-ticks);
#endif
	
	return 0;
}










