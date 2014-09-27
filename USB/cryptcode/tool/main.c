#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>
#include <sys/stat.h>
#include <elf.h>

//#define DEBUG

/*#define TEA_CODE_IV			0x61, 0x38, 0x6C, 0x6D, 0x80, 0xA7, 0xAF, 0xE3
#define TEA_CODE_KEY			0x62, 0xAD, 0x1A, 0x77, 0x84, 0x7C, 0x63, 0x75, 0x90, 0x6C, 0x20, 0xB6, 0x8D, 0x86, 0xE6, 0x49
#define TEA_DATA_KEY			0x62, 0xAD, 0x1A, 0x77, 0x84, 0x7C, 0x63, 0x75, 0x90, 0x6C, 0x20, 0xB6, 0x8D, 0x86, 0xE6, 0x49*/

uint8_t tea_code_IV[8];
uint8_t tea_code_key[16];
uint8_t tea_data_key[16];

#define STUB_SECTION_NAME		".cryptStub"
#define DATA_SECTION_NAME		".cryptData"
#define DATA_IV_SYMBOL_NAME		"cryptedDataMasterIV"

#undef D_PRINTF
#ifdef DEBUG
#define D_PRINTF(args...) printf(args);
#else
#define D_PRINTF(args...)
#endif

#define EndianSwap16(x) \
	((uint16_t)( \
		(((uint16_t)(x) & (uint16_t)0x00ffU) << 8) | \
		(((uint16_t)(x) & (uint16_t)0xff00U) >> 8) ))
#define EndianSwap32(x) \
	((uint32_t)( \
		(((uint32_t)(x) & (uint32_t)0x000000ffUL) << 24) | \
		(((uint32_t)(x) & (uint32_t)0x0000ff00UL) <<  8) | \
		(((uint32_t)(x) & (uint32_t)0x00ff0000UL) >>  8) | \
		(((uint32_t)(x) & (uint32_t)0xff000000UL) >> 24) ))
#define EndianSwap64(x) \
	((uint64_t)( \
		(uint64_t)(((uint64_t)(x) & (uint64_t)0x00000000000000ffULL) << 56) | \
		(uint64_t)(((uint64_t)(x) & (uint64_t)0x000000000000ff00ULL) << 40) | \
		(uint64_t)(((uint64_t)(x) & (uint64_t)0x0000000000ff0000ULL) << 24) | \
		(uint64_t)(((uint64_t)(x) & (uint64_t)0x00000000ff000000ULL) <<  8) | \
		(uint64_t)(((uint64_t)(x) & (uint64_t)0x000000ff00000000ULL) >>  8) | \
		(uint64_t)(((uint64_t)(x) & (uint64_t)0x0000ff0000000000ULL) >> 24) | \
		(uint64_t)(((uint64_t)(x) & (uint64_t)0x00ff000000000000ULL) >> 40) | \
		(uint64_t)(((uint64_t)(x) & (uint64_t)0xff00000000000000ULL) >> 56) ))

typedef struct
{
	Elf64_Shdr secHdr;

	uint8_t		*data;
	char		*name;

//	Elf64_Rel *relocTable;
//	int relocNumber;

} t_elfSectionDesc;

typedef struct
{

	Elf64_Ehdr hdr;
	Elf64_Phdr *progHdrs;
	t_elfSectionDesc *sections;
	int textSecIndex;

	char *stringTable;
	Elf64_Sym *symbolTable;
	int symbolNumber;

} t_ELF;

typedef struct
{
	uint64_t funcOpd;
	uint32_t funcSize;
	uint32_t funcKey;
} t_cryptoStubEntry;

uint8_t elfMagic[16] = { 0x7F, 0x45, 0x4C, 0x46, 0x02, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

int loadElf(FILE *in, t_ELF *elf);
void encryptFunction(FILE *fd, int funcOffset, int funcSize, uint8_t *funcKey);
void TEAEncrypt(uint32_t* v, uint32_t* k);
void TEAEncryptCbc(uint32_t *in, uint32_t *out, int bytes, uint32_t *IV, uint32_t *key);
void TEAEncryptCtr(uint8_t *in, uint8_t *out, int len, uint32_t *key, uint8_t *IV, uint8_t *ecount, int *num);

int main(int argc, char *argv[])
{
	t_ELF elf;
	FILE *fd;
	int rv, i, j;
	t_elfSectionDesc *stubSection = NULL, *dataSection = NULL;

	if(argc < 5)
	{
		printf("Usage: %s code.elf code_iv code_key data_key\n", argv[0]);
		exit(1);
	}

	srandom(time(0));
	
	fd = fopen(argv[2], "rb");
	if (!fd)
	{
		printf("Failed to open input file: %s\n", argv[2]);
		exit(1);
	}
	
	fread(tea_code_IV, 1, sizeof(tea_code_IV), fd);
	fclose(fd);
	
	fd = fopen(argv[3], "rb");
	if (!fd)
	{
		printf("Failed to open input file: %s\n", argv[3]);
		exit(1);
	}
	
	fread(tea_code_key, 1, sizeof(tea_code_key), fd);
	fclose(fd);
	
	fd = fopen(argv[4], "rb");
	if (!fd)
	{
		printf("Failed to open input file: %s\n", argv[4]);
		exit(1);
	}
	
	fread(tea_data_key, 1, sizeof(tea_data_key), fd);
	fclose(fd);

	fd = fopen(argv[1], "rb+");
	if(!fd)
	{
		printf("Failed to open input file: %s\n", argv[1]);
		exit(1);
	}

	loadElf(fd, &elf);
	if(elf.hdr.e_phnum != 1)
	{
		printf("ERROR: ELF must have 1 program header (%d)\n", elf.hdr.e_phnum);
		exit(1);
	}

	printf("Applying funcrypt..\n");
	for(i = 0; i < elf.hdr.e_shnum; i++)
		if(!strcmp(elf.sections[i].name, STUB_SECTION_NAME))
		{
			stubSection = &elf.sections[i];
			break;
		}
	if(stubSection != NULL)
	{
		t_cryptoStubEntry *stubs = (t_cryptoStubEntry *)stubSection->data;
		for(i = 0; i < stubSection->secHdr.sh_size / sizeof(t_cryptoStubEntry); i++)
		{
			int suicidal = 0;
			
			t_cryptoStubEntry thisStub;
			thisStub.funcOpd = EndianSwap64(stubs[i].funcOpd);
			thisStub.funcSize = EndianSwap32(stubs[i].funcSize);
			thisStub.funcKey = EndianSwap32(stubs[i].funcKey);
			//D_PRINTF("Stub %d: 0x%llX, 0x%08X, 0x%08X\n", i, thisStub.funcOpd, thisStub.funcSize, thisStub.funcKey);
			
			if (thisStub.funcSize == 0xC0DEBEEF && thisStub.funcKey == 0xDEADF00D)
				suicidal = 1;

			// find the opd entry for this stub
			Elf64_Sym *opdSym = NULL;
			for(j = 0; j < elf.symbolNumber; j++)
				if(elf.symbolTable[j].st_value == EndianSwap64(stubs[i].funcOpd))
				{
					opdSym = &elf.symbolTable[j];
					break;
				}
			if(!opdSym)
			{
				printf("ERROR: couldnt find opd symbol for 0x%llX\n", thisStub.funcOpd);
				exit(1);
			}

	//		D_PRINTF("found opd, name: %s\n", &elf.stringTable[opdSym->st_name]);
			char functionSymName[256];
			snprintf(functionSymName, 256, "%s", &elf.stringTable[opdSym->st_name]);

			Elf64_Sym *funcSym = NULL;
			for(j = 0; j < elf.symbolNumber; j++)
			{
				if(!strcmp(&elf.stringTable[elf.symbolTable[j].st_name], functionSymName))
				{
					funcSym = &elf.symbolTable[j];
					break;
				}
			}
			if(!funcSym)
			{
				printf("ERROR: couldnt find func symbol %s\n", functionSymName);
				exit(1);
			}

			int funcFileOffset = funcSym->st_value - elf.progHdrs[0].p_vaddr + elf.progHdrs[0].p_offset;
			int stubFileOffset = stubSection->secHdr.sh_offset + (i * sizeof(t_cryptoStubEntry));
			uint32_t funcSize;
			uint8_t funcKey[4];
			
			uint64_t func_addr;
			
			fseek(fd, funcFileOffset, SEEK_SET);
			fread(&func_addr, 1, 8, fd);
						
			func_addr = EndianSwap64(func_addr);
			funcFileOffset = func_addr - elf.progHdrs[0].p_vaddr + elf.progHdrs[0].p_offset;
			
			//D_PRINTF("found %s at 0x%llX, size 0x%X\n", functionSymName, func_addr, funcSym->st_size);
			//D_PRINTF("func off: 0x%X, stub off: 0x%X\n", funcFileOffset, stubFileOffset);

			funcSize = funcSym->st_size;

			for(j = 0; j < 4; j++)
				funcKey[j] = random();
			thisStub.funcOpd = EndianSwap64(thisStub.funcOpd);
			
			if (!suicidal)
				thisStub.funcSize = EndianSwap32(funcSize);
			else
			{
				thisStub.funcSize = EndianSwap32(funcSize | 0x80000000);
				//D_PRINTF("suicidal flag set\n");
			}
			
			memcpy(&thisStub.funcKey, funcKey, 4);
			fseek(fd, stubFileOffset, SEEK_SET);
			if(ftell(fd) != stubFileOffset)
			{
				printf("ERROR: failed to seek to 0x%X\n", stubFileOffset);
				exit(1);
			}
			if(fwrite(&thisStub, sizeof(t_cryptoStubEntry), 1, fd) != 1)
			{
				printf("ERROR: failed to write stub\n");
				exit(1);
			}

			encryptFunction(fd, funcFileOffset, funcSize, funcKey);
		}
		printf("%d functions encrypted\n", i);
	}
	else
		printf("WARNING: \'"STUB_SECTION_NAME"\' section not found, this ELF has no crypted functions\n");

	for(i = 0; i < elf.hdr.e_shnum; i++)
		if(!strcmp(elf.sections[i].name, DATA_SECTION_NAME))
		{
			dataSection = &elf.sections[i];
			break;
		}
	if(dataSection != NULL)
	{
		uint8_t teaIV[8];
		uint8_t teaKey[16]; // = { TEA_DATA_KEY };
		uint8_t ecount[8];
		int num = 0;
		
		memcpy(teaKey, tea_data_key, sizeof(tea_data_key));

		for(i = 0; i < 8; i++)
			teaIV[i] = random();

		Elf64_Sym *IVSym = NULL;
		for(j = 0; j < elf.symbolNumber; j++)
		{
			if(!strcmp(&elf.stringTable[elf.symbolTable[j].st_name], DATA_IV_SYMBOL_NAME))
			{
				IVSym = &elf.symbolTable[j];
				break;
			}
		}
		if(!IVSym)
		{
			printf("ERROR: couldnt find IV symbol %s\n", DATA_IV_SYMBOL_NAME);
			exit(1);
		}
		int IVFileOffset = IVSym->st_value - elf.progHdrs[0].p_vaddr + elf.progHdrs[0].p_offset;
		fseek(fd, IVFileOffset, SEEK_SET);
		if(ftell(fd) != IVFileOffset)
		{
			printf("ERROR: fseek failed on IV write\n");
			exit(1);
		}
		if(fwrite(teaIV, 8, 1, fd) != 1)
		{
			printf("ERROR: IV write failed\n");
			exit(1);
		}

		int cryptDataSize = dataSection->secHdr.sh_size;
		int cryptDataOffset = dataSection->secHdr.sh_offset;
		uint8_t *dataBuffer = (uint8_t *)malloc(cryptDataSize);
		if(!dataBuffer)
		{
			printf("malloc failed\n");
			exit(1);
		}

		fseek(fd, cryptDataOffset, SEEK_SET);
		if(ftell(fd) != cryptDataOffset)
		{
			printf("ERROR: fseek failed on data read\n");
			exit(1);
		}
		if(fread(dataBuffer, cryptDataSize, 1, fd) != 1)
		{
			printf("ERROR: data read failed\n");
			exit(1);
		}

		memset(ecount, 0, sizeof(ecount));
		teaIV[6] = teaIV[7] = 0; // big endian low order 2 bytes = 0 as are used for counter - counter has maximum of 64k * 8 = 512kb before poisoning IV
		TEAEncryptCtr(dataBuffer, dataBuffer, cryptDataSize, (uint32_t *)teaKey, teaIV, ecount, &num);

		fseek(fd, cryptDataOffset, SEEK_SET);
		if(ftell(fd) != cryptDataOffset)
		{
			printf("ERROR: fseek failed on data write\n");
			exit(1);
		}
		if(fwrite(dataBuffer, cryptDataSize, 1, fd) != 1)
		{
			printf("ERROR: data write failed\n");
			exit(1);
		}
		free(dataBuffer);
		printf("%d bytes of data encrypted\n", cryptDataSize);
	}
	else
		printf("WARNING: \'"DATA_SECTION_NAME"\' section not found, this ELF has no crypted data\n");

	fclose(fd);
	return 0;
}

void encryptFunction(FILE *fd, int funcOffset, int funcSize, uint8_t *funcKey)
{
	int i;
	uint8_t *codeBuffer = (uint8_t *)malloc(funcSize + 8);
	if(!codeBuffer)
	{
		printf("ERROR: malloc failed\n");
		exit(1);
	}

	fseek(fd, funcOffset, SEEK_SET);
	if(ftell(fd) != funcOffset)
	{
		printf("ERROR: fseek failed on func read\n");
		exit(1);
	}
	if(fread(codeBuffer, funcSize, 1, fd) != 1)
	{
		printf("ERROR: func read failed\n");
		exit(1);
	}

	uint8_t teaIV[8]; // = { TEA_CODE_IV };
	uint8_t teaKey[16];// = { TEA_CODE_KEY };
	
	memcpy(teaIV, tea_code_IV, sizeof(tea_code_IV));
	memcpy(teaKey, tea_code_key, sizeof(tea_code_key));

	// merge per-function key into base key
	for(i = 0; i < 4; i++)
	{
		teaKey[(i*4)+0] ^= funcKey[0];
		teaKey[(i*4)+1] ^= funcKey[1];
		teaKey[(i*4)+2] ^= funcKey[2];
		teaKey[(i*4)+3] ^= funcKey[3];
	}

	TEAEncryptCbc((uint32_t *)codeBuffer, (uint32_t *)codeBuffer, funcSize, (uint32_t *)teaIV, (uint32_t *)teaKey);

	fseek(fd, funcOffset, SEEK_SET);
	if(ftell(fd) != funcOffset)
	{
		printf("ERROR: fseek failed on func write\n");
		exit(1);
	}
	if(fwrite(codeBuffer, funcSize, 1, fd) != 1)
	{
		printf("ERROR: func write failed\n");
		exit(1);
	}
	free(codeBuffer);
}

void TEAEncrypt(uint32_t* v, uint32_t* k)
{
	uint32_t v0=v[0], v1=v[1], sum=0, i;
	uint32_t delta=0x9e3779b9;
	uint32_t k0=k[0], k1=k[1], k2=k[2], k3=k[3];

	// Fix endianness
	v0 = EndianSwap32(v0); v1 = EndianSwap32(v1);
	k0 = EndianSwap32(k0); k1 = EndianSwap32(k1); k2 = EndianSwap32(k2); k3 = EndianSwap32(k3);

	for (i=0; i < 32; i++) 
	{
		sum += delta;
		v0 += ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);
		v1 += ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);
	}
	v[0]= EndianSwap32(v0); v[1]= EndianSwap32(v1);
}

void TEAEncryptCbc(uint32_t *in, uint32_t *out, int bytes, uint32_t *IV, uint32_t *key)
{
	while(bytes > 0)
	{
		out[0] = in[0] ^ IV[0];
		out[1] = in[1] ^ IV[1];
		TEAEncrypt(out, key);
		IV[0] = out[0];
		IV[1] = out[1];
		in += 2;
		out += 2;
		bytes -= 8;
	}
}

// increment counter (64-bit int) by 1
static void ctr64_inc(uint8_t *counter) 
{
	uint32_t n=8;
	uint8_t  c;

	do {
		--n;
		c = counter[n];
		++c;
		counter[n] = c;
		if (c) return;
	} while (n);
}

void TEAEncryptCtr(uint8_t *in, uint8_t *out, int len, uint32_t *key, uint8_t *IV, uint8_t *ecount, int *num)
{
	unsigned int n;
	int l=0;

	n = *num;

	while (l<len) {
		if (n==0) {
			memcpy(ecount, IV, 8);
			TEAEncrypt((uint32_t *)ecount, key);
 			ctr64_inc(IV);
		}
		out[l] = in[l] ^ ecount[n];
		++l;
		n = (n+1) % 8;
	}

	*num=n;
}

int loadElf(FILE *in, t_ELF *elf)
{
	int fdSize;
	uint8_t *buffer;
	int i, j;
	Elf64_Shdr *secHdrs;
	char *secStrTab;

	fseek(in, 0, SEEK_END);
	fdSize = ftell(in);
	fseek(in, 0, SEEK_SET);
//	D_PRINTF("in size = %d bytes\n", fdSize);

	buffer = malloc(fdSize);
	if(!buffer)
	{
		printf("ERROR: malloc(%d) failed\n", fdSize);
		exit(1);
	}

	if(fread(buffer, 1, fdSize, in) != fdSize)
	{
		printf("ERROR: read(%d) failed\n", fdSize);
		exit(1);
	}

	if(memcmp(buffer, elfMagic, 16))
	{
		printf("Invalid ELF/OJB file!\n");
		exit(1);
	}

	// Fill header
	memcpy(&elf->hdr, buffer, sizeof(Elf64_Ehdr));

	elf->hdr.e_type = EndianSwap16(elf->hdr.e_type);
	elf->hdr.e_machine = EndianSwap16(elf->hdr.e_machine);
	elf->hdr.e_version = EndianSwap32(elf->hdr.e_version);
	elf->hdr.e_entry = EndianSwap64(elf->hdr.e_entry);
	elf->hdr.e_phoff = EndianSwap64(elf->hdr.e_phoff);
	elf->hdr.e_shoff = EndianSwap64(elf->hdr.e_shoff);
	elf->hdr.e_flags = EndianSwap32(elf->hdr.e_flags);
	elf->hdr.e_ehsize = EndianSwap16(elf->hdr.e_ehsize);
	elf->hdr.e_phentsize = EndianSwap16(elf->hdr.e_phentsize);
	elf->hdr.e_phnum = EndianSwap16(elf->hdr.e_phnum);
	elf->hdr.e_shentsize = EndianSwap16(elf->hdr.e_shentsize);
	elf->hdr.e_shnum = EndianSwap16(elf->hdr.e_shnum);
	elf->hdr.e_shstrndx = EndianSwap16(elf->hdr.e_shstrndx);
	
	// Fill program header if available
	if(elf->hdr.e_phoff)
	{
//		D_PRINTF("found program headers, reading..\n");
		elf->progHdrs = (Elf64_Phdr *)malloc(elf->hdr.e_phnum * sizeof(Elf64_Phdr));
		memcpy(elf->progHdrs, &buffer[elf->hdr.e_phoff], elf->hdr.e_phnum * sizeof(Elf64_Phdr));

		for(i = 0; i < elf->hdr.e_phnum; i++)
		{
			elf->progHdrs[i].p_type = EndianSwap32(elf->progHdrs[i].p_type);
			elf->progHdrs[i].p_flags = EndianSwap32(elf->progHdrs[i].p_flags);
			elf->progHdrs[i].p_offset = EndianSwap64(elf->progHdrs[i].p_offset);
			elf->progHdrs[i].p_vaddr = EndianSwap64(elf->progHdrs[i].p_vaddr);
			elf->progHdrs[i].p_paddr = EndianSwap64(elf->progHdrs[i].p_paddr);
			elf->progHdrs[i].p_filesz = EndianSwap64(elf->progHdrs[i].p_filesz);
			elf->progHdrs[i].p_memsz = EndianSwap64(elf->progHdrs[i].p_memsz);
			elf->progHdrs[i].p_align = EndianSwap64(elf->progHdrs[i].p_align);
		}
	}
	else
		elf->progHdrs = NULL;

	// Fill sections
	elf->sections = (t_elfSectionDesc *)malloc(elf->hdr.e_shnum * sizeof(t_elfSectionDesc));
	memset((void *)elf->sections, 0, elf->hdr.e_shnum * sizeof(t_elfSectionDesc));
	
	secHdrs = (Elf64_Shdr *)&buffer[elf->hdr.e_shoff];
	for(i = 0, j = elf->hdr.e_shnum; i < j; i++)
	{
		memcpy(&elf->sections[i].secHdr, &secHdrs[i], sizeof(Elf64_Shdr));

		elf->sections[i].secHdr.sh_name = EndianSwap32(elf->sections[i].secHdr.sh_name);
		elf->sections[i].secHdr.sh_type = EndianSwap32(elf->sections[i].secHdr.sh_type);
		elf->sections[i].secHdr.sh_flags = EndianSwap64(elf->sections[i].secHdr.sh_flags);
		elf->sections[i].secHdr.sh_addr = EndianSwap64(elf->sections[i].secHdr.sh_addr);
		elf->sections[i].secHdr.sh_offset = EndianSwap64(elf->sections[i].secHdr.sh_offset);
		elf->sections[i].secHdr.sh_size = EndianSwap64(elf->sections[i].secHdr.sh_size);
		elf->sections[i].secHdr.sh_link = EndianSwap32(elf->sections[i].secHdr.sh_link);
		elf->sections[i].secHdr.sh_info = EndianSwap32(elf->sections[i].secHdr.sh_info);
		elf->sections[i].secHdr.sh_addralign = EndianSwap64(elf->sections[i].secHdr.sh_addralign);
		elf->sections[i].secHdr.sh_entsize = EndianSwap64(elf->sections[i].secHdr.sh_entsize);

		if((elf->sections[i].secHdr.sh_type != SHT_NOBITS) && (elf->sections[i].secHdr.sh_size != 0))
		{
			elf->sections[i].data = malloc(elf->sections[i].secHdr.sh_size);
			if(!elf->sections[i].data)
			{
				printf("ERROR: No data for section %d\n", i);
				exit(1);
			}

			memcpy(elf->sections[i].data, &buffer[elf->sections[i].secHdr.sh_offset], elf->sections[i].secHdr.sh_size);
//			D_PRINTF("Section %d: %d bytes copied\n", i, elf->sections[i].secHdr.sh_size);
		}
		else
			elf->sections[i].data = NULL;

		// Fill in these later
		elf->sections[i].name = NULL;
//		elf->sections[i].relocTable = NULL;
	}
	
	// Process section names
	secStrTab = elf->sections[elf->hdr.e_shstrndx].data;
	for(i = 0; i < elf->hdr.e_shnum; i++)
	{
		elf->sections[i].name = &secStrTab[elf->sections[i].secHdr.sh_name];
//		D_PRINTF("Section %d name: %s\n", i, elf->sections[i].name);

		if(!strcmp(elf->sections[i].name, ".text"))
			elf->textSecIndex = i;
	}
/*
	// Process section relocation tables
	for(i = 0; i < elf->hdr.e_shnum; i++)
	{
		char relSecName[128];

		sprintf(relSecName, ".rel%s", elf->sections[i].name);
		for(j = 0; j < elf->hdr.e_shnum; j++)
		{
			if(!strcmp(relSecName, elf->sections[j].name))
			{
				elf->sections[i].relocTable = (Elf64_Rel *)elf->sections[j].data;
				D_PRINTF("reloc table for section %s found in section %s (off = 0x%X)\n", elf->sections[i].name,
					elf->sections[j].name, elf->sections[j].secHdr.sh_offset);
				elf->sections[i].relocNumber = elf->sections[j].secHdr.sh_size / sizeof(Elf64_Rel);
				break;
			}
		}
	}
*/
	// Find string table and symbol (there had better not be more than one of each :P)
	for(i = 0; i < elf->hdr.e_shnum; i++)
	{
		if(!strcmp(elf->sections[i].name, ".strtab") && (elf->sections[i].secHdr.sh_type == SHT_STRTAB))
		{
			elf->stringTable = elf->sections[i].data;
			D_PRINTF("string table found!\n");
		}
		else if(!strcmp(elf->sections[i].name, ".symtab") && (elf->sections[i].secHdr.sh_type == SHT_SYMTAB))
		{
			elf->symbolTable = (Elf64_Sym *)elf->sections[i].data;
			elf->symbolNumber = elf->sections[i].secHdr.sh_size / sizeof(Elf64_Sym);
			D_PRINTF("symbol table found! symbols = %d\n", elf->symbolNumber);
		}
	}
	
	for(i = 0; i < elf->symbolNumber; i++)
	{
		elf->symbolTable[i].st_name = EndianSwap32(elf->symbolTable[i].st_name);
		elf->symbolTable[i].st_shndx = EndianSwap16(elf->symbolTable[i].st_shndx);
		elf->symbolTable[i].st_value = EndianSwap64(elf->symbolTable[i].st_value);
		elf->symbolTable[i].st_size = EndianSwap64(elf->symbolTable[i].st_size);
	}	

	return 0;
}
