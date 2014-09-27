#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <time.h>
#include <ctype.h>
#include <sys/stat.h>

#include "Ps3IsoGen.h"  

Ps3IsoGen::Ps3IsoGen(const char *gameCode)
{
	this->gameCode = dupString(gameCode);
}

Ps3IsoGen::~Ps3IsoGen()
{
	delete[] gameCode;
}

int Ps3IsoGen::generate(const char *inDir, const char *outFile, const char *volumeName)
{
	int ret = Iso9660Gen::generate(inDir, outFile, volumeName);
	if (ret != 0)
		return ret;
	
	if (numOfParts > 1)
	{
		char *p = strrchr(outFilePath, '.');
		strcpy(p+1, "0");
	}
	
	FILE *f = fopen(outFilePath, "r+b");
	if (!f)
		return ISO9660_GEN_ERROR_OUTPUT;
	
	fread(ioBuf, 1, 0x1000, f);
	fseek(f, 0, SEEK_SET);
	ioBuf[3] = 2;
	*(uint32_t *)&ioBuf[0x14] = BE32(volumeSize-1);
	
	strcpy((char *)ioBuf+0x800, "PlayStation3");
	memset(ioBuf+0x810, ' ', 0x20);
	memcpy(ioBuf+0x810, gameCode, 4);
	ioBuf[0x814] = '-';
	strncpy((char *)ioBuf+0x815, gameCode+4, 5);
	
	fwrite(ioBuf, 1, 0x1000, f);
	fclose(f);
	
	return 0;
}
