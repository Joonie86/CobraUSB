#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <time.h>
#include <ctype.h>
#include <sys/stat.h>

#ifdef NOT_SCANDIR

extern "C" int alphasort(const dirent **_a, const dirent **_b);
extern "C" int scandir(const char *dirname, struct dirent ***ret_namelist,
			int (*select)(const struct dirent *),
			int (*compar)(const struct dirent **, const struct dirent **));

#endif


#include "Iso9660Gen.h" 

#define MULTIEXTENT_PART_SIZE	0xFFFFF800

static char *strncpy_upper(char *s1, const char *s2, size_t n)
{
	strncpy(s1, s2, n);
	
	for (size_t i = 0; i < n; i++)
	{
		if (s1[i] == 0)
			break;
		
		if (s1[i] >= 'a' && s1[i] <= 'z')
		{
			s1[i] = s1[i] - ('a'-'A');
		}		
	}
	
	return s1;
}


static char *createPath(char *dir, char *file)
{
	char *ret = new char[strlen(dir) + strlen(file) + 2];
	sprintf(ret, "%s/%s", dir, file);
	return ret;
}

static bool getFileSizeAndProcessMultipart(char *file, off64_t *size)
{
	struct stat statbuf;
	
	if (stat(file, &statbuf) < 0)
		return false;
	
	*size = statbuf.st_size;
	
	char *p = strrchr(file, '.');
	if (!p || strcmp(p+1, "66600") != 0)
		return true;
	
	for (int i = 1; ; i++)
	{
		p[4] = '0' + (i/10);
		p[5] = '0' + (i%10);
		
		if (stat(file, &statbuf) < 0)
			break;
		
		*size += statbuf.st_size;		
	}	
	
	*p = 0;	
	return true;
}

static void genIso9660Time(time_t t, Iso9660DirectoryRecord *record)
{
	struct tm *timeinfo = localtime(&t);	
	record->year = timeinfo->tm_year;
	record->month = timeinfo->tm_mon+1;
	record->day = timeinfo->tm_mday;
	record->hour = timeinfo->tm_hour;
	record->minute = timeinfo->tm_min;
	record->second = timeinfo->tm_sec;
}

static void genIso9660TimePvd(time_t t, char *volumeTime)
{
	struct tm *timeinfo = localtime(&t);	
	int year = timeinfo->tm_year + 1900;
	int month = timeinfo->tm_mon + 1;
	
	volumeTime[0] = (year/1000);
	volumeTime[1] = (year - (volumeTime[0]*1000)) / 100;
	volumeTime[2] = (year - (volumeTime[0]*1000) - (volumeTime[1]*100)) / 10;
	volumeTime[3] = year % 10;
	volumeTime[4] = (month >= 10) ? 1 : 0;
	volumeTime[5] = month%10;
	volumeTime[6] = timeinfo->tm_mday / 10;
	volumeTime[7] = timeinfo->tm_mday % 10;
	volumeTime[8] = timeinfo->tm_hour / 10;
	volumeTime[9] = timeinfo->tm_hour % 10;
	volumeTime[10] = timeinfo->tm_min / 10;
	volumeTime[11] = timeinfo->tm_min % 10;
	volumeTime[12] = timeinfo->tm_sec / 10;
	volumeTime[13] = timeinfo->tm_sec % 10;
	volumeTime[14] = volumeTime[15] = volumeTime[16] = 0;
	
	for (int i = 0; i < 16; i++)
		volumeTime[i] += '0';
}

static int get_ucs2_from_utf8(const unsigned char * input, const unsigned char ** end_ptr)
{
	*end_ptr = input;
	if (input[0] == 0)
		return -1;
	
	if (input[0] < 0x80) 
	{
		*end_ptr = input + 1;
		return input[0];
	}
	if ((input[0] & 0xE0) == 0xE0) 
	{
		if (input[1] == 0 || input[2] == 0)
			return -1;
		
		*end_ptr = input + 3;
		return (input[0] & 0x0F)<<12 | (input[1] & 0x3F)<<6 | (input[2] & 0x3F);
	}
    
	if ((input[0] & 0xC0) == 0xC0) 
	{
		if (input[1] == 0)
			return -1;
		
		*end_ptr = input + 2;
		return (input[0] & 0x1F)<<6 | (input[1] & 0x3F);
	}
	
	return -1;
}

static int utf8_to_ucs2(const unsigned char *utf8, uint16_t *ucs2, uint16_t maxLength)
{
	const unsigned char *p = utf8;
	int length = 0;
	
	while (*p && length < maxLength)
	{	
		int ch = get_ucs2_from_utf8(p, &p);
		if (ch < 0)
			break;
		
		ucs2[length++] = BE16(ch&0xFFFF);
	}
	
	return length;
}

static int select_directories(const struct dirent *entry)
{
	if ((strcmp(entry->d_name, ".") == 0) || (strcmp(entry->d_name, "..") == 0))
	{
		return 0;
	}
	else 
	{
		if (entry->d_type == DT_DIR)
			return 1;
	}
	
	return 0;
}

static int select_files(const struct dirent *entry)
{
	if ((strcmp(entry->d_name, ".") == 0) || (strcmp(entry->d_name, "..") == 0))
	{
		return 0;
	}
	else 
	{
		if (entry->d_type != DT_DIR)
			return 1;
	}
	
	return 0;
}

Iso9660Gen::Iso9660Gen()
{
	if (sizeof(Iso9660DirectoryRecord) != 0x22)
	{
		printf("directory record does not have wanted size.\n");
	}
	
	if (sizeof(Iso9660PVD) != 2048)
	{
		printf("pvd record doesn't have wanted size.\n");
	}
	
	fd = NULL;
	outFilePath = NULL;
	rootList = NULL;	
	tempBuf = NULL;
	ioBuf = NULL;
	pathTableL = NULL;
	pathTableM = NULL;
	pathTableJolietL = NULL;
	pathTableJolietM = NULL;
	partitionSize = 0;
}

Iso9660Gen::~Iso9660Gen()
{
	reset();
}

void Iso9660Gen::reset(void)
{
	if (fd)
		closeOutputFile();
	
	if (outFilePath)
	{
		delete[] outFilePath;			
		outFilePath = NULL;		
	}
	
	if (pathTableL)
	{
		delete[] pathTableL;
		pathTableL = NULL;
	}
	
	if (pathTableM)
	{
		delete[] pathTableM;
		pathTableM = NULL;
	}
	
	if (pathTableJolietL)
	{
		delete[] pathTableJolietL;
		pathTableJolietL = NULL;
	}
	
	if(pathTableJolietM)
	{
		delete[] pathTableJolietM;
		pathTableJolietM = NULL;
	}
	
	while (rootList)
	{
		DirList *next = rootList->next;
		
		if (rootList->path)
			delete[] rootList->path;
		
		if (rootList->content)
			delete[] rootList->content;
		
		if (rootList->contentJoliet)
			delete[] rootList->contentJoliet;
		
		FileList *fileList = rootList->fileList;
		
		while (fileList)
		{
			FileList *nextFile = fileList->next;
			
			if (fileList->path)
				delete[] fileList->path;
			
			delete fileList;
			fileList = nextFile;
		}
		
		delete rootList;
		rootList = next;
	}
	
	filesSizeSectors = 0;
	dirsSizeSectors = 0;
	dirsSizeSectorsJoliet = 0;
	pathTableSize = 0;
	pathTableSizeJoliet = 0;
	numOfParts = 1;
	bytesWrittenInPart = 0;
	totalSize = 0;
	canceled = false;
}

bool Iso9660Gen::openOutputFile(void)
{
	if (!outFilePath)
		return false;
	
	fd = (void *)fopen(outFilePath, "wb");
	if (!fd)
		return false;
	
	return true;
}

void Iso9660Gen::closeOutputFile(void)
{
	if (fd)
	{
		fclose((FILE *)fd);
		fd = NULL;
	}
}

bool Iso9660Gen::writeOutputFile(void *buf, off64_t size, off64_t *written)
{
	off64_t bSize, remSize, ret;
	
	if (!fd)
		return false;
	
	if (numOfParts == 1)
	{
		bSize = size;
		remSize = 0;
	}
	else
	{
		if ((bytesWrittenInPart + size) > partitionSize)
		{
			remSize = (bytesWrittenInPart+size)-partitionSize;
			bSize = size - remSize;
		}
		else
		{
			bSize = size;
			remSize = 0;
		}
	}
	
	if (bSize == 0)
	{
		ret = 0;
	}
	else
	{	
		ret = fwrite(buf, 1, bSize, (FILE *)fd); 
	}
	
	if (ret != bSize)
		return false;
	
	if (written)
		*written = ret;
	
	if (numOfParts == 1)
		return true;
	
	if (remSize == 0)
	{
		bytesWrittenInPart += bSize;
		return true;
	}
	
	closeOutputFile();
	
	bytesWrittenInPart = 0;
	currentPart++;
	
	if (currentPart >= 100)
		return false;
	
	char *p = strrchr(outFilePath, '.');
	sprintf(p+1, "%d", currentPart);
	
	if (!openOutputFile())
		return false;
	
	ret = fwrite((uint8_t *)buf+bSize, 1, remSize, (FILE *)fd); 
	if (ret != remSize)
		return false;
	
	if (written)
		*written += ret;
	
	bytesWrittenInPart += remSize;
	
	return true;
}

DirList *Iso9660Gen::getParent(DirList *dirList)
{
	DirList *tempList = rootList;
	char *parentPath;
	
	if (dirList == rootList)
		return dirList;
	
	parentPath = dupString(dirList->path);
	*(strrchr(parentPath, '/')) = 0;
	
	while (tempList)
	{
		if (strcmp(parentPath, tempList->path) == 0)
		{
			delete[] parentPath;
			return tempList;
		}
		
		tempList = tempList->next;
	}
	
	delete[] parentPath;
	return dirList;
}

bool Iso9660Gen::isDirectChild(DirList *dir, DirList *parentCheck)
{
	if (strcmp(dir->path, parentCheck->path) == 0)
		return false;
	
	char *p = strstr(dir->path, parentCheck->path);
	if (p != dir->path)
		return false;
	
	p += strlen(parentCheck->path) + 1;
	if (strchr(p, '/'))
		return false;
	
	return true;
}

Iso9660DirectoryRecord *Iso9660Gen::findDirRecord(char *dirName, Iso9660DirectoryRecord *parentRecord, size_t size, bool joliet)
{
	uint8_t *strCheck = new uint8_t[256];
	uint8_t *buf, *p;
	uint32_t pos = 0;
	int strCheckSize;
	
	memset(strCheck, 0, 256);
	
	if (!joliet)
	{
		strncpy_upper((char *)strCheck, dirName, MAX_ISONAME-2);
		strCheckSize = strlen((const char *)strCheck);
	}
	else
	{
		strCheckSize = utf8_to_ucs2((const unsigned char *)dirName, (uint16_t *)strCheck, MAX_ISODIR/2) * 2;		
	}
	
	buf = p = (uint8_t *)parentRecord;
	
	while ((p < (buf+size)))
	{
		Iso9660DirectoryRecord *current = (Iso9660DirectoryRecord *)p;
		
		if (current->len_dr == 0)
		{
			p += (0x800 - (pos&0x7ff));
			pos += (0x800 - (pos&0x7ff));
			if (p >= (buf+size))			
				break;
			
			current = (Iso9660DirectoryRecord *)p;			
			if (current->len_dr == 0)
				break;
		}
		
		if (current->len_fi == strCheckSize && memcmp(&current->fi, strCheck, strCheckSize) == 0)
		{
			delete[] strCheck;
			return current;
		}
		
		p += current->len_dr;
		pos += current->len_dr;		
	}
	
	//printf("%s not found (joliet=%d)!!!!!!!\n", dirName, joliet);
	delete[] strCheck;
	return NULL;
}

uint8_t *Iso9660Gen::buildPathTable(bool msb, bool joliet, size_t *retSize)
{
	DirList *dirList;
	uint8_t *p;
	int i = 0;
	
	memset(tempBuf, 0, tempBufSize);
	p = tempBuf;
	dirList = rootList;	
	while (dirList && i < 65536)
	{
		Iso9660PathTable *table = (Iso9660PathTable *)p;
		Iso9660DirectoryRecord *record;
		uint16_t parentIdx;
		
		record = (Iso9660DirectoryRecord *)((joliet) ? dirList->contentJoliet : dirList->content);
		
		if (dirList == rootList)
		{
			table->len_di = 1;
			table->dirID = 0;
			parentIdx = 1;
		}
		else
		{
			DirList *parent;
			
			char *fileName = strrchr(dirList->path, '/')+1;
			
			if (!joliet)
			{				
				strncpy_upper(&table->dirID, fileName, MAX_ISODIR);
				table->len_di = strlen(&table->dirID);
			}
			else
			{
				table->len_di = utf8_to_ucs2((const unsigned char *)fileName, (uint16_t *)&table->dirID, MAX_ISODIR/2) * 2;
			}			
			
			parent = getParent(dirList);
			parentIdx = (uint16_t)parent->idx+1;
		}
		
		if (msb)
		{
			table->dirLocation = record->msbStart;
			table->parentDN = BE16(parentIdx);
		}
		else
		{
			table->dirLocation = record->lsbStart;
			table->parentDN = LE16(parentIdx);
		}
		
		p = p+8+table->len_di;
		if (table->len_di&1)
			p++;
		
		dirList = dirList->next;
		i++;
	}
	
	*retSize = (p-tempBuf);
	uint8_t *ret = new uint8_t[*retSize];
	
	memcpy(ret, tempBuf, *retSize);	
	return ret;
}

bool Iso9660Gen::buildContent(DirList *dirList, bool joliet)
{
	Iso9660DirectoryRecord *record, *parentRecord = NULL;
	DirList *tempList, *parent;
	uint8_t *p = tempBuf;
	struct stat statbuf;
	
	memset(tempBuf, 0, tempBufSize);	
	parent = getParent(dirList);
	
	// . entry	
	record = (Iso9660DirectoryRecord *)p;	
	record->len_dr = 0x28;
	record->lsbStart = (!joliet) ? LE32(dirsSizeSectors) : LE32(dirsSizeSectorsJoliet);
	record->msbStart = (!joliet) ? BE32(dirsSizeSectors) : BE32(dirsSizeSectorsJoliet);
						
	if (stat(dirList->path, &statbuf) < 0)
		return false;
	
	genIso9660Time(statbuf.st_mtime, record);
	record->fileFlags = ISO_DIRECTORY;
	record->lsbVolSetSeqNum = LE16(1);
	record->msbVolSetSeqNum = BE16(1);
	record->len_fi = 1;
	p += 0x28;
	
	// .. entry
	record = (Iso9660DirectoryRecord *)p;	
	record->len_dr = 0x28;
	
	if (parent != dirList)
	{	
		parentRecord = (Iso9660DirectoryRecord *) ((joliet) ? parent->contentJoliet : parent->content);
		record->lsbStart = parentRecord->lsbStart;
		record->msbStart = parentRecord->msbStart;
		record->lsbDataLength = parentRecord->lsbDataLength;
		record->msbDataLength = parentRecord-> msbDataLength;
	}
	
	if (stat(parent->path, &statbuf) < 0)
		return false;
	
	genIso9660Time(statbuf.st_mtime, record);
	record->fileFlags = ISO_DIRECTORY;
	record->lsbVolSetSeqNum = LE16(1);
	record->msbVolSetSeqNum = BE16(1);
	record->len_fi = 1;
	record->fi = 1;
	p += 0x28;
	
	// Files entries
	FileList *fileList = dirList->fileList;
	
	while (fileList)
	{
		unsigned int parts = 1;
		uint32_t lba = fileList->rlba;
		
		if (fileList->size > 0xFFFFFFFF)
		{
			parts = fileList->size / MULTIEXTENT_PART_SIZE;
			if (fileList->size % MULTIEXTENT_PART_SIZE)
				parts++;
		}
		
		for (unsigned int i = 0; i < parts; i++)
		{		
			uint32_t offs;			
			record = (Iso9660DirectoryRecord *)malloc(2048);
			memset(record, 0, 2048);
		
			record->lsbStart = LE32(lba);
			record->msbStart = BE32(lba);
			
			if (!fileList->multipart)
			{			
				if (stat(fileList->path, &statbuf) < 0)
				{
					free(record);
					return false;
				}
			}
			else
			{
				char *s = new char[strlen(fileList->path)+7];
				sprintf(s, "%s.66600", fileList->path);
				
				if (stat(s, &statbuf) < 0)
				{
					free(record);
					delete[] s;
					return false;
				}
				
				delete[] s;
			}
	
			genIso9660Time(statbuf.st_mtime, record);
			
			if (parts == 1)
			{
				record->fileFlags = ISO_FILE;
				record->lsbDataLength = LE32(fileList->size);
				record->msbDataLength = BE32(fileList->size);				
			}
			else
			{
				uint32_t size;
				
				if (i == parts-1)
				{
					size = (fileList->size) - (i*MULTIEXTENT_PART_SIZE);
					record->fileFlags = ISO_FILE;
				}
				else
				{
					size = MULTIEXTENT_PART_SIZE;
					record->fileFlags = ISO_MULTIEXTENT;
					lba += bytesToSectors(MULTIEXTENT_PART_SIZE);
				}
				
				record->lsbDataLength = LE32(size);
				record->msbDataLength = BE32(size);					
			}
			
			record->lsbVolSetSeqNum = LE16(1);
			record->msbVolSetSeqNum = BE16(1);	
			
			char *fileName = strrchr(fileList->path, '/')+1;
			
			if (!joliet)
			{
				strncpy_upper(&record->fi, fileName, MAX_ISONAME-2);
				strcat(&record->fi, ";1");
				record->len_fi = strlen(&record->fi);				
			}
			else
			{
				char *s = new char[strlen(fileName)+3];				
				strcpy(s, fileName);
				strcat(s, ";1");				
				record->len_fi = utf8_to_ucs2((const unsigned char *)s, (uint16_t *)&record->fi, MAX_ISONAME/2) * 2;
				delete[] s;
			}
		
			record->len_dr = 0x27 + record->len_fi;
			if (record->len_dr&1)
			{
				record->len_dr++;
			}
			
			offs = (p-tempBuf);
			
			if ((offs/0x800) < ((offs+record->len_dr)/0x800))
			{
				offs = (offs+0x7ff)&~0x7ff;
				p = (tempBuf+offs);
			}
			
			if ((p+record->len_dr) >= (tempBuf+tempBufSize))
			{
				free(record);
				return false;
			}
		
			memcpy(p, record, record->len_dr);
			p += record->len_dr;		
			free(record);			
		}
		
		fileList = fileList->next;
	}
	
	tempList = dirList->next;
	while (tempList)
	{
		if (isDirectChild(tempList, dirList))
		{
			uint32_t offs;			
			record = (Iso9660DirectoryRecord *)malloc(2048);
			memset(record, 0, 2048);
		
			if (stat(tempList->path, &statbuf) < 0)
			{
				free(record);
				return false;
			}
			
			genIso9660Time(statbuf.st_mtime, record);
			record->fileFlags = ISO_DIRECTORY;
			
			record->lsbVolSetSeqNum = LE16(1);
			record->msbVolSetSeqNum = BE16(1);	
			
			char *fileName = strrchr(tempList->path, '/')+1;
			
			
			if (!joliet)
			{				
				strncpy_upper(&record->fi, fileName, MAX_ISODIR);
				record->len_fi = strlen(&record->fi);
			}
			else
			{
				record->len_fi = utf8_to_ucs2((const unsigned char *)fileName, (uint16_t *)&record->fi, MAX_ISODIR/2) * 2;
			}
			
			record->len_dr = 0x27 + record->len_fi;
			if (record->len_dr&1)
			{
				record->len_dr++;
			}
			
			offs = (p-tempBuf);
			
			if ((offs/0x800) < ((offs+record->len_dr)/0x800))
			{
				offs = (offs+0x7ff)&~0x7ff;
				p = (tempBuf+offs);
			}
			
			if ((p+record->len_dr) >= (tempBuf+tempBufSize))
			{
				free(record);
				return false;
			}			
		
			memcpy(p, record, record->len_dr);
			p += record->len_dr;	
			free(record);					
		}
		
		tempList = tempList->next;
	}
	
	size_t size = (p-tempBuf);
	size = (size+0x7ff)&~0x7ff;
		
	p = new uint8_t[size];
	memcpy(p, tempBuf, size);
	
	record = (Iso9660DirectoryRecord *)p;
	record->lsbDataLength = LE32(size);
	record->msbDataLength = BE32(size);
	
	if (dirList == parent)
	{
		parentRecord = (Iso9660DirectoryRecord *)(p+0x28);
		parentRecord->lsbStart = record->lsbStart;
		parentRecord->msbStart = record->msbStart;
		parentRecord->lsbDataLength = record->lsbDataLength;
		parentRecord->msbDataLength = record-> msbDataLength;
	}
	else
	{
		Iso9660DirectoryRecord *childRecord = findDirRecord(strrchr(dirList->path, '/')+1, parentRecord, (joliet) ? parent->contentJolietSize : parent->contentSize, joliet);
		if (!childRecord)
		{
			delete[] p;
			return false;
		}
		
		childRecord->lsbStart = record->lsbStart;
		childRecord->msbStart = record->msbStart;
		childRecord->lsbDataLength = record->lsbDataLength;
		childRecord->msbDataLength = record->msbDataLength;
	}
	
	if (!joliet)
	{	
		dirList->content = p;
		dirList->contentSize = size;	
		dirsSizeSectors += bytesToSectors(size);
	}
	else
	{
		dirList->contentJoliet = p;
		dirList->contentJolietSize = size;	
		dirsSizeSectorsJoliet += bytesToSectors(size);
	}
	
	return true;
}

void Iso9660Gen::fixDirLba(Iso9660DirectoryRecord *record, size_t size, uint32_t dirLba, uint32_t filesLba)
{
	uint8_t *p, *buf;
	uint32_t pos = 0;
	
	buf = p = (uint8_t *)record;	
	
	while ((p < (buf+size)))
	{
		Iso9660DirectoryRecord *current = (Iso9660DirectoryRecord *)p;
		
		if (current->len_dr == 0)
		{
			p += (0x800 - (pos&0x7ff));
			pos += (0x800- (pos&0x7ff));
			if (p >= (buf+size))			
				break;
			
			current = (Iso9660DirectoryRecord *)p;			
			if (current->len_dr == 0)
				break;
		}
		
		if (current->fileFlags & ISO_DIRECTORY)
		{
			current->lsbStart = LE32(LE32(current->lsbStart)+dirLba);
			current->msbStart = BE32(BE32(current->msbStart)+dirLba);
		}
		else
		{
			current->lsbStart = LE32(LE32(current->lsbStart)+filesLba);
			current->msbStart = BE32(BE32(current->msbStart)+filesLba);
		}
		
		p += current->len_dr;
		pos += current->len_dr;		
	}
}

void Iso9660Gen::fixPathTableLba(uint8_t *pathTable, size_t size, uint32_t dirLba, bool msb)
{
	uint8_t *p = pathTable;
	
	while ((p < (pathTable+size)))
	{
		Iso9660PathTable *table = (Iso9660PathTable *)p;
		
		if (msb)
		{
			table->dirLocation = BE32(BE32(table->dirLocation)+dirLba);
		}
		else
		{
			table->dirLocation = LE32(LE32(table->dirLocation)+dirLba);
		}
		
		p = p+8+table->len_di;
		if (table->len_di&1)
			p++;
	}
}

void Iso9660Gen::fixLba(uint32_t isoLba, uint32_t jolietLba, uint32_t filesLba)
{
	DirList *dirList = rootList;
	
	while (dirList)
	{
		fixDirLba((Iso9660DirectoryRecord *)dirList->content, dirList->contentSize, isoLba, filesLba);
		fixDirLba((Iso9660DirectoryRecord *)dirList->contentJoliet, dirList->contentJolietSize, jolietLba, filesLba);		
		dirList = dirList->next;
	}
	
	fixPathTableLba(pathTableL, pathTableSize, isoLba, false);
	fixPathTableLba(pathTableM, pathTableSize, isoLba, true);
	fixPathTableLba(pathTableJolietL, pathTableSizeJoliet, jolietLba, false);
	fixPathTableLba(pathTableJolietM, pathTableSizeJoliet, jolietLba, true);
}

bool Iso9660Gen::build(const char *inDir)
{
	DirList *dirList, *tail;
	struct dirent **dirs;
	int count;
	int idx = 0;
	
	rootList = new DirList;	
	rootList->path = dupString(inDir);
	rootList->content = NULL;
	rootList->contentJoliet = NULL;
	rootList->fileList = NULL;
	rootList->idx = idx++;
	rootList->next = NULL;
	dirList = tail = rootList;	
		
	while (dirList)
	{		
		count = scandir(dirList->path, &dirs, select_directories, alphasort);	
		if (count < 0)
			return false;		
	
		for (int i = 0; i < count; i++)
		{
			tail = tail->next = new DirList;
			tail->path = createPath(dirList->path, dirs[i]->d_name);
			tail->content = NULL;
			tail->contentJoliet = NULL;
			tail->idx = idx++;
			tail->fileList = NULL;
			tail->next = NULL;			
		
			free(dirs[i]);
		}	
	
		free(dirs);
		dirList = dirList->next;
	}
	
	dirList = rootList;
	while (dirList)
	{
		struct dirent **files;
		FileList *fileList = NULL;
		bool error = false;
		
		count = scandir(dirList->path, &files, select_files, alphasort);
		for (int i = 0; i < count; i++)
		{
			if (!error)
			{
				bool multipart = false;
				
				char *p = strrchr(files[i]->d_name, '.');
				if (p && strlen(p+1) == 5)
				{
					if (p[1] == '6' && p[2] == '6' && p[3] == '6' && isdigit(p[4]) && isdigit(p[5]))
					{
						multipart = true;
						
						if (p[4] != '0' || p[5] != '0')
						{
							free(files[i]);
							continue;
						}
					}
				}
				
				if (i == 0)
				{
					fileList = dirList->fileList = new FileList;
				}
				else
				{
					fileList = fileList->next = new FileList;
				}
				
				fileList->path = createPath(dirList->path, files[i]->d_name);
				fileList->multipart = multipart;
				fileList->next = NULL;
				
				if (getFileSizeAndProcessMultipart(fileList->path, &fileList->size))
				{
					fileList->rlba = filesSizeSectors;
					filesSizeSectors += bytesToSectors(fileList->size);					
				}
				else
				{
					error = true;
				}				
			}
			
			free(files[i]);
		}
		
		if (count >= 0)
			free(files);
		
		if (error)
			return false;
		
		dirList = dirList->next;
	}
	
	// Add iso directories
	dirList = rootList;
	while (dirList)
	{
		if (!buildContent(dirList, false))
		{
			return false;
		}
		
		dirList = dirList->next;
	}
	
	// Add joliet directories
	dirList = rootList;
	while (dirList)
	{
		if (!buildContent(dirList, true))
		{
			return false;
		}
		
		dirList = dirList->next;
	}
	
	pathTableL = buildPathTable(false, false, &pathTableSize);
	pathTableM = buildPathTable(true, false, &pathTableSize);
	pathTableJolietL = buildPathTable(false, true, &pathTableSizeJoliet);
	pathTableJolietM = buildPathTable(true, true, &pathTableSizeJoliet);
	
	uint32_t isoLba = (0xA000/0x800) + (bytesToSectors(pathTableSize) * 2) + (bytesToSectors(pathTableSizeJoliet) * 2);
	uint32_t jolietLba = isoLba + dirsSizeSectors;
	uint32_t filesLba = jolietLba + dirsSizeSectorsJoliet;
	
	fixLba(isoLba, jolietLba, filesLba);
	
	return true;
}

bool Iso9660Gen::write(const char *volumeName)
{	
	DirList *dirList;
	off64_t written;
	Iso9660PVD *pvd;
	time_t t = time(NULL);
	
	
		
	// Write first 16 empty sectors	
	memset(ioBuf, 0, 0x8000);	
	if (!writeOutputFile(ioBuf, 0x8000, &written))
		return false;
	
	// Generate and write iso pvd
	pvd = (Iso9660PVD *)ioBuf;
	memset(pvd, 0, 0x800);
	
	pvd->VDType = 1;
	memcpy(pvd->VSStdId, "CD001", sizeof(pvd->VSStdId));
	pvd->VSStdVersion = 1;
	memset(pvd->systemIdentifier, ' ', sizeof(pvd->systemIdentifier));	
	
	strncpy_upper(pvd->volumeIdentifier, volumeName, sizeof(pvd->volumeIdentifier));	
	for (unsigned int i = strlen(volumeName); i < sizeof(pvd->volumeIdentifier); i++)
	{
		pvd->volumeIdentifier[i] = ' ';
	}
	
	pvd->lsbVolumeSpaceSize = LE32(volumeSize);
	pvd->msbVolumeSpaceSize = BE32(volumeSize);
	pvd->lsbVolumeSetSize = LE16(1);
	pvd->msbVolumeSetSize = BE16(1);
	pvd->lsbVolumeSetSequenceNumber = LE16(1);
	pvd->msbVolumeSetSequenceNumber = BE16(1);
	pvd->lsbLogicalBlockSize = LE16(0x800);
	pvd->msbLogicalBlockSize = BE16(0x800);
	pvd->lsbPathTableSize = LE32(pathTableSize);
	pvd->msbPathTableSize = BE32(pathTableSize);
	pvd->lsbPathTable1 = LE32(0xA000/0x800);
	pvd->msbPathTable1 = BE32((0xA000/0x800)+bytesToSectors(pathTableSize));
	memset(pvd->volumeSetIdentifier, ' ', sizeof(pvd->volumeSetIdentifier));
	memcpy(pvd->volumeSetIdentifier, pvd->volumeIdentifier, sizeof(pvd->volumeIdentifier));
	memset(pvd->publisherIdentifier, ' ', sizeof(pvd->publisherIdentifier));
	memset(pvd->dataPreparerIdentifier, ' ', sizeof(pvd->dataPreparerIdentifier));
	memset(pvd->applicationIdentifier, ' ', sizeof(pvd->applicationIdentifier));
	memset(pvd->copyrightFileIdentifier, ' ', sizeof(pvd->copyrightFileIdentifier));
	memset(pvd->abstractFileIdentifier, ' ', sizeof(pvd->abstractFileIdentifier));
	memset(pvd->bibliographicFileIdentifier, ' ', sizeof(pvd->bibliographicFileIdentifier));
	genIso9660TimePvd(t, pvd->volumeCreation);
	memset(pvd->volumeModification, '0', 16);
	memset(pvd->volumeExpiration, '0', 16);
	memset(pvd->volumeEffective, '0', 16);
	pvd->FileStructureStandardVersion = 1;
	memcpy(pvd->rootDirectoryRecord, rootList->content, sizeof(pvd->rootDirectoryRecord));
	pvd->rootDirectoryRecord[0] = sizeof(pvd->rootDirectoryRecord);
	
	if (!writeOutputFile(ioBuf, 0x800, &written))
		return false;
	
	// Write joliet pvd
	memset(pvd, 0, 0x800);
	
	pvd->VDType = 2;
	memcpy(pvd->VSStdId, "CD001", sizeof(pvd->VSStdId));
	pvd->VSStdVersion = 1;
	memset(pvd->systemIdentifier, 0, sizeof(pvd->systemIdentifier));
	utf8_to_ucs2((const unsigned char *)volumeName, (uint16_t *)pvd->volumeIdentifier, sizeof(pvd->volumeIdentifier) / 2);
	pvd->lsbVolumeSpaceSize = LE32(volumeSize);
	pvd->msbVolumeSpaceSize = BE32(volumeSize);
	pvd->escapeSequences[0] = '%';
	pvd->escapeSequences[1] = '/';
	pvd->escapeSequences[2] = '@';
	pvd->lsbVolumeSetSize = LE16(1);
	pvd->msbVolumeSetSize = BE16(1);
	pvd->lsbVolumeSetSequenceNumber = LE16(1);
	pvd->msbVolumeSetSequenceNumber = BE16(1);
	pvd->lsbLogicalBlockSize = LE16(0x800);
	pvd->msbLogicalBlockSize = BE16(0x800);
	pvd->lsbPathTableSize = LE32(pathTableSizeJoliet);
	pvd->msbPathTableSize = BE32(pathTableSizeJoliet);
	pvd->lsbPathTable1 = LE32(0xA000/0x800 + (bytesToSectors(pathTableSize)*2));
	pvd->msbPathTable1 = BE32(0xA000/0x800 + (bytesToSectors(pathTableSize)*2) + bytesToSectors(pathTableSizeJoliet));
	memcpy(pvd->volumeSetIdentifier, pvd->volumeIdentifier, sizeof(pvd->volumeIdentifier));
	genIso9660TimePvd(t, pvd->volumeCreation);
	memset(pvd->volumeModification, '0', 16);
	memset(pvd->volumeExpiration, '0', 16);
	memset(pvd->volumeEffective, '0', 16);
	pvd->FileStructureStandardVersion = 1;
	memcpy(pvd->rootDirectoryRecord, rootList->contentJoliet, sizeof(pvd->rootDirectoryRecord));
	pvd->rootDirectoryRecord[0] = sizeof(pvd->rootDirectoryRecord);
	
	if (!writeOutputFile(ioBuf, 0x800, &written))
		return false;
	
	// Write sector 18
	memset(ioBuf, 0, 0x800);
	ioBuf[0] = 0xFF;
	memcpy(ioBuf+1, "CD001", 5);
	
	if (!writeOutputFile(ioBuf, 0x800, &written))
		return false;
	
	// Write empty sector 19
	memset(ioBuf, 0, 0x800);
		
	if (!writeOutputFile(ioBuf, 0x800, &written))
		return false;
	
	// Write pathTableL
	memset(ioBuf, 0, bytesToSectors(pathTableSize)*0x800);
	memcpy(ioBuf, pathTableL, pathTableSize);
	
	if (!writeOutputFile(ioBuf, bytesToSectors(pathTableSize)*0x800, &written))
		return false;
	
	// Write pathTableM
	memcpy(ioBuf, pathTableM, pathTableSize);
	
	if (!writeOutputFile(ioBuf, bytesToSectors(pathTableSize)*0x800, &written))
		return false;
	
	// Write pathTableJolietL
	memset(ioBuf, 0, bytesToSectors(pathTableSizeJoliet)*0x800);
	memcpy(ioBuf, pathTableJolietL, pathTableSizeJoliet);
	
	if (!writeOutputFile(ioBuf, bytesToSectors(pathTableSizeJoliet)*0x800, &written))
		return false;
	
	// Write pathTableJolietM
	memcpy(ioBuf, pathTableJolietM, pathTableSizeJoliet);
	
	if (!writeOutputFile(ioBuf, bytesToSectors(pathTableSizeJoliet)*0x800, &written))
		return false;
	
	delete[] pathTableL;
	delete[] pathTableM;
	delete[] pathTableJolietL;
	delete[] pathTableJolietM;
	pathTableL = NULL;
	pathTableM = NULL;
	pathTableJolietL = NULL;
	pathTableJolietM = NULL;
	
	// Write iso directories
	dirList = rootList;	
	while (dirList)
	{
		if (!writeOutputFile(dirList->content, dirList->contentSize, &written))
			return false;
		
		dirList = dirList->next;
	}
	
	// Write joliet directories
	dirList = rootList;	
	while (dirList)
	{
		if (!writeOutputFile(dirList->contentJoliet, dirList->contentJolietSize, &written))
			return false;
		
		dirList = dirList->next;
	}
	
	// Write files	
	off64_t current = (0xA000/0x800) + (bytesToSectors(pathTableSize) * 2) + (bytesToSectors(pathTableSizeJoliet) * 2) + dirsSizeSectors + dirsSizeSectorsJoliet;
	current = current * 0x800;
		
	if (progress)
		progress(current, totalSize, &canceled);
	
	if (canceled)
		return false;
	
	dirList = rootList;
	while (dirList)
	{
		FileList *fileList = dirList->fileList;
		
		while (fileList)
		{
			if (!fileList->multipart)
			{
				FILE *f = fopen(fileList->path, "rb");
				size_t r;
			
				while ((r = fread(ioBuf, 1, ioBufSize, f)) > 0)
				{
					if (r&0x7ff)
					{
						size_t rem = 0x800-(r&0x7ff);
						memset(ioBuf+r, 0, rem);
						r += rem;
					}
				
					if (!writeOutputFile(ioBuf, r, &written))
						return false;
				
					current += r;
				
					if (progress)
						progress(current, totalSize, &canceled);
					
					if (canceled)
					{
						fclose(f);
						return false;
					}
				}
				
				fclose(f);
			}
			else
			{
				strcat(fileList->path, ".66600");
				
				for (int i = 0; ; i++)
				{
					char *p = strrchr(fileList->path, '.');
					p[4] = '0' + (i/10);
					p[5] = '0' + (i%10);
					
					FILE *f = fopen(fileList->path, "rb");
					if (!f)
					{
						if (i == 0)
							return false;
						
						break;
					}
					
					size_t r;
			
					while ((r = fread(ioBuf, 1, ioBufSize, f)) > 0)
					{
						if (!writeOutputFile(ioBuf, r, &written))
							return false;
						
						current += r;
				
						if (progress)
							progress(current, totalSize, &canceled);
						
						if (canceled)
						{
							fclose(f);
							return false;
						}
					}
					
					fclose(f);
				}
				
				if (current&0x7ff)
				{
					off64_t rem = 0x800-(current&0x7ff);
					
					memset(ioBuf, 0, rem);
					if (!writeOutputFile(ioBuf, rem, &written))
						return false;
					
					current += rem;
					
					if (progress)
						progress(current, totalSize, &canceled);
					
					if (canceled)
						return false;
				}
			}			
						
			fileList = fileList->next;
		}
		
		dirList = dirList->next;
	}
	
	// Write pad
	memset(ioBuf, 0, padSectors*0x800);
	
	if (!writeOutputFile(ioBuf, padSectors*0x800, &written))
		return false;
	
	current += (padSectors*0x800);
	
	if (progress)
		progress(current, totalSize, &canceled);
	
	if (canceled)
		return false;
	
	return true;
}

void Iso9660Gen::setPartitionSize(off64_t size)
{
	partitionSize = size;
}

void Iso9660Gen::setProgressFunction(void (* progress)(off64_t current, off64_t total, bool *cancelCheck))
{
	 this->progress = progress;
}

bool Iso9660Gen::setBuffers(void *tempBuf, size_t tempBufSize, void *ioBuf, size_t ioBufSize)
{
	if (tempBufSize < 1048576 || ioBufSize < 1048576)
		return false;
	
	if ((tempBufSize & 0x7ff) || (ioBufSize&0x7ff))
		return false;
	
	this->tempBuf = (uint8_t *)tempBuf, this->ioBuf = (uint8_t *)ioBuf;
	this->tempBufSize = tempBufSize, this->ioBufSize = ioBufSize;
	return true;
}

int Iso9660Gen::generate(const char *inDir, const char *outFile, const char *volumeName)
{
	if (!tempBuf || !ioBuf)
		return IS09660_GEN_ERROR_SETUP;
	
	reset();	
	
	if (!build(inDir))
		return ISO9660_GEN_ERROR_INPUT;
	
	volumeSize = (0xA000/0x800) + (bytesToSectors(pathTableSize) * 2) + (bytesToSectors(pathTableSizeJoliet) * 2) + dirsSizeSectors + dirsSizeSectorsJoliet + filesSizeSectors;
	padSectors = 0x20;
	
	if (volumeSize & 0x1F)
	{
		padSectors += (0x20-(volumeSize&0x1F));
	}
	
	volumeSize += padSectors;
	
	totalSize = volumeSize;
	totalSize = totalSize * 0x800;
	
	if (partitionSize != 0)
	{
		numOfParts = totalSize / partitionSize;
		if (totalSize % partitionSize)
			numOfParts++;
	}
	else
	{
		numOfParts = 1;
	}
	
	if (numOfParts == 1)
	{
		outFilePath = dupString(outFile);		
	}
	else
	{
		currentPart = 0;
		outFilePath = new char[strlen(outFile)+4];
		sprintf(outFilePath, "%s.0", outFile);
	}
	
	if (!openOutputFile())
		return ISO9660_GEN_ERROR_OUTPUT;
	
	if (!write(volumeName))
	{
		closeOutputFile();
		
		if (true)
		{
			if (numOfParts == 1)
			{
				unlink(outFilePath);
			}
			else
			{
				for (int i = 0; i < numOfParts; i++)
				{
					char *p = strrchr(outFilePath, '.');
					sprintf(p+1, "%d", i);
					
					unlink(outFilePath);					
				}
			}
		}
		
		return ISO9660_GEN_ERROR_OUTPUT;
	}
	
	closeOutputFile();	
	
	return 0;
}


