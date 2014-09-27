#ifndef __NETISO_H__
#define __NETISO_H__

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NETISO_PORT	38008

enum NETISO_CMD
{
	/* Closes the active file (if any) and open/stat a new one (read only) */
	NETISO_CMD_OPEN_FILE = 0x1224,
	/* Reads the active file. Offsets and sizes in bytes. If file read fails, client is exited */
	NETISO_CMD_READ_FILE_CRITICAL,
	/* Reads 2048 sectors in a file that uses 2352 bytes sectors. */
	NETISO_CMD_READ_CD_2048_CRITICAL,
	
	/* Replace this with any custom command */
	NETISO_CMD_CUSTOM_0 = 0x2412,	
};

typedef struct _netiso_cmd
{
	uint16_t opcode;
	uint8_t data[14];
} __attribute__((packed)) netiso_cmd;

typedef struct _netiso_open_cmd
{
	uint16_t opcode;
	uint16_t fp_len;
	uint8_t pad[12];
} __attribute__((packed)) netiso_open_cmd;

typedef struct _netiso_open_result
{
	int64_t file_size; // -1 on error 
	uint64_t mtime;	
} __attribute__((packed)) netiso_open_result;

typedef struct _netiso_read_file_critical_cmd
{
	uint16_t opcode;
	uint16_t pad;
	uint32_t num_bytes;
	uint64_t offset;
} __attribute__((packed)) netiso_read_file_critical_cmd;

typedef struct _netiso_read_cd_2048_critical_cmd
{
	uint16_t opcode;
	uint16_t pad;
	uint32_t start_sector;
	uint32_t sector_count;
	uint32_t pad2;
} __attribute__((packed)) netiso_read_cd_2048_critical_cmd;

#ifdef __BIG_ENDIAN__

static inline uint16_t BE16(uint16_t x) 
{
	return x;
}

static inline uint32_t BE32(uint32_t x)
{
	return x;
}

static inline uint64_t BE64(uint64_t x)
{
	return x;
}

#else

static inline uint16_t BE16(uint16_t x)
{
	uint16_t ret = (x<<8)&0xFF00;
	ret |= ((x>>8)&0xFF);
	
	return ret;
}

static inline uint32_t BE32(uint32_t x)
{
	uint32_t ret = (((x) & 0xff) << 24);
	ret |= (((x) & 0xff00) << 8);
	ret |= (((x) & 0xff0000) >> 8);
	ret |= (((x) >> 24) & 0xff);
	
	return ret;
}

static inline uint64_t BE64(uint64_t x)
{
	uint64_t ret = (x << 56) & 0xff00000000000000ULL;
	ret |= ((x << 40) & 0x00ff000000000000ULL);
	ret |= ((x << 24) & 0x0000ff0000000000ULL);
	ret |= ((x << 8) & 0x000000ff00000000ULL);
	ret |= ((x >> 8) & 0x00000000ff000000ULL);
	ret |= ((x >> 24) & 0x0000000000ff0000ULL);
	ret |= ((x >> 40) & 0x000000000000ff00ULL);
	ret |= ((x >> 56) & 0x00000000000000ffULL);
	
	return ret;
}

#endif

#ifdef __cplusplus
}
#endif

#endif

