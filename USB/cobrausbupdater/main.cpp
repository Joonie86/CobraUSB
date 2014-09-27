#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <assert.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <math.h>
#include <stddef.h>
#include <ctype.h>
#include <sys/stat.h>

#include <sys/process.h>
#include <sys/memory.h>
#include <sys/timer.h>
#include <sys/return_code.h>
#include <sys/prx.h>

#include <cell/gcm.h>
#include <cell/pad.h>
#include <cell/keyboard.h>
#include <cell/sysmodule.h>
#include <cell/dbgfont.h>
#include <cell/codec/pngdec.h>
#include <cell/cell_fs.h>
#include <cell/l10n.h>
#include <cell/font.h>
#include <cell/fontFT.h>
#include <cell/fontGcm.h>


#include <sysutil/sysutil_sysparam.h>
#include <sysutil/sysutil_msgdialog.h>
#include <sysutil/sysutil_screenshot.h>


#include <netex/net.h>
#include <netex/libnetctl.h>

#include <libftp.h>


#include "common.h"
#include "syscall8.h"
#include "graphics.h"
#include "dialog.h"
#include "cobra.h"
#include "cobraupdate.h"
#include "sha1.h"

using namespace cell::Gcm;

#define	BUTTON_SELECT		(1<<0)
#define	BUTTON_L3		(1<<1)
#define	BUTTON_R3		(1<<2)
#define	BUTTON_START		(1<<3)
#define	BUTTON_UP		(1<<4)
#define	BUTTON_RIGHT		(1<<5)
#define	BUTTON_DOWN		(1<<6)
#define	BUTTON_LEFT		(1<<7)
#define	BUTTON_L2		(1<<8)
#define	BUTTON_R2		(1<<9)
#define	BUTTON_L1		(1<<10)
#define	BUTTON_R1		(1<<11)
#define	BUTTON_TRIANGLE		(1<<12)
#define	BUTTON_CIRCLE		(1<<13)
#define	BUTTON_CROSS		(1<<14)
#define	BUTTON_SQUARE		(1<<15)


enum
{
	PS2EMU_HW,
	PS2EMU_GX,
	PS2EMU_SW
};

SYS_PROCESS_PARAM(1001, 0x10000)

static void *host_addr;
int request_exit = 0;

extern "C" int alphasort(const dirent **_a, const dirent **_b);
extern "C" int scandir(const char *dirname, struct dirent ***ret_namelist,
			int (*select)(const struct dirent *),
			int (*compar)(const struct dirent **, const struct dirent **));

static int load_modules(void);
static int unload_modules(void);

bool exitprogram = false;
void sysutilCallback(uint64_t status, uint64_t param, void * userdata)
{
	(void)param;
	(void)userdata;
	switch(status)
	{
		case CELL_SYSUTIL_REQUEST_EXITGAME:
			request_exit = 1;
		break;
		
		default:
			exitprogram = false;
		break;
	}
	
	return;
}

static uint32_t new_pad = 0, old_pad = 0, cmd_pad;

int pad_read(void)
{
	int ret;

	u32 padd;

	u32 paddLX, paddLY; //, paddRX, paddRY;

	CellPadData databuf;
	CellPadInfo2 infobuf;
	static u32 old_info = 0;

	cmd_pad = 0;

	ret = cellPadGetInfo2(&infobuf);

	if (ret != 0) {
		old_pad = new_pad = 0;
		return 1;
	}

	if (infobuf.port_status[0] == CELL_PAD_STATUS_DISCONNECTED) {
		old_pad = new_pad = 0;
		return 1;
	}

	if ((infobuf.system_info & CELL_PAD_INFO_INTERCEPTED)
		&& (!(old_info & CELL_PAD_INFO_INTERCEPTED))) {
		old_info = infobuf.system_info;
	} else if ((!(infobuf.system_info & CELL_PAD_INFO_INTERCEPTED))
			   && (old_info & CELL_PAD_INFO_INTERCEPTED)) {
		old_info = infobuf.system_info;
		old_pad = new_pad = 0;
		return 1;
	}

	ret = cellPadGetData(0, &databuf);

	if (ret != CELL_OK) {
		old_pad = new_pad = 0;
		return 1;
	}

	if (databuf.len == 0) {
		new_pad = 0;
		return 1;
	}

	padd = (databuf.button[2] | (databuf.button[3] << 8));

	/* @drizzt Add support for analog sticks
	 * TODO: Add support for right analog stick */
	//paddRX = databuf.button[4];
	//paddRY = databuf.button[5];
	paddLX = databuf.button[6];
	paddLY = databuf.button[7];

	if (paddLX < 0x10)
		padd |= BUTTON_LEFT;
	else if (paddLX > 0xe0)
		padd |= BUTTON_RIGHT;

	if (paddLY < 0x10)
		padd |= BUTTON_UP;
	else if (paddLY > 0xe0)
		padd |= BUTTON_DOWN;

	new_pad = padd & (~old_pad);
	old_pad = padd;

	return 1;
}

static int unload_mod = 0;

static int load_modules()
{
	int ret;

	ret = cellSysmoduleLoadModule(CELL_SYSMODULE_FS);
	if (ret != CELL_OK) return ret;
	else unload_mod|=1;
	
	/*ret = cellSysmoduleLoadModule(CELL_SYSMODULE_PNGDEC);
	if(ret != CELL_OK) return ret;
	else unload_mod|=2;*/
		
	ret = cellSysmoduleLoadModule( CELL_SYSMODULE_IO );
	if (ret != CELL_OK) return ret;
	else unload_mod|=4;
		
	ret = cellSysmoduleLoadModule( CELL_SYSMODULE_GCM_SYS );
	if (ret != CELL_OK) return ret;
	else unload_mod|=8;
	
	/*ret = cellSysmoduleLoadModule(CELL_SYSMODULE_L10N);
	if (ret != CELL_OK) return ret;
	else unload_mod|=32;*/
	
	host_addr = memalign(0x100000, 0x100000);
	if(cellGcmInit(0x10000, 0x100000, host_addr) != CELL_OK) return -1;
	
	if(initDisplay()!=0) return -1;

	initShader();
	setDrawEnv();
		
	if(setRenderObject()) return -1;

	ret = cellPadInit(1);
	if (ret != 0) return ret;
	
	setRenderTarget();
	
	initFont();
		
	/*ret = cellSysmoduleLoadModule(CELL_SYSMODULE_NET);
	if (ret != CELL_OK) return ret;
	else unload_mod|=16;*/

	return ret;
}
static int unload_modules()
{
	cellPadEnd();	
	termFont();
	free(host_addr);
	
	if (unload_mod & 32) cellSysmoduleUnloadModule(CELL_SYSMODULE_L10N);
	if (unload_mod & 16) cellSysmoduleUnloadModule(CELL_SYSMODULE_NET);
	if (unload_mod & 8) cellSysmoduleUnloadModule(CELL_SYSMODULE_GCM_SYS);
	if (unload_mod & 4) cellSysmoduleUnloadModule(CELL_SYSMODULE_IO);
	if (unload_mod & 2) cellSysmoduleUnloadModule(CELL_SYSMODULE_PNGDEC);	
	if (unload_mod & 1) cellSysmoduleUnloadModule( CELL_SYSMODULE_FS );
	
	return 0;
}

#define MAX_SIZE	1048576
#define WRITE_RETRIES		10

static uint8_t g_buf[MAX_SIZE];

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

static uint32_t swap32(uint32_t data)
{
	uint32_t ret = (((data) & 0xff) << 24);
	ret |= (((data) & 0xff00) << 8);
	ret |= (((data) & 0xff0000) >> 8);
	ret |= (((data) >> 24) & 0xff);
	
	return ret;
}

static uint16_t swap16(uint16_t data)
{
	uint32_t ret = (data<<8)&0xFF00;
	ret |= ((data>>8)&0xFF);
	
	return ret;
}

static int sys_get_version(uint32_t *version)
{
	system_call_2(8, SYSCALL8_OPCODE_GET_VERSION, (uint64_t)(uint32_t)version);
	return (int)p1;
}

int sys_sm_shutdown(uint64_t type, void *argp, uint64_t args)
{
	system_call_3(379, type, (uint64_t)(uint32_t)argp, args);
	return (int)p1;
}

static int select_files(const struct dirent *entry)
{
	if (entry->d_type == DT_DIR)
	{
		return 0;
	}
	else
	{
		const char *p = strrchr(entry->d_name, '.');
		if (p && strcasecmp(p+1, "cba") == 0)
			return 1;
	}
		
	return 0;
}

static int search_cobra_update2(char *dir, CobraUpdateHeader *pheader, FILE **pf, uint32_t *pversion)
{
	struct dirent **files;
	int count = scandir(dir, &files, select_files, alphasort);
	CobraUpdateHeader header;
	FILE *f;
	
	*pversion = 0;
	
	for (int i = 0; i < count; i++)
	{
		char path[2048];
				
		snprintf(path, sizeof(path), "%s/%s", dir, files[i]->d_name);
		f = fopen(path, "rb");
		if (f)
		{
			if (fread(&header, 1, sizeof(CobraUpdateHeader), f) == sizeof(CobraUpdateHeader))
			{
				if (memcmp(header.id, COBRA_SIG, sizeof(header.id)) == 0 && swap16(header.format_version) == FORMAT_VERSION && swap16(header.fw_version) != 0)
				{
					if (swap16(header.fw_version) > *pversion)
					{
						if (*pversion != 0)
							fclose(*pf);
						
						*pf = f;
						*pversion = swap16(header.fw_version);
						memcpy(pheader, &header, sizeof(CobraUpdateHeader));
						continue;
					}
				}
					
			}
			
			fclose(f);
		}
	}
	
	if (*pversion > 0)
		return 0;
	
	return -1;
}

static int search_cobra_update(CobraUpdateHeader *pheader, FILE **pf)
{
	char usb[32];
	uint32_t highest_version = 0;
	
	for (int i = 0; i < 256; i++)
	{
		uint32_t version;
		CobraUpdateHeader header;
		FILE *f = NULL;
		
		sprintf(usb, "/dev_usb%03d", i);
		DPRINTF("Searching in %s\n", usb);
		if (search_cobra_update2(usb, &header, &f, &version) == 0)
		{
			if (version > highest_version)
			{
				if (highest_version != 0)
					fclose(*pf);
				
				highest_version = version;
				*pf = f;
				memcpy(pheader, &header, sizeof(CobraUpdateHeader));
			}
			else
			{
				fclose(f);
			}
		}
	}
	
	if (highest_version > 0)
		return 0;
	
	return -1;
}

static int get_cobra_update(char *file, CobraUpdateHeader *header, FILE **pf)
{
	*pf = fopen(file, "rb");
	if (!(*pf))
		return -1;
	
	uint32_t version = 0;
	
	if (fread(header, 1, sizeof(CobraUpdateHeader), *pf) == sizeof(CobraUpdateHeader))
	{
		if (memcmp(header->id, COBRA_SIG, sizeof(header->id)) == 0 && swap16(header->format_version) == FORMAT_VERSION && swap16(header->fw_version) != 0)
		{
			version = swap16(header->fw_version);
		}
	}
	
	if (version > 0)
		return 0;
	
	fclose(*pf);	
	return -1;
}

int verify_file(FILE *f, CobraUpdateHeader *header, uint64_t *fsz)
{
	SHA1Context ctx;
	int ret;
	uint32_t pos = ftell(f);
	uint32_t read;
	uint8_t sha1[20];
	
	if (memcmp(header->id, COBRA_SIG, sizeof(header->id)) != 0)
		return -1;
	
	ret = cobra_scp_decrypt(COBRA_SCP_DES_KEY_1, header->sha1, 16);
	if (ret < 0)
	{
		DPRINTF("Verify 1 failed.\n");
		return -1;
	}
	
	fseek(f, 0, SEEK_END);
	*fsz = ftell(f);
	fseek(f, sizeof(CobraUpdateHeader), SEEK_SET);
	
	SHA1Reset(&ctx);
	
	while ((read = fread(g_buf, 1, MAX_SIZE, f)) > 0)
	{
		SHA1Input(&ctx, g_buf, read);
	}
	
	SHA1Result(&ctx, sha1);
	if (memcmp(sha1, header->sha1, 16) != 0)
		return -1;
	
	fseek(f, pos, SEEK_SET);
	return 0;
}

static void SHA1(void *buf, uint16_t size, uint8_t *sha1)
{
	SHA1Context ctx;
	
	SHA1Reset(&ctx);
	SHA1Input(&ctx, (uint8_t *)buf, size);
	SHA1Result(&ctx, sha1);
}

static int is_empty_page(uint8_t *buf)
{
	for (int i = 0; i < COBRA_SPI_FLASH_PAGE_SIZE; i++)
		if (buf[i] != 0xFF)
			return 0;
		
	return 1;
}

static int _spi_flash_write(uint32_t address, uint8_t*buf, uint32_t size, int decrypt)
{
	static uint8_t sector_buf[COBRA_SPI_FLASH_SECTOR_SIZE];
	uint32_t sector_address;
	uint32_t remaining;
	int ret;
	
	if (size == 0)
		return 0;
	
	if ((address+size) > COBRA_SPI_FLASH_SIZE)
		return -1;
	
	sector_address = address;
	remaining = size;
	
	while (remaining > 0)
	{
		uint32_t write_size;
		
		write_size = COBRA_SPI_FLASH_SECTOR_SIZE;
		if (write_size > remaining)
			write_size = remaining;
		
		memset(sector_buf, 0xff, sizeof(sector_buf));
		memcpy(sector_buf, buf, write_size);
			
		ret = cobra_spi_flash_erase_sector(sector_address);
		if (ret < 0)
			return ret;
			
		for (uint32_t i = 0; i < COBRA_SPI_FLASH_SECTOR_SIZE; i += COBRA_SPI_FLASH_PAGE_SIZE)
		{
			if (decrypt || !is_empty_page(sector_buf+i))
			{
				if (decrypt)
					ret = cobra_spi_flash_decrypt_and_page_program(sector_address+i, sector_buf+i, COBRA_SPI_FLASH_PAGE_SIZE);
				else
					ret = cobra_spi_flash_page_program(sector_address+i, sector_buf+i, COBRA_SPI_FLASH_PAGE_SIZE);
					
				if (ret < 0)
					return ret;
			}
		}
		
		sector_address += COBRA_SPI_FLASH_SECTOR_SIZE;
		address += write_size;
		remaining -= write_size;
		buf += write_size;
	}
	
	return 0;
}

static int verify_write_old(uint32_t address, uint32_t size, uint8_t *sha1)
{
	int ret; 
	uint8_t read_sha1[20];
	uint8_t *buf = (uint8_t *)malloc(size);
	uint8_t *ptr = buf;
	uint32_t remaining = size;
	uint32_t current_address = address;
		
	while (remaining > 0)
	{	
		uint32_t block_size;
		
		if (remaining > 4096)
			block_size = 4096;
		else
			block_size = remaining;
		
		ret = cobra_spi_flash_read(current_address, ptr, block_size);
		if (ret < 0)
		{
			free(buf);
			return ret;
		}
		
		remaining -= block_size;
		ptr += block_size;
		current_address += block_size;
	}
	
	SHA1(buf, size, read_sha1);	
	free(buf);
	
	return (memcmp(sha1, read_sha1, 20) == 0);
}

static int spi_flash_write(uint32_t address, uint8_t*buf, uint32_t size, int decrypt, uint8_t *sha1)
{	
	int ret;
	static int new_method = 1;
	uint8_t read_sha1[20];
	
	if (new_method)
	{
		/*memset(read_sha1, 0, 20);
		
		ret = cobra_spi_flash_hash(address, size, read_sha1);
		if (ret < 0)
			new_method = 0;	
		else
		{
			int i;
			
			for (i = 0; i < 20; i++)
			{
				if (read_sha1[i] != 0)
					break;
			}
			
			if (i == 20)
				new_method = 0;
		}
		
		if (!new_method)
		{
			DPRINTF("Using old method.\n");
		}*/
		new_method = 0;
	}
	
	if (memcmp(read_sha1, sha1, 20) == 0)
	{
		DPRINTF("%x %x doesn't need update.\n", address, size);
		return 0;
	}
		
	for (int i = 0; i < WRITE_RETRIES; i++)
	{
		ret = _spi_flash_write(address, buf, size, decrypt);
		if (ret < 0)
			return ret;
		
		if (new_method)
		{
			ret = cobra_spi_flash_hash(address, size, read_sha1);
			if (ret < 0)
				return ret;
			
			if (memcmp(read_sha1, sha1, 20) == 0)
				break;			
		}
		else
		{		
			ret = verify_write_old(address, size, sha1);
			if (ret != 0)
			{
				if (ret == 1)
					ret = 0;
			
				break;
			}			
		}
		
		DPRINTF("verify_write failed on try #%d\n", i+1);
		if (i == (WRITE_RETRIES-1))
		{
			char msg[256];
			
			cellMsgDialogAbort();
			sys_timer_usleep(200000);
			snprintf(msg, sizeof(msg), "All write retries to %x failed. Please contact Cobra USB Team.\n", address);
			ok_dialog(msg);
			exit(-1);
		}
	}
	
	return ret;
}

static int update_cobra(CobraUpdateHeader *header, FILE *f)
{
	CobraUpdateOp operation;
	uint64_t fsz, percentage = 0, new_percentage, delta;
	int ret = 0;
	
	if (verify_file(f, header, &fsz) != 0)
	{
		ret = ERROR_INVALID_FILE;
		goto finalize;
	}
	
	while (fread(&operation, 1, sizeof(operation), f) == sizeof(operation))
	{
		ret = cobra_scp_decrypt(COBRA_SCP_DES_KEY_3, &operation, sizeof(operation));
		if (ret < 0)
		{
			ret = ERROR_COMUNICATION_ERROR;
			goto finalize;
		}		
		
		if (swap32(operation.size) > MAX_SIZE)
		{
			ret = ERROR_INVALID_FILE;
			goto finalize;
		}
		
		if (swap32(operation.size) > 0 && fread(g_buf, 1, swap32(operation.size), f) != swap32(operation.size))
		{
			ret = ERROR_INVALID_FILE;
			goto finalize;
		}		
		
		switch (operation.opcode)
		{
			case UPDATE_OPCODE_SPI_FLASH:
				ret = spi_flash_write(swap32(operation.data), g_buf, swap32(operation.size), 0, operation.sha1);			
			break;
			
			case UPDATE_OPCODE_SPI_FLASH_DEC:
				ret = spi_flash_write(swap32(operation.data), g_buf, swap32(operation.size), 1, operation.sha1);	
			break;
			
			case UPDATE_OPCODE_START_BOOTLOADER:
			{
				ret = cobra_mcu_start_bootloader(swap32(operation.data), g_buf);
				//printf("bootloader ret = %X\n", ret);				
			}
			break;
			
			case UPDATE_OPCODE_REBOOT:
				ret = cobra_mcu_reboot();
			break;
		}
		
		if (ret < 0)
		{
			ret = ERROR_COMUNICATION_ERROR;
			goto finalize;
		}
		
		new_percentage = (ftell(f)*100)/fsz;
		delta = new_percentage - percentage;
		
		if (new_percentage > 99)
			new_percentage = 99;
		
		percentage = new_percentage;
				
		if (delta > 0)
			cellMsgDialogProgressBarInc(CELL_MSGDIALOG_PROGRESSBAR_INDEX_SINGLE, delta);
	}
	
	new_percentage = 100;
	delta = new_percentage - percentage;
				
	if (delta > 0)
		cellMsgDialogProgressBarInc(CELL_MSGDIALOG_PROGRESSBAR_INDEX_SINGLE, delta);
	
	sys_timer_usleep(200000);
	
finalize:

	fclose(f);
	return ret;
}

static CobraUpdateHeader *g_header;
static FILE *g_f;
int g_ret;
bool is_thread_running = false;

static void update_thread(uint64_t)
{	
	g_ret = update_cobra(g_header, g_f);
	is_thread_running = false;
	sys_ppu_thread_exit(0);
}

static void progress_callback(int, void *)
{
}

static void do_update_cobra(CobraUpdateHeader *header, FILE *f)
{
	sys_ppu_thread_t thread;
	int flags;
	const char *err_msg = "";
	
	flags = CELL_MSGDIALOG_TYPE_SE_TYPE_NORMAL | CELL_MSGDIALOG_TYPE_SE_MUTE_ON | CELL_MSGDIALOG_TYPE_BUTTON_TYPE_NONE | CELL_MSGDIALOG_TYPE_PROGRESSBAR_SINGLE;
	cellMsgDialogOpen2(flags, "Updating Cobra USB Firmware...", progress_callback, NULL, NULL);
	
	g_header = header;
	g_f = f;
	is_thread_running = true;
	sys_ppu_thread_create(&thread, update_thread, NULL, 500, 64*1024, 0, "");
	
	while (is_thread_running)
	{
		cellSysutilCheckCallback();
		flip();
	}
	
	cellMsgDialogAbort();
	setRenderColor();
	
	switch (g_ret)
	{
		case 0:
			ok_dialog("Update completed.\nA reboot is needed, press OK to reboot.\n");
			sys_sm_shutdown(0x8201, 0, 0);
		break;
		
		case ERROR_FILE_OPEN:
			err_msg = "Error opening file.\n";
		break;
		
		case ERROR_DEVICE_OPEN:
			err_msg = "Error opening device: COBRA was not found.\n";
		break;
		
		case ERROR_INVALID_FILE:
			err_msg = "Invalid update file.\n";
		break;
		
		case ERROR_NEED_HIGHER_VERSION:
			err_msg = "This update requires a higher version of the flasher.\n";
		break;
		
		case ERROR_COMUNICATION_ERROR:
			err_msg = "Communication error with device (device unplugged?)\n";
		break;
		
		case ERROR_OLD_NOT_SUPPORTED:
			err_msg = "Old firmware format is not supported by this version of the flasher.\n";
		break;
	}
	
	ok_dialog(err_msg);
}

int main(int argc, char *argv[])
{
	uint32_t version;
	CobraUpdateHeader header;
	FILE *f = NULL;
	char name[32];
	char msg[256];
	
	load_modules();
	cellSysutilRegisterCallback(0, sysutilCallback, NULL);	
	
	if (sys_get_version(&version) != 0)
		sys_process_exit(-1);
	
	version=version&0xFF;
	
	DPRINTF("Current version: %02X\n", version);
	
	if (version < 4) /* < 4.0 */
	{
		ok_dialog("Cobra USB Updater requires at least cobra firmware 3.3 final to work.\n");
		sys_process_exit(0);
	}
	
	if (argc >= 2)
	{
		if (get_cobra_update(argv[1], &header, &f) != 0)
		{
			char msg[240];
			
			snprintf(msg, sizeof(msg), "%s doesn't exist or is invalid cobrau update.\n", argv[1]);
			ok_dialog(msg);
			sys_process_exit(0);
		}
	}
	
	else if (search_cobra_update(&header, &f) != 0)
	{
		ok_dialog("No Cobra USB FW Update found in any USB.\n");
		sys_process_exit(0);
	}
	
	if (cobra_open_device() < 0)
	{
		ok_dialog("Cobra USB is not inserted.\n");
		sys_process_exit(0);
	}
	
	if (fread(name, 1, 32, f) != 32)
		sys_process_exit(-1);
	
	name[31] = 0;
	snprintf(msg, sizeof(msg), "Do you want to update to %s?\n", name);
	
	if (!yes_no_dialog(msg, false, true))
	{
		fclose(f);
		sys_process_exit(0);
	}
	
	do_update_cobra(&header, f);	
	unload_modules();
	sys_process_exit(0);
	
	return 0;
}