#include <lv2/lv2.h>
#include <lv2/error.h>
#include <lv2/libc.h>
#include <lv2/memory.h>
#include <cryptcode/cryptcode.h>
#include "common.h"
#include "config.h"
#include "region.h"
#include "modulespatch.h"
#include "cobra.h"

#define CONFIG_SPI_FLASH_ADDRESS 0x1FF000

CobraConfig config;

static void check_and_correct(CobraConfig *cfg)
{
	uint32_t i;
	int found = 0;
	
	for (i = 1; i <= BD_VIDEO_REGION_MAX; i *= 2)
	{
		if (cfg->bd_video_region == i)
		{
			found = 1;
			break;
		}
	}
	
	if (!found)
		cfg->bd_video_region = 0;
	else
		found = 0;
	
	for (i = 1; i <= DVD_VIDEO_REGION_MAX; i *= 2)
	{
		if (cfg->dvd_video_region == i)
		{
			found = 1;
			break;
		}
	}
	
	if (!found)
		cfg->dvd_video_region = 0;	
	
	if (cfg->ps2softemu > 1)
		cfg->ps2softemu = 0;
	
	if (cfg->spoof_version > MAX_SPOOF_VERSION)
	{
		cfg->spoof_version = 0;
	}
	else 
	{
		uint8_t h, l;
		
		h = (cfg->spoof_version&0xFF)>>4;
		l = cfg->spoof_version&0xF;
		
		if (h > 9 || l > 9)
		{
			cfg->spoof_version = 0;
		}
	}
	
	if (cfg->spoof_revision > MAX_SPOOF_REVISION)
		cfg->spoof_revision = 0;
		
	if (cfg->size > sizeof(CobraConfig))
		cfg->size = sizeof(CobraConfig);
}

static uint16_t checksum(CobraConfig *cfg)
{
	uint8_t *buf = &cfg->bd_video_region;
	uint16_t size = cfg->size - sizeof(cfg->size) - sizeof(cfg->checksum);
	uint16_t cs = 0;
	
	for (int i = 0; i < size; i++)
	{
		cs += buf[i];
	}
	
	return cs;
}

ENCRYPTED_FUNCTION(int, read_cobra_config, (void))
{
	int ret;
	
	ret = cobra_spi_flash_read(CONFIG_SPI_FLASH_ADDRESS, &config, sizeof(config), 0);
	if (ret != 0)
		return ret;
	
	if (config.size > 4096 || checksum(&config) != config.checksum)
	{
		memset(&config, 0, sizeof(config));		
	}
	else
	{
		check_and_correct(&config);
	}
	
	config.size = sizeof(config);
	
	bd_video_region = config.bd_video_region;
	dvd_video_region = config.dvd_video_region;
	condition_ps2softemu = config.ps2softemu;
	DPRINTF("Configuration read. spoof_version = %04X, spoof_revision = %d\n", config.spoof_version, config.spoof_revision);
		
	return 0;
}

ENCRYPTED_FUNCTION(int, write_cobra_config, (void))
{
	int ret;
	
	ret = cobra_spi_flash_erase_sector(CONFIG_SPI_FLASH_ADDRESS);	
	if (ret != 0)
		return ret;
	
	return cobra_spi_flash_page_program(CONFIG_SPI_FLASH_ADDRESS, &config, sizeof(config));
}

ENCRYPTED_FUNCTION(int, sys_read_cobra_config, (CobraConfig *cfg))
{
	int erase_size, copy_size;
	
	cfg = get_secure_user_ptr(cfg);
	
	if (cfg->size > 4096)
		return EINVAL;	
	
	erase_size = cfg->size-sizeof(config.size);
	if (erase_size < 0)
		erase_size = 0;
	
	memset(&cfg->checksum, 0, erase_size);
	
	copy_size = ((cfg->size > config.size) ? config.size : cfg->size) - sizeof(config.size);
	if (copy_size < 0)
		copy_size = 0;
	
	//DPRINTF("erase = %d, copy = %d\n", erase_size, copy_size);
	
	memcpy(&cfg->checksum, &config.checksum, copy_size);
	return 0;
}

ENCRYPTED_FUNCTION(int, sys_write_cobra_config, (CobraConfig *cfg))
{
	int copy_size;
	
	cfg = get_secure_user_ptr(cfg);
	
	if (cfg->size > 4096)
		return EINVAL;	
	
	check_and_correct(cfg);
	
	cfg->checksum = checksum(cfg);
	copy_size = cfg->size - sizeof(config.size);	
	if (copy_size < 0)
		copy_size = 0;
	
	memcpy(&config.checksum, &cfg->checksum, copy_size);
	bd_video_region = config.bd_video_region;
	dvd_video_region = config.dvd_video_region;
	condition_ps2softemu = config.ps2softemu;
	
	return write_cobra_config();
}



