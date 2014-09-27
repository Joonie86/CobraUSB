Files:
libcobra.a, cobra.h -> cobra library
Iso9660Gen.cpp, Iso9660Gen.h, Ps3IsoGen.cpp, Ps3IsoGen.h, iso9660.h, scandir.c -> to generate ps3 isos from directory
scandir is necessary because there is no scandir implementation in the sony sdk.



The proper way to mount an iso:

// This function mounts an iso. If there is an iso previously mounted, it umounts it.
int do_mount_iso(char *files[], ...)
{
	unsigned int effective_disctype, iso_disctype;
	
	cobra_get_disctype(NULL, &effective_disctype, &iso_disctype);
	
	// If there is an effective disc in the system, it must be ejected
	if (effective_disctype != DISC_TYPE_NONE)
	{
		cobra_send_fake_disc_eject_event();
	}
	
	// If there is an iso mounted, unmount it
	if (iso_disctype != DISC_TYPE_NONE)
	{
		cobra_umount_disc_image();
	}
	
	result = cobra_mount_XXX_disc_image(...);
	if (result != 0)
	{
		// Error processing
		...
	}
	
	// Issue the insert event now
	cobra_send_fake_disc_insert_event();
	return 0;
}

After the fake insert, the xmb automounter will typically mount the file system in a small period of time... except when it fails (for example, it fails with some psx games,
this is not a cobra bug, it happens with some original cd's too)

If you are gonna exit after mounting the iso, there is no reason  to wait for the automounter to mount the filesystem, except for ps3 isos:
You should check if the iso is a valid one (not encrypted one). Afer mounting a ps3 iso you could have a code like this:

// Verifyng if iso is valid. Waiting a max of 1 second for XMB automonter to mount the disc
for ( i = 0; i < 50; i++)
{
	CellFsStat stat;
				
	if (cellFsStat("/dev_bdvd", &stat) == 0)
	{
		int fd;
					
		if (cellFsOpen("/dev_bdvd/PS3_GAME/USRDIR/EBOOT.BIN", CELL_FS_O_RDONLY, &fd, NULL, 0) == 0)
		{
			uint32_t sig;
			uint64_t nread;
						
			cellFsRead(fd, &sig, 4, &nread);
			cellFsClose(fd);
						
			if (sig != 0x53434500 && sig != 0x7F454c46)
			{
				// show error dialog here
				do_umount_iso();
				return;
			}						
		}
					
		break;
	}
	
	sys_timer_usleep(20000);
}

if (i == 50)
{
	// Not valid either
	do_umount_so();
	return;
}



Specific cases of PSX iso:

All supported psx isos or cue/bin in cobra must be 2352.
To get the track definition, proceed like this:

TrackDef tracks[100];
char bin_filename[256];
int num_tracks;

if (file extension is iso)
{
	tracks[0].lba = 0;
	tracks[0].is_audio = 0;
	num_tracks = 1;
}
else if (file extension is cue)
{
	result = cobra_parse_cue(cue_buf, cue_buf_size, &tracks, 100, &num_tracks, bin_filename, 255);
	if (result != 0)
	{
		...;
		error processing;
	}
}

Cobra USB Manager doesn't list bin files. Instead it list isos and cue.
When a cue is detected, it is parsed and if succesfull it tries the following things to detect the bin path

- Firstly it merges the bin filename from what cobra_parse_cue detected, and the directory where the cue is.
- If it fails, and this is the internal disk, which is case sensitive, it tries to find a file that has same name but with different case.
- If that fails too, it tries to check if a file with same base name as cue but with bin extension exists.


Specific case of PS2 isos:

PS2 isos can be 2048 or 2352. Easiest way to detect this is to seek to offset 0x8000 and check the CD001 signature. IF present, it is a 2048 iso, otherwise, assume a 2352 one.
If it is a 2048 iso, there is no need to pass any track definition to the mount function, pass NULL.
If it is a 2352, proceed like in the PSX case.


The proper way to umount an iso:

int do_umount_iso(void)
{
	unsigned int real_disctype, effective_disctype, iso_disctype;
	
	cobra_get_disctype(&real_disctype, &effective_disctype, &iso_disctype);
	
	if (iso_disctype == DISC_TYPE_NONE)
		return 0; // Exit now, no iso mounted
		
	// If there is an effective disc in the system, it must be ejected
	if (effective_disctype != DISC_TYPE_NONE)
	{
		cobra_send_fake_disc_eject_event();
	}
	
	cobra_umount_disc_image();
	
	// If there is a real disc in the system, issue an insert event
	if (real_disctype != DISC_TYPE_NONE)
	{
		cobra_send_fake_disc_insert_event();
	}
	
	return 0;
}


Application start: on application start, cobra_lib_init should be called, iso should be umounted, psp iso game unset, jb game unmapped, and any other mapped path also unmapped
The fastest way to do all of this at once:

cobra_lib_init();
do_umount_iso();
cobra_map_game(NULL, NULL, NULL);
cobra_map_paths(NULL, NULL, 0);
cobra_unset_psp_game();

Disc dumping:

Common method for BD (not ps3), DVD and PS2 DVD:

Use sys_storage_get_device_info to get the disc size, and sys_storage_open, read and close for the dumping.
For DVD, and PS2 DVD you could do additional processing to create a MDS when dual layer is detected.
Before closing the sys_storage handle, do some code like this:


DiscPhysInfo layer0;
DiscPhysInfo layer1;

if (cobra_get_disc_phys_info(handle, 0, &layer0) == 0)
{
	if (layer0.num_layers == 1) // 1 means 2
	{
		if (cobra_get_disc_phys_info(handle, 1, &layer1) == 0)
		{
			cobra_create_mds(mds_path, size_in_sectors, &layer0, &layer1);
		}
	}
}

For BD, there is no point in creating the mds file.

Disc dumping method for PS3 BD:

Use sys_storage_get_device_info to get the size of the disc in sectors.
Forget about any other sys_storage* function and use the cobra_read_ps3_disc function. Don't forget to do a cobra_disc_auth before the dump


Disc dumping for PSX CD and PS2 CD:

DON'T use sys_storage_get_device_info to get the size;
Instead use cobra_get_cd_td and make lba_end-tracks[0].lba 
This function is also needed to get the tracks definition, that you need for cobra_cd_read and to generate the cue.
Multiply by 2352, not 2048, to get the size in bytes

Use sys_storage_open to open the disc, cobra_cd_read to read the disc, and sys_storage_close to close the disc.
Don't assume that the disc starts at lba 0. Assume that it starts at tracks[0].lba

As specified in cobra_cd_read, you shouldn't cross the boundary of a track in a single call. Because of it, it is probably a better idea to have
a function that dumps a track, and then a global function that does something like this:

int do_dump_ps_cd(...)
{
	TrackDef tracks[100];
	uint32_t lba_end;
	unsigned int num_tracks;
	
	result = sys_storage_open(..., &handle, ...);
	if (result != 0)
	{
		// Error processing
		...
	}
	
	result = cobra_get_cd_td(handle, &tracks, 100, &num_tracks, &lba_end);
	if (result != 0)
	{
		// Error processing
		...
	}
	
	// Check that first track is not audio, since cobra can't handle isos with first track as audio
	if (tracks[0].is_audio)
	{
		// Error processing
		...
	}
	
	// Check that all other tracks are audio, since cobra can't handle isos with more than one data track
	for (i = 1; i < num_tracks; i++)
	{
		if (!tracks[i].is_audio)
		{
			// Error processing
			...
		}
	}
	
	// dump tracks
	for (i = 0; i < num_tracks; i++)
	{
		uint32_t track_size;
		
		if (i == (num_tracks-1))
		{
			track_size = lba_end - tracks[i].lba;
		}
		else
		{
			track_size = tracks[i+1].lba - tracks[i].lba;
		}
		
		result = do_dump_track(handle, tracks[i].lba, track_size, tracks[i].is_audio);
		if (result != 0)
		{
			// Error processing
			...
		}
	}
	
	sys_storage_close(handle);
	
	if (num_tracks > 1)
	{
		// Create the cue here, see below
	}
	
	return 0;
}

As stated in cobra.h, it seems that some errors are common in CD's.
cobra_cd_read already does 10 retries on one by one sectors. If EIO is returned, you should probably continue with dumping and add the returned value in num_errors
to some global counter, and if it bypasses certain number, abort the dump. If an error different than EIO is returned, abort inmediatelly. 

Creating the cue:

First of all, if you detect that there is only one track, use .iso extension for the output file, otherwise use .bin extension.
If there is more than one track, create the cue with cobra_create_cue, and pass the tracks definition that cobra_get_cd_td returned.


Disc authentification:
When a disc change is detected, you should issue a cobra_disc_auth command. 

The disc authentification problem in PSX CD-R, PS2 CD-R and PS2 DVD+-R

Cobra core usually gets the disc type from the data returned directly by the bd drive. But when detecting a CD or DVD, it tries to check if it is a PSX or PS2 disc 
by reading some data from it.
However, if the system is in PS3 disc authentification mode, it fails in reading the CD or DVD, and effective_disctype will be DISC_TYPE_CD or DISC_TYPE_DVD

The work around is to do something like this when detecting a new CD or DVD in the system:

(the following code assumes that there is no iso mounted)

void on_new_disc_insert()
{
	unsigned int effective_disctype;
	
	cobra_get_disctype(NULL, &effective_disctype, NULL);
	
	if (effective_disctype == DISC_TYPE_CD || effective_disctype == DISC_TYPE_DVD)
	{
		cobra_disc_auth();
		cobra_send_fake_disc_eject_event();
		sys_timer_usleep(300);
		cobra_send_fake_disc_insert_event();
		
		// Now if the disc was indeed a PS CD/DVD backup, effective_disctype will have proper value
		cobra_get_disctype(NULL, &effective_disctype, NULL);
	}
	
	// process efective_disctype here
}

You could also move the disc_auth before the "if", since anyways you will need to have the disc authenticated


To allow or not to allow PS2:

int allow_ps2 = 0;

if (cobra_get_ps2_emu_type() != PS2_EMU_SW)
{
	allow_ps2 = 1;
}
else
{
	CobraConfig *config;
	
	cobra_read_config(&config);
	allow_ps2 = config.ps2softemu;
}

Generate an ISO from a directory using Iso9660Gen and Ps3IsoGen c++ classes:
Make sure to add -DNOT_SCANDIR to PPU_CPPFLAGS, and include scandir.c file in PPU_SRCS

Normal non ps3 disc:

{
	Iso9660Gen *iso = new Iso9660Gen();
	iso->setBuffer(temp_buf, TEMP_BUF_SIZE, ioBuf, IO_BUF_SIZE);
	iso->setProgressFunction(iso_creation_progress);
	
	if (split_files)
	{
		iso->setPartitionSize(0xFFFF0000);
	}
	
	result = iso->generate(input_dir, output_file, "DISC_LABEL_HERE");
	delete iso;

	if (result != 0)
	{
		// ... error processing, result is one of the defined in Iso9660Gen.h
	}
}

Cobra USB Manager and genps3iso use the following values for TEMP_BUF_SIZE and IO_BUF_SIZE: 4 MB and 28 MB.
IO_BUF_SIZE only matters for write efficiency (the bigger the better), but the value of TEMP_BUF_SIZE is important, you should leave it at 4 MB.

the generate method is a blocking one, so you should have another thread calling cellSysutilCheckCallback, and flipping the screen.
Initially, generate method will scan the input directory. After the scan and fs structures creation are finished, it will begin writing the iso and calling
your progress callback function.

Cobra USB Manager uses the following progress callback, you may want to have something similar:

static void iso_creation_progress(off64_t current, off64_t total, bool *cancelCheck)
{
	char msg[64];
	static off64_t perc = 0;
	off64_t new_perc = (current*100)/total;
	off64_t delta = new_perc - perc;
	
	*cancelCheck = abort_copy;
	
	snprintf(msg, sizeof(msg), get_string(STRING_COPIED_PROGRESS), current/1048576, total/1048576);
	cellMsgDialogProgressBarSetMsg(CELL_MSGDIALOG_PROGRESSBAR_INDEX_SINGLE, msg);
				
	if (delta > 0)
		cellMsgDialogProgressBarInc(CELL_MSGDIALOG_PROGRESSBAR_INDEX_SINGLE, delta);
	
	perc = new_perc;
}

where abort_copy is a global boolean variable that indicates if the operation should be canceled or not. Iso9660Gen read this value in cancelCheck param.
if the operation is aborted, generate will return an error, be prepared to handle that situation.

PS3 disc: 
same code except the constructor:

Ps3IsoGen *iso = new Ps3IsoGen(title_id); 

where title_id is the game title_id with a length of 9 characters, e.g. BLUS00112

It would be a good idea to specify "PS3VOLUME" as the label passed to generate method, to match the label created by sony tools.
				
