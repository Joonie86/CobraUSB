#include "common.h"
#include "File.h"

File::File()
{
	fd = INVALID_FD;
}

File::~File()
{
	DPRINTF("File destructor.\n");
	
	if (FD_OK(fd))
		this->close();
}

int File::open(const char *path, int flags)
{
	if (FD_OK(fd))
		this->close();
	
	fd = open_file(path, flags);
	if (!FD_OK(fd))
		return -1;
	
	return 0;
}

int File::close(void)
{
	return close_file(fd);
}

ssize_t File::read(void *buf, size_t nbyte)
{
	return read_file(fd, buf, nbyte);
}

ssize_t File::write(void *buf, size_t nbyte)
{
	return write_file(fd, buf, nbyte);
}

int64_t File::seek(int64_t offset, int whence)
{
	return seek_file(fd, offset, whence);
}

int File::fstat(file_stat_t *fs)
{
	return fstat_file(fd, fs);
}


