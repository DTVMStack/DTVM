// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef ZEN_PLATFORM_SGX_FILE_H
#define ZEN_PLATFORM_SGX_FILE_H

#include <stdio.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define F_DUPFD 0
#define F_GETFD 1
#define F_SETFD 2
#define F_GETFL 3
#define F_SETFL 4

#define FD_CLOEXEC 1

#define O_PATH 010000000
#define O_SEARCH O_PATH
#define O_EXEC O_PATH

#define O_ACCMODE (03 | O_SEARCH)
#define O_RDONLY 00
#define O_WRONLY 01
#define O_RDWR 02

#define O_CREAT 0100
#define O_EXCL 0200
#define O_NOCTTY 0400
#define O_TRUNC 01000
#define O_APPEND 02000
#define O_NONBLOCK 04000
#define O_DSYNC 010000
#define O_SYNC 04010000
#define O_RSYNC 04010000
#define O_DIRECTORY 0200000
#define O_NOFOLLOW 0400000
#define O_CLOEXEC 02000000

#define O_ASYNC 020000
#define O_DIRECT 040000
#define O_LARGEFILE 0
#define O_NOATIME 01000000
#define O_PATH 010000000
#define O_TMPFILE 020200000
#define O_NDELAY O_NONBLOCK

#define S_IFMT 0170000
#define S_IFDIR 0040000
#define S_IFCHR 0020000
#define S_IFBLK 0060000
#define S_IFREG 0100000
#define S_IFIFO 0010000
#define S_IFLNK 0120000
#define S_IFSOCK 0140000

#define SEEK_SET 0
#define SEEK_CUR 1
#define SEEK_END 2

#define S_ISDIR(mode) (((mode)&S_IFMT) == S_IFDIR)
#define S_ISCHR(mode) (((mode)&S_IFMT) == S_IFCHR)
#define S_ISBLK(mode) (((mode)&S_IFMT) == S_IFBLK)
#define S_ISREG(mode) (((mode)&S_IFMT) == S_IFREG)
#define S_ISFIFO(mode) (((mode)&S_IFMT) == S_IFIFO)
#define S_ISLNK(mode) (((mode)&S_IFMT) == S_IFLNK)
#define S_ISSOCK(mode) (((mode)&S_IFMT) == S_IFSOCK)

#define AT_SYMLINK_NOFOLLOW 0x100
#define AT_REMOVEDIR 0x200
#define AT_SYMLINK_FOLLOW 0x400

#define POLLIN 0x001
#define POLLPRI 0x002
#define POLLOUT 0x004
#define POLLERR 0x008
#define POLLHUP 0x010
#define POLLNVAL 0x020
#define POLLRDNORM 0x040
#define POLLRDBAND 0x080
#define POLLWRNORM 0x100
#define POLLWRBAND 0x200

#define FIONREAD 0x541B

#define PATH_MAX 4096

/* Special value used to indicate openat should use the current
   working directory. */
#define AT_FDCWD -100

typedef long __syscall_slong_t;

typedef unsigned long dev_t;
typedef unsigned long ino_t;
typedef unsigned mode_t;
typedef unsigned long nlink_t;
typedef unsigned socklen_t;
typedef long blksize_t;
typedef long blkcnt_t;

typedef int pid_t;
typedef unsigned gid_t;
typedef unsigned uid_t;

typedef unsigned long nfds_t;

typedef struct SGXFILE {
  char *_IO_read_ptr; /* Current read pointer */
  char *_IO_read_end; /* End of get area. */
} SGXFILE;

extern SGXFILE *sgx_stdout;
extern SGXFILE *sgx_stderr;

int open(const char *pathname, int flags, ...);

int close(int fd);

extern ssize_t sgx_write(int fd, const void *buf, size_t n);

off_t lseek(int fd, off_t offset, int whence);
int ftruncate(int fd, off_t length);

int remove(const char *);

int fileno(SGXFILE *stream);

int isatty(int fd);

SGXFILE *fopen(const char *filename, const char *mode);

int fclose(SGXFILE *stream);

#ifdef __cplusplus
}
#endif

#endif
