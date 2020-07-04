#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <string.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "userprog/process.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/vaddr.h"
#include "threads/palloc.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "devices/input.h"
#include "intrinsic.h"
#include "threads/malloc.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

static void syscall_halt (void);
static void syscall_exit (int status);
static int syscall_fork (const char *thr_name, struct intr_frame *f);
static void syscall_exec (const char *cmd_line);
static int syscall_wait (int pid);
static bool syscall_create (const char *file, unsigned initial_size);
static bool syscall_remove (const char *file);
static int syscall_open (const char *file);
static int syscall_filesize (int fd);
static int syscall_read (int fd, void *buffer, unsigned length);
static int syscall_write (int fd, const void *buffer, unsigned length);
static void syscall_seek (int fd, unsigned position);
static unsigned syscall_tell (int fd);
static void syscall_close (int fd);
static int syscall_dup2 (int oldfd, int newfd);
static void *syscall_mmap(void *addr, size_t length, int writable, int fd, off_t offset);
static void syscall_munmap (void *addr);
static int create_file_descriptor (struct file *file);
static void check_mem_space_read (const void *addr_, const size_t size, const bool is_str);
static void check_mem_space_write (const void *addr_, const size_t size);
static int64_t get_user(const uint8_t *uaddr);
static bool put_user(uint8_t *udst, uint8_t byte);
static bool valid_user_addr (const uint8_t *addr);

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f) {
	ASSERT (thread_is_user (thread_current ()));
	switch (f->R.rax) {
		case SYS_HALT:
			syscall_halt ();
			break;
		case SYS_EXIT:
			syscall_exit ((int)f->R.rdi);
			break;
		case SYS_FORK:
			f->R.rax = (uint64_t)syscall_fork ((const char*)f->R.rdi, f);
			break;
		case SYS_EXEC:
			syscall_exec ((const char*)f->R.rdi);
			break;
		case SYS_WAIT:
			f->R.rax = (uint64_t)syscall_wait ((int)f->R.rdi);
			break;
		case SYS_CREATE:
			f->R.rax = (uint64_t)syscall_create ((const char*)f->R.rdi, (unsigned)f->R.rsi);
			break;
		case SYS_REMOVE:
			f->R.rax = (uint64_t)syscall_remove ((const char*)f->R.rdi);
			break;
		case SYS_OPEN:
			f->R.rax = (uint64_t)syscall_open ((const char*)f->R.rdi);
			break;
		case SYS_FILESIZE:
			f->R.rax = (uint64_t)syscall_filesize ((int)f->R.rdi);
			break;
		case SYS_READ:
			f->R.rax = (uint64_t)syscall_read ((int)f->R.rdi, (void*)f->R.rsi, (unsigned)f->R.rdx);
			break;
		case SYS_WRITE:
			f->R.rax = (uint64_t)syscall_write ((int)f->R.rdi, (const void*)f->R.rsi, (unsigned)f->R.rdx);
			break;
		case SYS_SEEK:
			syscall_seek ((int)f->R.rdi, (unsigned)f->R.rsi);
			break;
		case SYS_TELL:
			f->R.rax = (uint64_t)syscall_tell ((int)f->R.rdi);
			break;
		case SYS_CLOSE:
			syscall_close ((int)f->R.rdi);
			break;
		/* Extra for Project 2 */
		case SYS_DUP2:
			f->R.rax = (uint64_t)syscall_dup2 ((int)f->R.rdi, (int)f->R.rsi);
			break;
		/* Project 3 and optionally project 4. */
		case SYS_MMAP:			/* Map a file into memory. */
			f->R.rax = (uint64_t)syscall_mmap ((void*)f->R.rdi, (size_t)f->R.rsi, (int)f->R.rdx, (int)f->R.r10 , (off_t)f->R.r8 );
			break;
		case SYS_MUNMAP:		/* Remove a memory mapping. */
			syscall_munmap ((void*)f->R.rdi);
			break;

		/* Project 4 only. */
		//case SYS_CHDIR:			/* Change the current directory. */
		//case SYS_MKDIR:			/* Create a directory. */
		//case SYS_READDIR:		/* Reads a directory entry. */
		//case SYS_ISDIR:			/* Tests if a fd represents a directory. */
		//case SYS_INUMBER:		/* Returns the inode number for a fd. */
		default:
			ASSERT (0); //Unknown syscall (could not be implemented yet)
	}
}

/* Terminates Pintos by calling power_off(). This should be seldom used,
 * because you lose some information about possible deadlock situations,
 * etc. */
static void
syscall_halt (void) {
	power_off ();
}

/* Terminates the current user program, returning status to the kernel.
 * If the process's parent waits for it (see wait()), this is the status
 * that will be returned. Conventionally, a status of 0 indicates success
 * and nonzero values indicate errors. */
static void
syscall_exit (int status) {
	thread_exit (status);
}

/* Create new process which is the clone of current process with the name
 * THREAD_NAME. You don't need to clone the value of the registers except
 * %RBX, %RSP, %RBP, and %R12 - %R15, which are callee-saved registers.
 * Must return pid of the child process, otherwise shouldn't be a valid
 * pid. In child process, the return value should be 0. The child should
 * have DUPLICATED resources including file descriptor and virtual memory
 * space. Parent process should never return from the fork until it knows
 * whether the child process successfully cloned. That is, if the child
 * process fail to duplicate the resource, the fork () call of parent
 * should return the TID_ERROR.
 * The template utilizes the pml4_for_each() in threads/mmu.c to copy
 * entire user memory space, including corresponding pagetable structures,
 * but you need to fill missing parts of passed pte_for_each_func (See
 * virtual address). */
static int
syscall_fork (const char *thr_name, struct intr_frame *f) {
	ASSERT (f);

	if (thr_name == NULL)
		return -1;
	check_mem_space_read (thr_name, 0, true);
	return process_fork (thr_name, f);
}

/* Change current process to the executable whose name is given in
 * cmd_line, passing any given arguments. This never returns if
 * successful. Otherwise the process terminates with exit state -1, if the
 * program cannot load or run for any reason. This function does not
 * change the name of the thread that called exec. Please note that file
 * descriptors remain open across an exec call. */
static void
syscall_exec (const char *cmd_line) {
	struct thread *curr = thread_current ();
	char *cmd_line_copy;

	check_mem_space_read (cmd_line, 0, true);

	/* Close current executable. */
	ASSERT (curr->executable);
	file_close (curr->executable);
	curr->executable = NULL;
	/* Make a copy of CMD_LINE. */
	cmd_line_copy = palloc_get_page (0);
	if (cmd_line_copy == NULL)
		thread_exit (-1);
	strlcpy (cmd_line_copy, cmd_line, PGSIZE);

	process_exec (cmd_line_copy);
	thread_exit (-1); /* Not reached on success. */
}

/* Waits for a child process pid and retrieves the child's exit status.
 * If pid is still alive, waits until it terminates. Then, returns the
 * status that pid passed to exit.
 * If pid did not call exit(), but was terminated by the kernel (e.g.
 * killed due to an exception), returns -1.
 * A parent process can wait for child processes that have already
 * terminated by the time the parent calls wait and the exit status of the
 * terminated child will be returned.
 * Returns -1 immediately if any of the following conditions is true:
 * 1) pid does not refer to a direct child of the calling process.
 * pid is a direct child of the calling process if and only if the calling
 * process received pid as a return value from a successful call to exec.
 * Children are not inherited: if A spawns child B and B spawns child
 * process C, then A cannot wait for C, even if B is dead. A call to
 * wait(C) by process A will fail. Similarly, orphaned processes are not
 * assigned to a new parent if their parent process exits before they do.
 * 2) The process that calls wait has already called wait on pid. That is,
 * a process may wait for any given child at most once. */
static int
syscall_wait (int pid) {
	return process_wait ((tid_t)pid);
}

/* Creates a new file called file initially initial_size bytes in size.
* Returns true if successful, false otherwise. Creating a new file does
* not open it: opening the new file is a separate operation which would
* require a open system call. */
static bool
syscall_create (const char *file, unsigned initial_size) {
	check_mem_space_read (file, 0, true);
	return filesys_create(file, initial_size);
}

/* Deletes the file called file. Returns true if successful, false
 * otherwise. A file may be removed regardless of whether it is open or
 * closed, and removing an open file does not close it. */
static bool
syscall_remove (const char *file) {
	if (file == NULL)
		return false;
	check_mem_space_read (file, 0, true);
	return filesys_remove(file);
}

/* Opens the file called file. Returns a nonnegative integer handle called
 * a "file descriptor" (fd), or -1 if the file could not be opened. File
 * descriptors numbered 0 and 1 are reserved for the console: fd 0
 * (STDIN_FILENO) is standard input, fd 1 (STDOUT_FILENO) is standard
 * output. The open system call will never return either of these file
 * descriptors, which are valid as system call arguments only as
 * explicitly described below. Each process has an independent set of file
 * descriptors. File descriptors are inherited by child processes. When a
 * single file is opened more than once, whether by a single process or
 * different processes, each open returns a new file descriptor. Different
 * file descriptors for a single file are closed independently in separate
 * calls to close and they do not share a file position. */
static int
syscall_open (const char *file) {
	struct file *f;

	if (file == NULL)
		return -1;
	check_mem_space_read (file, 0, true);
	f = filesys_open (file);
	if (f == NULL)
		return -1;
	return create_file_descriptor (f);
}

/* Opens a file descriptor in the current process' file descriptor table
	 and maps it to the given FILE. Returns -1 on failure, otherwise a file
	 descriptor (integer) in the range [0, MAX_FD], inclusive. */
static int
create_file_descriptor (struct file *file) {
	struct fd_table *fd_t = &thread_current ()->fd_t;
	struct file_descriptor *fd;

	ASSERT (file);
	ASSERT (fd_t->table);
	ASSERT (fd_t->size <= MAX_FD + 1);

	if (fd_t->size == MAX_FD + 1) { /* Full table. */
		file_close (file);
		return -1;
	}
	/* Find and return the fd with lowest index available. */
	for (int i = 0; i <= MAX_FD; i++) {
		fd = &fd_t->table[i];
		switch (fd->fd_st) {
			case FD_OPEN:
				if (fd->fd_file == NULL) {
					ASSERT ((fd->fd_t == FDT_STDIN || fd->fd_t == FDT_STDOUT)
							&& fd->dup_fds == NULL);
				} else
					ASSERT (fd->fd_t == FDT_OTHER && fd->dup_fds);
				break;
			case FD_CLOSE:
				ASSERT (fd->fd_t == FDT_OTHER && fd->fd_file == NULL && fd->dup_fds == NULL);
				fd->dup_fds = (uint8_t *)calloc (MAX_FD + 1, sizeof (uint8_t));
				if (!fd->dup_fds) {
					file_close (file);
					return -1;
				}
				fd->dup_fds[i] = 1;
				fd->fd_st = FD_OPEN;
				fd->fd_file = file;
				fd_t->size++;
				return i;
			default:
				ASSERT (0);
		}
	}
	ASSERT (0); /* Should not be reached. */
}

/* Returns the size, in bytes, of the file open as fd. */
static int
syscall_filesize (int fd) {
	struct fd_table *fd_t = &thread_current ()->fd_t;
	struct file_descriptor *file_descriptor;

	ASSERT (fd_t->table);
	ASSERT (fd_t->size <= MAX_FD + 1);

	if (fd < 0 || fd > MAX_FD)
		return -1;
	file_descriptor = &fd_t->table[fd];
	switch (file_descriptor->fd_st) {
		case FD_OPEN:
			if (file_descriptor->fd_file == NULL) {
				ASSERT ((file_descriptor->fd_t == FDT_STDIN
						|| file_descriptor->fd_t == FDT_STDOUT)
						&& file_descriptor->dup_fds == NULL);
				return -1;
			}
			ASSERT (file_descriptor->fd_t == FDT_OTHER
					&& file_descriptor->dup_fds);
			return (int)file_length (file_descriptor->fd_file);
		case FD_CLOSE:
			ASSERT (file_descriptor->fd_t == FDT_OTHER
					&& file_descriptor->fd_file == NULL
					&& file_descriptor->dup_fds == NULL);
			return -1;
		default:
			ASSERT (0);
	}
	ASSERT (0); /* Should not be reached. */
}

/* Reads length bytes from the file open as fd into buffer. Returns the
 * number of bytes actually read (0 at end of file), or -1 if the file
 * could not be read (due to a condition other than end of file). fd 0
 * reads from the keyboard using input_getc(). */
static int
syscall_read (int fd, void *buffer, unsigned length) {
	struct fd_table *fd_t = &thread_current ()->fd_t;
	struct file_descriptor *file_descriptor;
	uint8_t *ui8buffer = (uint8_t*)buffer;
	unsigned bytes_read = 0, bytes_left = length;

	check_mem_space_write (buffer, length);

	ASSERT (fd_t->table);
	ASSERT (fd_t->size <= MAX_FD + 1);

	if (fd < 0 || fd > MAX_FD)
		return -1;
	file_descriptor = &fd_t->table[fd];
	switch (file_descriptor->fd_st) {
		case FD_OPEN:
			if (file_descriptor->fd_file == NULL) {
				ASSERT ((file_descriptor->fd_t == FDT_STDIN
						|| file_descriptor->fd_t == FDT_STDOUT)
						&& file_descriptor->dup_fds == NULL);
				if (file_descriptor->fd_t == FDT_STDOUT)
					return -1;
				while (bytes_left > 0) {
					ui8buffer[bytes_read] = input_getc ();
					bytes_read++;
					bytes_left--;
				}
				return length;
			}
			ASSERT (file_descriptor->fd_t == FDT_OTHER
					&& file_descriptor->dup_fds);
			return (int)file_read (file_descriptor->fd_file, buffer, length);
		case FD_CLOSE:
			ASSERT (file_descriptor->fd_t == FDT_OTHER
					&& file_descriptor->fd_file == NULL
					&& file_descriptor->dup_fds == NULL);
			return -1;
		default:
			ASSERT (0);
	}
	ASSERT (0); /* Should not be reached. */
}

/* Writes size bytes from buffer to the open file fd. Returns the number
 * of bytes actually written, which may be less than size if some bytes
* could not be written (end-of-file reached), 0 meaning no bytes written
* at all. Writing past end-of-file would normally extend the file, but
* file growth is not implemented by the basic file system.
* fd 1 writes to the console (stdout). */
static int
syscall_write (int fd, const void *buffer, unsigned length) {
	struct fd_table *fd_t = &thread_current ()->fd_t;
	struct file_descriptor *file_descriptor;
	unsigned bytes_written, bytes_left = length;

	check_mem_space_read (buffer, length, false);

	ASSERT (fd_t->table);
	ASSERT (fd_t->size <= MAX_FD + 1);

	if (fd < 0 || fd > MAX_FD)
		return -1;
	file_descriptor = &fd_t->table[fd];
	switch (file_descriptor->fd_st) {
		case FD_OPEN:
			if (file_descriptor->fd_file == NULL) {
				ASSERT ((file_descriptor->fd_t == FDT_STDIN
						|| file_descriptor->fd_t == FDT_STDOUT)
						&& file_descriptor->dup_fds == NULL);
				if (file_descriptor->fd_t == FDT_STDIN)
					return -1;
				/* Write to stdout. */
				while (bytes_left > 0) {
					/* Write in 200-byte chunks. */
					bytes_written = (bytes_left > 200)? 200: bytes_left;
					putbuf (buffer + length - bytes_left, bytes_written);
					bytes_left -= bytes_written;
				}
				return length;
			}
			ASSERT (file_descriptor->fd_t == FDT_OTHER
					&& file_descriptor->dup_fds);
			return (int)file_write (file_descriptor->fd_file, buffer, length);
		case FD_CLOSE:
			ASSERT (file_descriptor->fd_t == FDT_OTHER
					&& file_descriptor->fd_file == NULL
					&& file_descriptor->dup_fds == NULL);
			return -1;
		default:
			ASSERT (0);
	}
	ASSERT (0); /* Should not be reached. */
}

/* Changes the next byte to be read or written in open file fd to
 * position, expressed in bytes from the beginning of the file (Thus, a
 * position of 0 is the file's start). A seek past the current end of a
 * file is not an error. A later read obtains 0 bytes, indicating end of
 * file. A later write extends the file, filling any unwritten gap with
 * zeros. (However, in Pintos files have a fixed length until project 4 is
 * complete, so writes past end of file will return an error.) These
 * semantics are implemented in the file system and do not require any
 * special effort in system call implementation. */
static void
syscall_seek (int fd, unsigned position) {
	struct fd_table *fd_t = &thread_current ()->fd_t;
	struct file_descriptor *file_descriptor;

	ASSERT (fd_t->table);
	ASSERT (fd_t->size <= MAX_FD + 1);

	if (fd < 0 || fd > MAX_FD)
		return;
	file_descriptor = &fd_t->table[fd];
	switch (file_descriptor->fd_st) {
		case FD_OPEN:
			if (file_descriptor->fd_file == NULL) {
				ASSERT ((file_descriptor->fd_t == FDT_STDIN
						|| file_descriptor->fd_t == FDT_STDOUT)
						&& file_descriptor->dup_fds == NULL);
				return;
			}
			ASSERT (file_descriptor->fd_t == FDT_OTHER
					&& file_descriptor->dup_fds);
			file_seek (file_descriptor->fd_file, position);
			return;
		case FD_CLOSE:
			ASSERT (file_descriptor->fd_t == FDT_OTHER
					&& file_descriptor->fd_file == NULL
					&& file_descriptor->dup_fds == NULL);
			return;
		default:
			ASSERT (0);
	}
	ASSERT (0); /* Should not be reached. */
}

/* Returns the position of the next byte to be read or written in open
* file fd, expressed in bytes from the beginning of the file. */
static unsigned
syscall_tell (int fd) {
	struct fd_table *fd_t = &thread_current ()->fd_t;
	struct file_descriptor *file_descriptor;

	ASSERT (fd_t->table);
	ASSERT (fd_t->size <= MAX_FD + 1);

	if (fd < 0 || fd > MAX_FD)
		return 0;
	file_descriptor = &fd_t->table[fd];
	switch (file_descriptor->fd_st) {
		case FD_OPEN:
			if (file_descriptor->fd_file == NULL) {
				ASSERT ((file_descriptor->fd_t == FDT_STDIN
						|| file_descriptor->fd_t == FDT_STDOUT)
						&& file_descriptor->dup_fds == NULL);
				return 0;
			}
			ASSERT (file_descriptor->fd_t == FDT_OTHER
					&& file_descriptor->dup_fds);
			return (unsigned)file_tell (file_descriptor->fd_file);
		case FD_CLOSE:
			ASSERT (file_descriptor->fd_t == FDT_OTHER
					&& file_descriptor->fd_file == NULL
					&& file_descriptor->dup_fds == NULL);
			return 0;
		default:
			ASSERT (0);
	}
	ASSERT (0); /* Should not be reached. */
}

/* Closes file descriptor fd. Exiting or terminating a process implicitly
 * closes all its open file descriptors, as if by calling this function
 * for each one. */
static void
syscall_close (int fd) {
	struct fd_table *fd_t = &thread_current ()->fd_t;
	struct file_descriptor *file_descriptor;

	ASSERT (fd_t->table);
	ASSERT (fd_t->size <= MAX_FD + 1);

	if (fd < 0 || fd > MAX_FD)
		return;
	file_descriptor = &fd_t->table[fd];
	switch (file_descriptor->fd_st) {
		case FD_OPEN:
			fd_t->size--;
			file_descriptor->fd_st = FD_CLOSE;
			if (file_descriptor->fd_file == NULL) {
				ASSERT ((file_descriptor->fd_t == FDT_STDIN
						|| file_descriptor->fd_t == FDT_STDOUT)
						&& file_descriptor->dup_fds == NULL);
				file_descriptor->fd_t = FDT_OTHER;
				return;
			}
			ASSERT (file_descriptor->fd_t == FDT_OTHER
					&& file_descriptor->dup_fds);
			if (file_open_cnt (file_descriptor->fd_file) == 1)
				free(file_descriptor->dup_fds);
			else
				file_descriptor->dup_fds[fd] = 0;
			file_close (file_descriptor->fd_file);
			file_descriptor->fd_file = NULL;
			file_descriptor->dup_fds = NULL;
			return;
		case FD_CLOSE:
			ASSERT (file_descriptor->fd_t == FDT_OTHER
					&& file_descriptor->fd_file == NULL
					&& file_descriptor->dup_fds == NULL);
			return;
		default:
			ASSERT (0);
	}
	ASSERT (0); /* Should not be reached. */
}

/* The dup2() system call creates a copy of the file descriptor oldfd with
 * the file descriptor number specified in newfd, and returns newfd on
 * success. If the file descriptor newfd was previously open, it is
 * silently closed before being reused.
 * Note the following points:
 * If oldfd is not a valid file descriptor, then the call fails (returns
 * -1), and newfd is not closed.
 * If oldfd is a valid file descriptor, and newfd has the same value as
 * oldfd, then dup2() does nothing, and returns newfd.
 * After a successful return from this system call, the old and new file
 * descriptors may be used interchangeably. Although they are different
 * file descriptors, they refer to the same open file description and thus
 * share file offset and status flags; for example, if the file offset is
 * modified by using seek on one of the descriptors, the offset is also
 * changed for the other. */
static int
syscall_dup2 (int oldfd, int newfd) {
	struct fd_table *fd_t = &thread_current ()->fd_t;
	struct file_descriptor *old_file_descriptor, *new_file_descriptor;

	ASSERT (fd_t->table);
	ASSERT (fd_t->size <= MAX_FD + 1);

	if (oldfd < 0 || oldfd > MAX_FD || newfd < 0 || newfd > MAX_FD)
		return -1;
	old_file_descriptor = &fd_t->table[oldfd];
	switch (old_file_descriptor->fd_st) {
		case FD_OPEN:
			ASSERT ((old_file_descriptor->fd_file == NULL
							&& old_file_descriptor->dup_fds == NULL
							&& (old_file_descriptor->fd_t == FDT_STDIN
									|| old_file_descriptor->fd_t == FDT_STDOUT))
					|| (old_file_descriptor->fd_file != NULL
							&& old_file_descriptor->fd_t == FDT_OTHER
							&& old_file_descriptor->dup_fds));
			if (oldfd == newfd)
				return newfd;
			syscall_close (newfd);
			new_file_descriptor = &fd_t->table[newfd];
			ASSERT (new_file_descriptor->fd_st == FD_CLOSE
					&& new_file_descriptor->fd_t == FDT_OTHER
					&& new_file_descriptor->fd_file == NULL
					&& new_file_descriptor->dup_fds == NULL);
			new_file_descriptor->fd_st = FD_OPEN;
			new_file_descriptor->fd_t = old_file_descriptor->fd_t;
			if (old_file_descriptor->fd_file) {
				ASSERT (old_file_descriptor->dup_fds);
				new_file_descriptor->fd_file = file_dup2 (old_file_descriptor->fd_file);
				new_file_descriptor->dup_fds = old_file_descriptor->dup_fds;
				new_file_descriptor->dup_fds[newfd] = 1;
			}
			fd_t->size++;
			return newfd;
		case FD_CLOSE:
			ASSERT (old_file_descriptor->fd_t == FDT_OTHER
					&& old_file_descriptor->fd_file == NULL
					&& old_file_descriptor->dup_fds == NULL);
			return -1;
		default:
			ASSERT (0);
	}
	ASSERT (0); /* Should not be reached. */
}

/* Maps length bytes the file open as fd starting from offset byte into the
 * process's virtual address space at addr.
 * The entire file is mapped into consecutive virtual pages starting at addr.
 * If the length of the file is not a multiple of PGSIZE, then some bytes in the
 * final mapped page "stick out" beyond the end of the file.
 * Set these bytes to zero when the page is faulted in, and discard them when
 * the page is written back to disk.
 * If successful, this function returns the virtual address where the file is
 * mapped. On failure, it must return NULL which is not a valid address to map
 * a file. */
static void *
syscall_mmap (void *addr, size_t length, int writable, int fd, off_t offset) {
	struct fd_table *fd_t = &thread_current ()->fd_t;
	struct file_descriptor *file_descriptor;
	struct file *newfile;

	ASSERT (fd_t->table);
	ASSERT (fd_t->size <= MAX_FD + 1);

	//check fail conditions
	if (length == 0 || !vm_is_page_addr(addr) || !is_user_vaddr (addr) || pg_ofs(offset) != 0
			|| fd < 0 || fd > MAX_FD)
		return NULL;


	file_descriptor = &fd_t->table[fd];
	if (file_descriptor->fd_t == FDT_STDIN || file_descriptor->fd_t == FDT_STDOUT)
		return NULL;
	switch (file_descriptor->fd_st) {
		case FD_OPEN:
			if (file_descriptor->fd_file == NULL)
				return NULL;
			ASSERT (file_descriptor->fd_t == FDT_OTHER
					&& file_descriptor->dup_fds);
			if (file_length (file_descriptor->fd_file) <= 0)
				return NULL;
			newfile = file_reopen (file_descriptor->fd_file);
			if (!newfile)
				return NULL;
			return do_mmap (addr, length, writable, newfile, offset);
		case FD_CLOSE:
			ASSERT (file_descriptor->fd_t == FDT_OTHER
					&& file_descriptor->fd_file == NULL
					&& file_descriptor->dup_fds == NULL);
			return NULL;
		default:
			ASSERT (0);
	}
	ASSERT (0); /* Should not be reached. */
}

/* Unmaps the mapping for the specified address range addr, which must be the
 * virtual address returned by a previous call to mmap by the same process that
 * has not yet been unmapped. */
static void
syscall_munmap (void *addr) {
	struct page *page;

	if (!vm_is_page_addr (addr))
		return;
	page = spt_find_page (&thread_current ()->spt, addr);
	if (!page || VM_TYPE (page->operations->type) != VM_FILE)
		return;
	do_munmap (addr);
}


/* Given the address ADDR of a memory space of size SIZE bytes, this
 * function checks if a memory violation occurs when trying to read from it.
 * If ADDR points to a string, the IS_STR variable must be set to true
 * (otherwise false) and SIZE must be 0.
 * If there is a memory violation (or ADDR is NULL), the process will be
 * terminated with exit status of -1, otherwise nothing happens. */
static void
check_mem_space_read (const void *addr_, const size_t size, const bool is_str) {
	uint8_t *addr = (uint8_t*)addr_;

	if (addr == NULL)
		thread_exit (-1);
	if (is_str) { /* String assumed. */
		ASSERT (size == 0);
		/* Check the first byte pointed to by ADDR. */
		if (!valid_user_addr (addr) || get_user (addr) == -1)
			thread_exit (-1);
		/* Check each byte of memory starting at ADDR+1 until NULL is found. */
		while (*addr) {
			addr++;
			if (!valid_user_addr (addr) || get_user (addr) == -1)
				thread_exit (-1);
		}
	}
	else {
		/* Check the SIZE-bytes of memory starting at ADDR. */
		for (size_t i = 0; i < size; i++) {
			if (!valid_user_addr (addr) || get_user (addr) == -1)
				thread_exit (-1);
			addr++;
		}
	}
}

/* Reads a byte at user virtual address UADDR.
 * UADDR must be below KERN_BASE.
 * Returns the byte value if successful, -1 if a segfault occurred. */
static int64_t
get_user (const uint8_t *uaddr) {
	int64_t result;
	__asm __volatile (
		"movabsq $done_get, %0\n"
		"movzbq %1, %0\n"
		"done_get:\n"
		: "=&a" (result) : "m" (*uaddr));
	return result;
}

/* Given the address ADDR of a memory space of size SIZE bytes, this
 * function checks if a memory violation occurs when trying to write on it.
 * If there is a memory violation (or ADDR is NULL), the process will be
 * terminated with exit status of -1, otherwise nothing happens.
 * The space will be set to 0s on success. */
static void
check_mem_space_write (const void *addr_, const size_t size) {
	uint8_t *addr = (uint8_t*)addr_;

	if (addr == NULL)
		thread_exit (-1);
	/* Check the SIZE-bytes of memory starting at ADDR. */
	for (size_t i = 0; i < size; i++) {
		if (!valid_user_addr (addr) || !put_user (addr, 0))
			thread_exit (-1);
		addr++;
	}
}

/* Writes BYTE to user address UDST.
 * UDST must be below KERN_BASE.
 * Returns true if successful, false if a segfault occurred. */
static bool
put_user (uint8_t *udst, uint8_t byte) {
	int64_t error_code;
	__asm __volatile (
		"movabsq $done_put, %0\n"
		"movb %b2, %1\n"
		"done_put:\n"
		: "=&a" (error_code), "=m" (*udst) : "q" (byte));
	return error_code != -1;
}

/* Checks if the given ADDR is in the user address space and mapped to a
	 kernel page. Returns TRUE if these two conditions are true, FALSE
	 otherwise. */
static bool
valid_user_addr (const uint8_t *addr_) {
	void *addr = (void*)addr_;
	struct thread *curr = thread_current ();
	return (is_user_vaddr(addr) && spt_find_page (&curr->spt, addr));
}
