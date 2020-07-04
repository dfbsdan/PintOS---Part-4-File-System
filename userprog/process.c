#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/mmu.h"
#include "threads/vaddr.h"
#include "intrinsic.h"
#include "devices/timer.h"
#ifdef VM
#include "vm/vm.h"
#endif

static struct terminated_child_st *terminated_child (tid_t child_tid);
static bool active_child (tid_t child_tid);
static void process_cleanup (bool exit);
static bool load (const char *command, struct intr_frame *if_);
static void initd (void *command);
static void __do_fork (void *);
static bool duplicate_fd_table (struct fd_table *parent_fd_t);

/* General process initializer for initd and other process. */
static void
process_init (void) {
	struct thread *current = thread_current ();
}

/* Starts the first userland program, called "initd", loaded from the first
 * word inside COMMAND.
 * The new thread may be scheduled (and may even exit)
 * before process_create_initd() returns. Returns the initd's
 * thread id, or TID_ERROR if the thread cannot be created.
 * Notice that THIS SHOULD BE CALLED ONCE. */
tid_t
process_create_initd (const char *command) {
	char *command_copy, *file_name, command_buf[strlen (command) +1], *save_ptr;
	tid_t tid;

	/* Get file_name. */
	strlcpy (command_buf, command, strlen (command) +1);
	file_name = strtok_r (command_buf, " ", &save_ptr);
	ASSERT (file_name != NULL);

	/* Make a copy of COMMAND.
	 * Otherwise there's a race between the caller and load(). */
	command_copy = palloc_get_page (0);
	if (command_copy == NULL)
		return TID_ERROR;
	strlcpy (command_copy, command, PGSIZE);

	/* Create a new thread to execute COMMAND. */
	tid = thread_create (file_name, PRI_DEFAULT, initd, command_copy);
	if (tid == TID_ERROR)
		palloc_free_page (command_copy);
	return tid;
}

/* A thread function that launches first user process. */
static void
initd (void *command) {
#ifdef VM
	if (!supplemental_page_table_init (&thread_current ()->spt))
		PANIC("Fail to launch initd (spt initializer)\n");
#endif

	process_init ();
	if (process_exec (command) < 0)
		PANIC("Fail to launch initd\n");
	NOT_REACHED ();
}

/* Clones the current process as `name`. Returns the new process's thread id, or
 * TID_ERROR if the thread cannot be created. */
tid_t
process_fork (const char *name, struct intr_frame *if_) {
	struct thread *curr = thread_current ();
	tid_t child_tid;
	struct terminated_child_st *child_st;
	struct parent_process_frame parent_frame;

	ASSERT (curr->fork_sema.value == 0);
	ASSERT (list_size (&curr->fork_sema.waiters) == 0);

	/* Clone current thread to new thread.*/
	parent_frame.parent = curr;
	parent_frame.f = if_;
	child_tid = thread_create (name, PRI_DEFAULT, __do_fork, &parent_frame);
	if (child_tid == TID_ERROR)
		return TID_ERROR;
	/* Wait for child to finish forking. */
	sema_down (&curr->fork_sema);
	/* Check if the child finished with some error. */
	if (!active_child (child_tid)) {
		child_st = terminated_child (child_tid);
		if (child_st == NULL)
			return TID_ERROR;
		if (child_st->exit_status == -1) {
			process_wait (child_tid);
			return TID_ERROR;
		}
	}
	return child_tid;
}

#ifndef VM
/* Duplicate the parent's address space by passing this function to the
 * pml4_for_each. This is only for the project 2. */
static bool
duplicate_pte (uint64_t *pte, void *va, void *aux) {
	struct thread *current = thread_current ();
	struct thread *parent = (struct thread *) aux;
	void *parent_page;
	void *newpage;
	bool writable;

	/* If the parent_page is kernel page, then return immediately (skip). */
	if (is_kern_pte (pte))
		return true;

	/* Resolve VA from the parent's page map level 4. */
	parent_page = pml4_get_page (parent->pml4, va);

	/* Allocate new PAL_USER page for the child and set result to NEWPAGE. */
	newpage = palloc_get_page (PAL_USER);
	if (newpage == NULL)
		return false;

	/* Duplicate parent's page to the new page and check whether parent's
	 * page is writable or not (set WRITABLE according to the result). */
	memcpy (newpage, parent_page, PGSIZE);
	writable = is_writable (pte);

	/* Add new page to child's page table at address VA with WRITABLE
	 * permission. */
	if (!pml4_set_page (current->pml4, va, newpage, writable)) {
		/* Fail to insert page. */
		palloc_free_page (newpage);
		return false;
	}
	return true;
}
#endif

/* A thread function that copies parent's execution context. */
static void
__do_fork (void *aux) {
	struct intr_frame if_, *parent_if;
	struct parent_process_frame *parent_frame;
	struct thread *parent;
	struct thread *current = thread_current ();

	parent_frame = (struct parent_process_frame *)aux;
	parent = parent_frame->parent;
	/* Pass the parent_if. (i.e. process_fork()'s if_) */
	parent_if = parent_frame->f;

	ASSERT (thread_is_user (parent));
	ASSERT (parent->fork_sema.value == 0);

	/* Make sure parent waits for forking finalization. */
	while (list_size (&parent->fork_sema.waiters) == 0)
		thread_yield ();

	/* Read the cpu context to local stack. */
	memcpy (&if_, parent_if, sizeof (struct intr_frame));
	/* Return 0 on child's fork() call. */
	if_.R.rax = 0;

	/* Duplicate PT */
	current->pml4 = pml4_create();
	if (current->pml4 == NULL)
		goto error;

	process_activate (current);
#ifdef VM
	if (!supplemental_page_table_init (&current->spt)
			|| !supplemental_page_table_copy (&current->spt, &parent->spt))
		goto error;
#else
	if (!pml4_for_each (parent->pml4, duplicate_pte, parent))
		goto error;
#endif

	/* Duplicate parent's fd table. */
	if (!duplicate_fd_table (&parent->fd_t))
		goto error;

	/* Reopen parent's executable file and deny write on it. */
	current->executable = file_reopen (parent->executable);
	if (current->executable == NULL)
		goto error;
	file_deny_write (current->executable);

	process_init ();

	/* Finally, switch to the newly created process and wake up parent.
		 This part should be reched ONLY on a successful forking. */
	sema_up (&parent->fork_sema);
	do_iret (&if_);
	ASSERT (0); /* Should not be reached. */
error:
	sema_up (&parent->fork_sema);
	thread_exit (-1);
}

/* Duplicates the given PARENT FD TABLE into the current thread's. Returns
 * TRUE on success, FALSE otherwise. */
static bool
duplicate_fd_table (struct fd_table *parent_fd_t) {
	struct fd_table *curr_fd_t = &thread_current ()->fd_t;
	struct file_descriptor *parent_fd, *curr_fd, *dup_fd;
	enum intr_level old_level;
	size_t dup_cnt;

	ASSERT (parent_fd_t);
	ASSERT (parent_fd_t->table);
	ASSERT (curr_fd_t);
	ASSERT (curr_fd_t->table);

	old_level = intr_disable ();
	/* Initialize size to 0. */
	curr_fd_t->size = 0;
	/* Initially close stdin and stdout. */
	curr_fd = &curr_fd_t->table[0];
	curr_fd->fd_st = FD_CLOSE;
	curr_fd->fd_t = FDT_OTHER;
	curr_fd = &curr_fd_t->table[1];
	curr_fd->fd_st = FD_CLOSE;
	curr_fd->fd_t = FDT_OTHER;

	/* Copy file descriptors. */
	for (int i = 0; i <= MAX_FD; i++) {
		parent_fd = &parent_fd_t->table[i];
		curr_fd = &curr_fd_t->table[i];
		switch (curr_fd->fd_st) {
			case FD_OPEN:
				if (curr_fd->fd_file == NULL) {
					ASSERT ((curr_fd->fd_t == FDT_STDIN || curr_fd->fd_t == FDT_STDOUT)
							&& curr_fd->dup_fds == NULL);
				} else
					ASSERT (curr_fd->fd_t == FDT_OTHER && curr_fd->dup_fds);
				break;
			case FD_CLOSE:
				ASSERT (curr_fd->fd_file == NULL && curr_fd->fd_t == FDT_OTHER
						&& curr_fd->dup_fds == NULL);
				switch (parent_fd->fd_st) {
					case FD_OPEN:
						/* Copy open fd. */
						if (parent_fd->fd_file) {
							ASSERT (parent_fd->fd_t == FDT_OTHER && parent_fd->dup_fds);
							curr_fd->dup_fds = (uint8_t *)calloc (MAX_FD + 1, sizeof (uint8_t));
							if (!curr_fd->dup_fds) {
								intr_set_level (old_level);
								return false;
							}
							curr_fd->dup_fds[i] = 1;
							curr_fd->fd_file = file_duplicate (parent_fd->fd_file);
							if (!curr_fd->fd_file) {
								free (curr_fd->dup_fds);
								curr_fd->dup_fds = NULL;
								intr_set_level (old_level);
								return false;
							}
							/* Copy duplicated fds (with dup2()). */
							if (file_open_cnt (parent_fd->fd_file) > 1) {
								dup_cnt = 1;
								for (int k = i + 1;
										k <= MAX_FD && dup_cnt != file_open_cnt (parent_fd->fd_file);
										k++) {
									if (parent_fd->dup_fds[k]) {
										dup_fd = &curr_fd_t->table[k];
										ASSERT (dup_fd->fd_st == FD_CLOSE
												&& dup_fd->fd_t == FDT_OTHER
												&& dup_fd->fd_file == NULL
												&& dup_fd->dup_fds == NULL);
										dup_fd->fd_st = FD_OPEN;
										dup_fd->fd_file = file_dup2 (curr_fd->fd_file);
										dup_fd->dup_fds = curr_fd->dup_fds;
										dup_fd->dup_fds[k] = 1;
										dup_cnt++;
										curr_fd_t->size++;
									}
								}
							}
							ASSERT (file_open_cnt (curr_fd->fd_file) == file_open_cnt (parent_fd->fd_file));
						} else
							ASSERT ((parent_fd->fd_t == FDT_STDIN || parent_fd->fd_t == FDT_STDOUT)
									&& parent_fd->dup_fds == NULL);
						curr_fd->fd_st = FD_OPEN;
						curr_fd->fd_t = parent_fd->fd_t;
						curr_fd_t->size++;
						break;
					case FD_CLOSE:
						ASSERT (parent_fd->fd_file == NULL && parent_fd->fd_t == FDT_OTHER
								&& parent_fd->dup_fds == NULL);
						break;
					default:
						ASSERT (0);
				}
				break;
			default:
				ASSERT (0);
		}
	}
	ASSERT (curr_fd_t->size == parent_fd_t->size);
	intr_set_level (old_level);
	return true;
}

/* Switch the current execution context to the f_name.
 * Returns -1 on fail. */
int
process_exec (void *command_) {
	char *command = command_;
	bool success;

	/* We cannot use the intr_frame in the thread structure.
	 * This is because when current thread rescheduled,
	 * it stores the execution information to the member. */
	struct intr_frame _if;
	_if.ds = _if.es = _if.ss = SEL_UDSEG;
	_if.cs = SEL_UCSEG;
	_if.eflags = FLAG_IF | FLAG_MBS;

	/* We first kill the current context */
	process_cleanup (false);

	/* And then load the binary */
	success = load (command, &_if);

	/* If load failed, quit. */
	palloc_free_page (command);
	if (!success)
	{
		//printf("process_exec: loading failed\n"); //////////////////////////////////TEMPORAL: TESTING
		return -1;
	}
	/* Start switched process. */
	do_iret (&_if);
	NOT_REACHED ();
}


/* Waits for thread TID to die and returns its exit status.  If
 * it was terminated by the kernel (i.e. killed due to an
 * exception), returns -1.  If TID is invalid or if it was not a
 * child of the calling process, or if process_wait() has already
 * been successfully called for the given TID, returns -1
 * immediately, without waiting.
 *
 * This function will be implemented in problem 2-2.  For now, it
 * does nothing. */
int
process_wait (tid_t child_tid) {
	struct terminated_child_st *child_st;
	int exit_status;

	if (!terminated_child (child_tid) && !active_child (child_tid))
		return -1;
	while (active_child (child_tid) && !terminated_child (child_tid))
		thread_yield (); //Wait for child's termination
	/* Get child's exit status. */
	child_st = terminated_child (child_tid);
	ASSERT (child_st);
	exit_status = child_st->exit_status;
	/* Clean up. */
	list_remove (&child_st->elem);
	free (child_st);
	return exit_status;
}

/* Given a CHILD_TID tid, this function tries to find if such tid
 * corresponds to a current thread's terminated child's tid by looking at
 * its terminated_children_st list. If such tid is found, the corresponding
 * terminated_child_st structure (created on its termination) is returned
 * as a pointer.
 * Returns NULL if such element is not found. */
static struct terminated_child_st *
terminated_child (tid_t child_tid) {
	struct thread *curr = thread_current ();
	struct list_elem *child_st_elem;
	struct terminated_child_st *child_st;
	enum intr_level old_level;

	old_level = intr_disable ();
	if (!list_empty (&curr->terminated_children_st)) {
		for (child_st_elem = list_front (&curr->terminated_children_st);
				child_st_elem != list_end (&curr->terminated_children_st);
				child_st_elem = list_next (child_st_elem)) {
			child_st = list_entry (child_st_elem, struct terminated_child_st, elem);
			if (child_st->pid == child_tid) {
				intr_set_level (old_level);
				return child_st;
			}
		}
	}
	intr_set_level (old_level);
	return NULL;
}

/* Given a CHILD_TID tid, this function tries to find if such tid
 * corresponds to a current thread's active child's tid by looking at
 * its active_children list. If such child is found returns TRUE, otherwise
 * FALSE. */
static bool
active_child (tid_t child_tid) {
	struct thread *child, *curr = thread_current ();
	struct list_elem *child_elem;
	enum intr_level old_level;

	old_level = intr_disable ();
	if (!list_empty (&curr->active_children)) {
		for (child_elem = list_front (&curr->active_children);
				child_elem != list_end (&curr->active_children);
				child_elem = list_next (child_elem)) {
			child = list_entry (child_elem, struct thread, active_child_elem);
			if (child->tid == child_tid) {
				intr_set_level (old_level);
				return true;
			}
		}
	}
	intr_set_level (old_level);
	return false;
}

/* Exit the process. This function is called by thread_exit (). */
void
process_exit (int status) {
	struct thread *child, *curr = thread_current ();
	struct terminated_child_st *child_st;
	struct list_elem *child_elem;
	struct file_descriptor *fd;
	enum intr_level old_level;

	old_level = intr_disable ();

	curr->exit_status = status;
	if (thread_is_user (curr)) {
		ASSERT (curr->fd_t.table);
		ASSERT (curr->fd_t.size <= MAX_FD + 1);
		/* Report termination to parent, if any. */
		if (curr->parent) {
			/* Remove from parent's active_children list. */
			list_remove (&curr->active_child_elem);
			/* Report exit status to parent. */
			child_st = (struct terminated_child_st*)malloc (sizeof (struct terminated_child_st));
			if (child_st != NULL) {
				child_st->pid = curr->tid;
				child_st->exit_status = curr->exit_status;
				list_push_back (&curr->parent->terminated_children_st, &child_st->elem);
			}
		}
		/* Destroy file descriptor table. */
		for (int i = 0; i <= MAX_FD; i++) {
			fd = &curr->fd_t.table[i];
			switch (fd->fd_st) {
				case FD_OPEN:
					if (fd->fd_file == NULL) {
						ASSERT (fd->fd_t == FDT_STDIN || fd->fd_t == FDT_STDOUT);
						break;
					}
					ASSERT (fd->fd_t == FDT_OTHER && fd->dup_fds != NULL);
					if (file_open_cnt (fd->fd_file) == 1)
						free(fd->dup_fds);
					file_close (fd->fd_file);
					break;
				case FD_CLOSE:
					ASSERT (fd->fd_t == FDT_OTHER && fd->fd_file == NULL && fd->dup_fds == NULL);
					break;
				default:
					ASSERT (0);
			}
		}
		free (curr->fd_t.table);
		if (!thread_tests) {
			if (curr->executable)
				file_close(curr->executable);
			else //Debugging purposes
				ASSERT (status == -1);
			/* Print exit status. */
			printf ("%s: exit(%d)\n", curr->name, curr->exit_status);
		}
	} else { //Debugging purposes
		ASSERT (curr->executable == NULL);
		ASSERT (curr->fd_t.table == NULL);
	}

	if (curr->curr_dir) dir_close(curr->curr_dir);

	/* Destroy unfreed information of finished child processes (this occurs
	 * when wait() is not called on a pid). */
	while (!list_empty (&curr->terminated_children_st)) {
		child_elem = list_pop_front (&curr->terminated_children_st);
		child_st = list_entry (child_elem, struct terminated_child_st, elem);
		free (child_st);
	}
	/* Report termination to children. */
	if (!list_empty (&curr->active_children)) {
		for (child_elem = list_front (&curr->active_children);
				child_elem != list_end (&curr->active_children);
				child_elem = list_next (child_elem)) {
			child = list_entry (child_elem, struct thread, active_child_elem);
			child->parent = NULL;
		}
	}


	intr_set_level (old_level);
	process_cleanup (true);
}

/* Free the current process's resources. The EXIT argument defines if the
 * cleanup process is done in order to finish a process completely (i.e.
 * process_exit ()), or in order to change its execution context (i.e.
 * process_exec ()). */
static void
process_cleanup (bool exit) {
	struct thread *curr = thread_current ();

#ifdef VM
	supplemental_page_table_kill (&curr->spt, exit);
#endif

	uint64_t *pml4;
	/* Destroy the current process's page directory and switch back
	 * to the kernel-only page directory. */
	pml4 = curr->pml4;
	if (pml4 != NULL) {
		/* Correct ordering here is crucial.  We must set
		 * cur->pagedir to NULL before switching page directories,
		 * so that a timer interrupt can't switch back to the
		 * process page directory.  We must activate the base page
		 * directory before destroying the process's page
		 * directory, or our active page directory will be one
		 * that's been freed (and cleared). */
		curr->pml4 = NULL;
		pml4_activate (NULL);
		pml4_destroy (pml4);
	}
}

/* Sets up the CPU for running user code in the nest thread.
 * This function is called on every context switch. */
void
process_activate (struct thread *next) {
	/* Activate thread's page tables. */
	pml4_activate (next->pml4);

	/* Set thread's kernel stack for use in processing interrupts. */
	tss_update (next);
}

/* We load ELF binaries.  The following definitions are taken
 * from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
#define EI_NIDENT 16

#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
 * This appears at the very beginning of an ELF binary. */
struct ELF64_hdr {
	unsigned char e_ident[EI_NIDENT];
	uint16_t e_type;
	uint16_t e_machine;
	uint32_t e_version;
	uint64_t e_entry;
	uint64_t e_phoff;
	uint64_t e_shoff;
	uint32_t e_flags;
	uint16_t e_ehsize;
	uint16_t e_phentsize;
	uint16_t e_phnum;
	uint16_t e_shentsize;
	uint16_t e_shnum;
	uint16_t e_shstrndx;
};

struct ELF64_PHDR {
	uint32_t p_type;
	uint32_t p_flags;
	uint64_t p_offset;
	uint64_t p_vaddr;
	uint64_t p_paddr;
	uint64_t p_filesz;
	uint64_t p_memsz;
	uint64_t p_align;
};

/* Abbreviations */
#define ELF ELF64_hdr
#define Phdr ELF64_PHDR

static bool setup_stack (struct intr_frame *if_, int argc, char **argv);
static int get_argc (const char* command);
static char **parse_command (int argc, char *file_name, char *save_ptr);
static bool validate_segment (const struct Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes,
		bool writable);

/* Loads an ELF executable from COMMAND into the current thread.
 * Stores the executable's entry point into *RIP
 * and its initial stack pointer into *RSP.
 * Returns true if successful, false otherwise. */
static bool
load (const char *command, struct intr_frame *if_) {
	struct thread *t = thread_current ();
	struct ELF ehdr;
	struct file *file = NULL;
	char *command_copy, *file_name, *save_ptr, **argv = NULL;
	off_t file_ofs;
	bool success = false;
	int i, argc;

	/* Allocate and activate page directory. */
	t->pml4 = pml4_create ();
	if (t->pml4 == NULL)
	{
		//printf("load: pml4_create\n"); /////////////////////////////////////////////TEMPORAL: TESTING
		return false;
	}
	process_activate (thread_current ());

	/* Avoid race conditions by copying the command. */
	command_copy = (char*)malloc (strlen (command) + 1);
	if (command_copy == NULL)
	{
		//printf("load: command_copy\n"); ////////////////////////////////////////////TEMPORAL: TESTING
		return false;
	}
  strlcpy (command_copy, command, strlen (command) + 1);
  file_name = strtok_r (command_copy, " ", &save_ptr);
	if (file_name == NULL)
	{
		//printf("load: file_name\n"); ///////////////////////////////////////////////TEMPORAL: TESTING
		goto done;
	}
	/* Open executable file. */
	file = filesys_open (file_name);
	if (file == NULL) {
		printf ("load: %s: open failed\n", file_name);
		goto done;
	}
	ASSERT (!t->executable);
	t->executable = file; /* Assign executable file. */
	file_deny_write(t->executable); /* Deny write. */

	/* Read and verify executable header. */
	if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
			|| memcmp (ehdr.e_ident, "\177ELF\2\1\1", 7)
			|| ehdr.e_type != 2
			|| ehdr.e_machine != 0x3E // amd64
			|| ehdr.e_version != 1
			|| ehdr.e_phentsize != sizeof (struct Phdr)
			|| ehdr.e_phnum > 1024) {
		printf ("load: %s: error loading executable\n", file_name);
		goto done;
	}

	/* Read program headers. */
	file_ofs = ehdr.e_phoff;
	for (i = 0; i < ehdr.e_phnum; i++) {
		struct Phdr phdr;

		if (file_ofs < 0 || file_ofs > file_length (file))
			goto done;
		file_seek (file, file_ofs);

		if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
			goto done;
		file_ofs += sizeof phdr;
		switch (phdr.p_type) {
			case PT_NULL:
			case PT_NOTE:
			case PT_PHDR:
			case PT_STACK:
			default:
				/* Ignore this segment. */
				break;
			case PT_DYNAMIC:
			case PT_INTERP:
			case PT_SHLIB:
				goto done;
			case PT_LOAD:
				if (validate_segment (&phdr, file)) {
					bool writable = (phdr.p_flags & PF_W) != 0;
					uint64_t file_page = phdr.p_offset & ~PGMASK;
					uint64_t mem_page = phdr.p_vaddr & ~PGMASK;
					uint64_t page_offset = phdr.p_vaddr & PGMASK;
					uint32_t read_bytes, zero_bytes;
					if (phdr.p_filesz > 0) {
						/* Normal segment.
						 * Read initial part from disk and zero the rest. */
						read_bytes = page_offset + phdr.p_filesz;
						zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
								- read_bytes);
					} else {
						/* Entirely zero.
						 * Don't read anything from disk. */
						read_bytes = 0;
						zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
					}
					if (!load_segment (file, file_page, (void *) mem_page,
								read_bytes, zero_bytes, writable))
					{
						printf("load: load_segment\n"); ////////////////////////////////////TEMPORAL: TESTING
						goto done;
					}
				}
				else
					goto done;
				break;
		}
	}

	/* Set up stack. */
	argc = get_argc (command);
  argv = parse_command (argc, file_name, save_ptr);
	if (!setup_stack (if_, argc, argv))
	{
		printf("load: setup_stack\n"); /////////////////////////////////////////////TEMPORAL: TESTING
		goto done;
	}
	/* Start address. */
	if_->rip = ehdr.e_entry;

	success = true;

done:
	/* We arrive here whether the load is successful or not. */
	if (argv != NULL)
		free (argv);
	free (command_copy);
	return success;
}

/* Gets the number of arguments in a given COMMAND (including
   the filename). */
static int
get_argc (const char* command) {
	char command_copy[strlen (command) +1], *arg, *save_ptr;
	int argc = 0;

	strlcpy (command_copy, command, strlen (command) +1);
	for (arg = strtok_r (command_copy, " ", &save_ptr); arg != NULL;
			arg = strtok_r (NULL, " ", &save_ptr))
		argc++;
	return argc;
}

/* Makes an argument vector holding the FILE_NAME given in a command
   as well as all the arguments given. strtok_r must have been called
   once in the original command buffer so that SAVE_PTR will be used
   now as an argument to strtok_r. */
static char **
parse_command (int argc, char *file_name, char *save_ptr) {
  char **argv, *arg;

	ASSERT (argc >= 0);

	if (argc == 0) return NULL;
  argv = (char**)malloc (argc * sizeof (char*));
	ASSERT (argv);
  /* Add all the arguments to ARGV (including FILE_NAME). */
  argv[0] = file_name;
  for (int i = 1; i < argc; i++) {
      arg = strtok_r (NULL, " ", &save_ptr);
      argv[i] = arg;
  }
  return argv;
}

/* Checks whether PHDR describes a valid, loadable segment in
 * FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Phdr *phdr, struct file *file) {
	/* p_offset and p_vaddr must have the same page offset. */
	if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
		return false;

	/* p_offset must point within FILE. */
	if (phdr->p_offset > (uint64_t) file_length (file))
		return false;

	/* p_memsz must be at least as big as p_filesz. */
	if (phdr->p_memsz < phdr->p_filesz)
		return false;

	/* The segment must not be empty. */
	if (phdr->p_memsz == 0)
		return false;

	/* The virtual memory region must both start and end within the
	   user address space range. */
	if (!is_user_vaddr ((void *) phdr->p_vaddr))
		return false;
	if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
		return false;

	/* The region cannot "wrap around" across the kernel virtual
	   address space. */
	if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
		return false;

	/* Disallow mapping page 0.
	   Not only is it a bad idea to map page 0, but if we allowed
	   it then user code that passed a null pointer to system calls
	   could quite likely panic the kernel by way of null pointer
	   assertions in memcpy(), etc. */
	if (phdr->p_vaddr < PGSIZE)
		return false;

	/* It's okay. */
	return true;
}

#ifndef VM
/* Codes of this block will be ONLY USED DURING project 2.
 * If you want to implement the function for whole project 2, implement it
 * outside of #ifndef macro. */

/* load() helpers. */
static bool install_page (void *upage, void *kpage, bool writable);

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	ASSERT (0);//Not reached in project 4

	file_seek (file, ofs);
	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* Get a page of memory. */
		uint8_t *kpage = palloc_get_page (PAL_USER);
		if (kpage == NULL)
			return false;

		/* Load this page. */
		if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes) {
			palloc_free_page (kpage);
			return false;
		}
		memset (kpage + page_read_bytes, 0, page_zero_bytes);

		/* Add the page to the process's address space. */
		if (!install_page (upage, kpage, writable)) {
			printf("fail\n");
			palloc_free_page (kpage);
			return false;
		}

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}

/* Initializes a process' stack. */
static bool
setup_stack (struct intr_frame *if_, const int argc, char **argv) {
	uint8_t *kpage, *esp = (uint8_t*)USER_STACK;
	bool success = false;
	int i;

	kpage = palloc_get_page (PAL_USER | PAL_ZERO);
	if (kpage != NULL) {
		success = install_page (((uint8_t *) USER_STACK) - PGSIZE, kpage, true);
		if (success)
			if_->rsp = USER_STACK;
		else
			palloc_free_page (kpage);
	}
	/* If the page was successfully created, place the
	arguments in the stack. */
	if (success) {
		/* Push all the arguments in decreasing order. */
		for (i = argc - 1; i >= 0; i--) {
				esp -= strlen (argv[i]) + 1;
				memcpy (esp, argv[i], strlen (argv[i]) + 1);
				argv[i] = (char*)esp;
		}
		/* Align the arguments with the 64-bit system. */
		i = 0;
		while(((uint64_t)esp % 8) != 0) {
				esp--;
				i++;
		}
		ASSERT (i < 8);
		memset (esp, 0, i);
		/* Push NULL pointer (end of argv). */
		esp -= sizeof (char*);
		memset (esp, 0, sizeof (char*));
		/* Push the address of each argument. */
		for (i = argc - 1; i >= 0; i--) {
				esp -= sizeof (char*);
				memcpy (esp, &argv[i], sizeof (char*));
		}
		/* Set argument registers. */
		if_->R.rdi = (uint64_t)argc;
		if_->R.rsi = (uint64_t)esp;
		/* Leave a space for the return address. */
		esp -= sizeof (void*);
		memset (esp, 0, sizeof (void*));
		/* Set process' initial stack pointer. */
		if_->rsp = (uintptr_t)esp;
	}
	return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
 * virtual address KPAGE to the page table.
 * If WRITABLE is true, the user process may modify the page;
 * otherwise, it is read-only.
 * UPAGE must not already be mapped.
 * KPAGE should probably be a page obtained from the user pool
 * with palloc_get_page().
 * Returns true on success, false if UPAGE is already mapped or
 * if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable) {
	struct thread *t = thread_current ();

	/* Verify that there's not already a page at that virtual
	 * address, then map our page there. */
	return (pml4_get_page (t->pml4, upage) == NULL
			&& pml4_set_page (t->pml4, upage, kpage, writable));
}
#else
/* From here, codes will be used after project 3.
 * If you want to implement the function for only project 2, implement it on the
 * upper block. */

/* Structure used in lazy_load_segment and load_segment in order to fetch the
 * executable's data. */
struct load_segment_aux {
	struct file *file;	/* Source file (executable) for segment loading. */
	off_t offset;				/* File's offset to read from. */
	size_t read_bytes;	/* Number of bytes to read from FILE. */
};

static bool
lazy_load_segment (struct page *page, void *aux_) {
	void *kva;
	struct load_segment_aux *aux;
	struct file *file;
	off_t offset;
	size_t read_bytes;

	/* Load the segment from the file.
	 * This called when the first page fault occurs on address VA.
	 * VA is available when calling this function. */
	//printf("lazy_load_segment\n"); ///////////////////////////////////////////////TEMPORAL: TESTING
	ASSERT (page && page->frame && thread_is_user (page->t));
	kva = page->frame->kva;
	ASSERT (kva);
	ASSERT (spt_find_page (&page->t->spt, page->va) == page);
	ASSERT (pml4_get_page (page->t->pml4, page->va) == kva);
	aux = (struct load_segment_aux*)aux_;
	ASSERT (aux);
	file = aux->file;
	offset = aux->offset;
	read_bytes = aux->read_bytes;
	free (aux);
	ASSERT (file);
	ASSERT (((size_t)offset + read_bytes) <= (size_t)file_length (file));
	ASSERT (read_bytes <= PGSIZE);

	/* Read the data and fill the rest of the page with zeroes. */
	if ((size_t)file_read_at (file, kva, read_bytes, offset) == read_bytes) {
		if (read_bytes < PGSIZE)
			memset (kva + read_bytes, 0, PGSIZE - read_bytes);
		//printf("lazy_load_segment: success\n"); ////////////////////////////////////TEMPORAL: TESTING
		return true;
	}
	printf("lazy_load_segment: failure\n"); //////////////////////////////////////TEMPORAL: TESTING
	return false;
}

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	struct load_segment_aux *aux;

	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	//printf("load_segment\n");/////////////////////////////////////////////////////TEMPORAL: TESTING
	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		aux = (struct load_segment_aux*)malloc (sizeof (struct load_segment_aux));
		if (!aux)
			return false;
		aux->file = file;
		aux->offset = ofs;
		aux->read_bytes = page_read_bytes;
		if (!vm_alloc_page_with_initializer (VM_ANON | VM_ANON_EXEC, upage,
					writable, lazy_load_segment, aux))
			return false;

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
		ofs += page_read_bytes;
	}
	return true;
}

/* Create a PAGE of stack at the USER_STACK. Return true on success. */
static bool
setup_stack (struct intr_frame *if_, int argc, char **argv) {
	void *stack_bottom = (void *) (((uint8_t *) USER_STACK) - PGSIZE);
	uint8_t *esp = (uint8_t*)USER_STACK;
	int i;

	/* Map the stack on stack_bottom and claim the page immediately. The page is
	 * marked as stack automatically by including VM_ANON_STACK here (see
	 * anon_initializer()). */
	//printf("setup_stack: Setting up stack page\n"); //////////////////////////////TEMPORAL: TESTING
	if (!(vm_alloc_page (VM_ANON | VM_ANON_STACK, stack_bottom, true)
			&& vm_claim_page (stack_bottom, &thread_current ()->spt)))
		return false;
	//printf("setup_stack: Stack page obtained successfully\n"); ///////////////////TEMPORAL: TESTING
	/* Push all the arguments in decreasing order. */
	for (i = argc - 1; i >= 0; i--) {
			esp -= strlen (argv[i]) + 1;
			memcpy (esp, argv[i], strlen (argv[i]) + 1);
			argv[i] = (char*)esp;
	}
	/* Align the arguments with the 64-bit system. */
	i = 0;
	while(((uint64_t)esp % 8) != 0) {
			esp--;
			i++;
	}
	ASSERT (i < 8);
	memset (esp, 0, i);
	/* Push NULL pointer (end of argv). */
	esp -= sizeof (char*);
	memset (esp, 0, sizeof (char*));
	/* Push the address of each argument. */
	for (i = argc - 1; i >= 0; i--) {
			esp -= sizeof (char*);
			memcpy (esp, &argv[i], sizeof (char*));
	}
	/* Set argument registers. */
	if_->R.rdi = (uint64_t)argc;
	if_->R.rsi = (uint64_t)esp;
	/* Leave a space for the return address. */
	esp -= sizeof (void*);
	memset (esp, 0, sizeof (void*));
	/* Set process' initial stack pointer. */
	if_->rsp = (uintptr_t)esp;
	//printf("setup_stack: success\n"); ////////////////////////////////////////////TEMPORAL: TESTING
	return true;
}
#endif /* VM */
