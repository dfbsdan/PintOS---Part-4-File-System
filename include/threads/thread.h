#ifndef THREADS_THREAD_H
#define THREADS_THREAD_H

#include <debug.h>
#include <list.h>
#include <stdint.h>
#include "threads/interrupt.h"
#ifdef VM
#include "vm/vm.h"
#endif

#ifdef USERPROG
#include "threads/synch.h"

#define MAX_FD 511 /* Max allowed file descriptor per process. */

/* Allowed states of a file descriptor. */
enum fd_status {FD_CLOSE, FD_OPEN};

/* Allowed types of file descriptor. */
enum fd_type {FDT_STDIN, FDT_STDOUT, FDT_OTHER};

/* File descriptor structure. */
struct file_descriptor {
	/* Status of the file descriptor. */
	enum fd_status fd_st;
	/* Type of the file descriptor. If the fd is closed or open and
		 associated with a file, this has to be FDT_OTHER, if open and not
		 associated, either FDT_STDIN or FDT_STDOUT. */
	enum fd_type fd_t;
	/* File associated with the fd. If the fd is open, this has to be a
		 valid file pointer unless its type is FDT_STDIN or FDT_STDOUT.
		 If the fd is closed, FILE is always NULL */
	struct file *fd_file;
	/* Holds the indexes of open duplicated file descriptors (with dup2()). Shared
		 by all those fds that point to the same file. By default, STDIN and STDOUT
		 file descriptors hold a NULL pointer. */
	uint8_t *dup_fds;
};

/* Structure holding the file descriptors of a process. */
struct fd_table {
	/* Keeps track of the number of opened file descriptors. */
	size_t size;
	/* File descriptor table of a process.
		 Each index corresponds to a file descriptor in the range [0, MAX_FD],
		 inclusive. */
	struct file_descriptor *table;
};
#endif

/* States in a thread's life cycle. */
enum thread_status {
	THREAD_RUNNING,     /* Running thread. */
	THREAD_READY,       /* Not running but ready to run. */
	THREAD_BLOCKED,     /* Waiting for an event to trigger. */
	THREAD_DYING        /* About to be destroyed. */
};

/* Thread identifier type.
   You can redefine this to whatever type you like. */
typedef int tid_t;
#define TID_ERROR ((tid_t) -1)          /* Error value for tid_t. */

/* Thread priorities. */
#define PRI_MIN 0                       /* Lowest priority. */
#define PRI_DEFAULT 31                  /* Default priority. */
#define PRI_MAX 63                      /* Highest priority. */

/* A kernel thread or user process.
 *
 * Each thread structure is stored in its own 4 kB page.  The
 * thread structure itself sits at the very bottom of the page
 * (at offset 0).  The rest of the page is reserved for the
 * thread's kernel stack, which grows downward from the top of
 * the page (at offset 4 kB).  Here's an illustration:
 *
 *      4 kB +---------------------------------+
 *           |          kernel stack           |
 *           |                |                |
 *           |                |                |
 *           |                V                |
 *           |         grows downward          |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           +---------------------------------+
 *           |              magic              |
 *           |            intr_frame           |
 *           |                :                |
 *           |                :                |
 *           |               name              |
 *           |              status             |
 *      0 kB +---------------------------------+
 *
 * The upshot of this is twofold:
 *
 *    1. First, `struct thread' must not be allowed to grow too
 *       big.  If it does, then there will not be enough room for
 *       the kernel stack.  Our base `struct thread' is only a
 *       few bytes in size.  It probably should stay well under 1
 *       kB.
 *
 *    2. Second, kernel stacks must not be allowed to grow too
 *       large.  If a stack overflows, it will corrupt the thread
 *       state.  Thus, kernel functions should not allocate large
 *       structures or arrays as non-static local variables.  Use
 *       dynamic allocation with malloc() or palloc_get_page()
 *       instead.
 *
 * The first symptom of either of these problems will probably be
 * an assertion failure in thread_current(), which checks that
 * the `magic' member of the running thread's `struct thread' is
 * set to THREAD_MAGIC.  Stack overflow will normally change this
 * value, triggering the assertion. */
/* The `elem' member has a dual purpose.  It can be an element in
 * the run queue (thread.c), or it can be an element in a
 * semaphore wait list (synch.c).  It can be used these two ways
 * only because they are mutually exclusive: only a thread in the
 * ready state is on the run queue, whereas only a thread in the
 * blocked state is on a semaphore wait list. */
struct thread {
	/* Owned by thread.c. */
	tid_t tid;                          /* Thread identifier. */
	enum thread_status status;          /* Thread state. */
	char name[16];                      /* Name (for debugging purposes). */
	int priority;                       /* Priority. */
	int original_priority;							/* Original priority of the thread,
																				 i.e. that has NOT been
																				 donated. */
	struct list_elem all_elem;					/* Element used in the all_list. */
	int recent_cpu;											/* Recent cpu value (mlfqs). */
	int nice;														/* Niceness value (mlfqs). */

	/* Shared between thread.c and timer.c. */
	int64_t alarm;                      /* Holds the number of ticks that
																				 define the wake up time of a
																				 thread. */

	/* Shared between thread.c and synch.c. */
	struct list_elem elem;              /* List element. */
	struct lock *waiting_lock;					/* Holds a pointer to a lock the
																				 thread is waiting for, if there
																				 is no such lock, it is NULL by
																				 default. */
	struct list locks_held;							/* List of locks being held by the
																				 thread. */

#ifdef USERPROG
	/* Owned by userprog/process.c. */
	uint64_t *pml4;                     /* Page map level 4 */
	struct file *executable; 						/* Pointer to current file. */
	struct list active_children;				/* Holds pointers to active children. */
	struct list_elem active_child_elem;	/* active_children list element. */
	struct list terminated_children_st;	/* Holds the tids and exit statuses
	 																			 of terminated children. */
	struct thread *parent;
	struct semaphore fork_sema;					/* Used on a fork() system call to
																				 wake up the calling process once
																				 the child has finished forking. */
	/* Owned by userprog/process.c and userprog/syscall.c. */
	struct fd_table fd_t;								/* Process' file descriptor table. */
	int exit_status;
#endif
#ifdef VM
	/* Table for whole virtual memory owned by thread. */
	struct supplemental_page_table spt;
#endif

	/* Owned by thread.c. */
	struct intr_frame tf;               /* Information for switching */
	unsigned magic;                     /* Detects stack overflow. */
};

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
extern bool thread_mlfqs;

void thread_init (void);
void thread_start (void);

void thread_tick (void);
void thread_print_stats (void);

typedef void thread_func (void *aux);
tid_t thread_create (const char *name, int priority, thread_func *, void *);

void thread_block (void);
void thread_unblock (struct thread *);
void thread_sleep (void);

struct thread *thread_current (void);
tid_t thread_tid (void);
const char *thread_name (void);
bool thread_is_user (struct thread *t);

void thread_exit (int status) NO_RETURN;
void thread_yield (void);

int thread_get_priority (void);
void thread_set_priority (int);
void thread_donate_priority (struct thread *target);
void thread_update_priority (void);

int thread_get_nice (void);
void thread_set_nice (int);
int thread_get_recent_cpu (void);
int thread_get_load_avg (void);

void do_iret (struct intr_frame *tf);

#endif /* threads/thread.h */
