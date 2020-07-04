#include "threads/thread.h"
#include <debug.h>
#include <stddef.h>
#include <random.h>
#include <stdio.h>
#include <string.h>
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/intr-stubs.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "threads/fpa.h"
#include "threads/malloc.h"
#include "intrinsic.h"
#include "devices/timer.h"
#ifdef USERPROG
#include "userprog/process.h"
#endif

/* Random value for struct thread's `magic' member.
   Used to detect stack overflow.  See the big comment at the top
   of thread.h for details. */
#define THREAD_MAGIC 0xcd6abf4b

/* Random value for basic thread
   Do not modify this value. */
#define THREAD_BASIC 0xd42df210

static int load_avg; /* System's load average value. */

/* Compares the PRIORITY values of two given threads. Returns true if
   a's is less than b's, false otherwise. */
static list_less_func compare_priorities;

/* Compares the ALARM values of two given threads. Returns true if
   a's is less than b's, false otherwise. */
static list_less_func compare_alarms;

/* List of processes in THREAD_BLOCKED state, i.e., those that
   are waiting for something to be activated (alarms). */
static struct list sleep_list;

/* List of processes in THREAD_READY state, that is, processes
   that are ready to run but not actually running. */
static struct list ready_list;

/* List of all threads. Threads are added to this list when they are
	 created and removed when they exit. */
static struct list all_list;

/* Idle thread. */
static struct thread *idle_thread;

/* Initial thread, the thread running init.c:main(). */
static struct thread *initial_thread;

/* Lock used by allocate_tid(). */
static struct lock tid_lock;

/* Thread destruction requests */
static struct list destruction_req;

/* Statistics. */
static long long idle_ticks;    /* # of timer ticks spent idle. */
static long long kernel_ticks;  /* # of timer ticks in kernel threads. */
static long long user_ticks;    /* # of timer ticks in user programs. */

/* Scheduling. */
#define TIME_SLICE 4            /* # of timer ticks to give each thread. */
static unsigned thread_ticks;   /* # of timer ticks since last yield. */
static int priority_ticks;			/* # of timer ticks since last priority
																	calculation (mlfqs). */

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
bool thread_mlfqs;

static void kernel_thread (thread_func *, void *aux);

static void idle (void *aux UNUSED);
static struct thread *next_thread_to_run (void);
static bool init_thread (struct thread *, const char *name, int priority,
		int recent_cpu, int nice);
static void do_schedule(int status);
static void schedule (void);
static tid_t allocate_tid (void);
static void wake_up_threads (void);
static struct thread *get_max_donor (void);
#ifdef USERPROG
static bool init_fd_table (struct fd_table *fd_t);
#endif
static int mlfqs_calculate_priority (struct thread *t);
static void mlfqs_update_priorities (void);
static void mlfqs_update_recent_cpu (void);
static void mlfqs_update_load_avg (void);

/* Returns true if T appears to point to a valid thread. */
#define is_thread(t) ((t) != NULL && (t)->magic == THREAD_MAGIC)

/* Returns the running thread.
 * Read the CPU's stack pointer `rsp', and then round that
 * down to the start of a page.  Since `struct thread' is
 * always at the beginning of a page and the stack pointer is
 * somewhere in the middle, this locates the curent thread. */
#define running_thread() ((struct thread *) (pg_round_down (rrsp ())))


// Global descriptor table for the thread_start.
// Because the gdt will be setup after the thread_init, we should
// setup temporal gdt first.
static uint64_t gdt[3] = { 0, 0x00af9a000000ffff, 0x00cf92000000ffff };

/* Initializes the threading system by transforming the code
   that's currently running into a thread.  This can't work in
   general and it is possible in this case only because loader.S
   was careful to put the bottom of the stack at a page boundary.

   Also initializes the run queue and the tid lock.

   After calling this function, be sure to initialize the page
   allocator before trying to create any threads with
   thread_create().

   It is not safe to call thread_current() until this function
   finishes. */
void
thread_init (void) {
	ASSERT (intr_get_level () == INTR_OFF);

	/* Reload the temporal gdt for the kernel
	 * This gdt does not include the user context.
	 * The kernel will rebuild the gdt with user context, in gdt_init (). */
	struct desc_ptr gdt_ds = {
		.size = sizeof (gdt) - 1,
		.address = (uint64_t) gdt
	};
	lgdt (&gdt_ds);

	/* Init the globla thread context */
	lock_init (&tid_lock);
	list_init (&sleep_list);
	list_init (&all_list);
	list_init (&ready_list);
	list_init (&destruction_req);
	load_avg = 0;

	/* Set up a thread structure for the running thread. */
	initial_thread = running_thread ();
	if (!init_thread (initial_thread, "main", PRI_DEFAULT, 0, 0))
		PANIC ("Unable to initialize threading system");
	initial_thread->status = THREAD_RUNNING;
	initial_thread->tid = allocate_tid ();
}

/* Starts preemptive thread scheduling by enabling interrupts.
   Also creates the idle thread. */
void
thread_start (void) {
	/* Create the idle thread. */
	struct semaphore idle_started;
	sema_init (&idle_started, 0);
	thread_create ("idle", PRI_MIN, idle, &idle_started);

	/* Start preemptive thread scheduling. */
	intr_enable ();

	/* Wait for the idle thread to initialize idle_thread. */
	sema_down (&idle_started);
}

/* Called by the timer interrupt handler at each timer tick.
   Thus, this function runs in an external interrupt context. */
void
thread_tick (void) {
	struct thread *t = thread_current ();

	/* Update statistics. */
	if (t == idle_thread)
		idle_ticks++;
#ifdef USERPROG
	else if (t->pml4 != NULL)
		user_ticks++;
#endif
	else
		kernel_ticks++;

	wake_up_threads ();
	if (thread_mlfqs) {
		//Update all threads' priorities every fourth tick
		ASSERT (priority_ticks <= 3 && priority_ticks >= 0);
		//Update recent_cpu values and load_avg
		if (t != idle_thread)
			t->recent_cpu = add_fp_n (t->recent_cpu, 1);
		if ((timer_ticks () % TIMER_FREQ) == 0) {
			mlfqs_update_load_avg ();
			mlfqs_update_recent_cpu ();
		}
		if (priority_ticks == 3) {
			priority_ticks = 0;
			mlfqs_update_priorities ();
		} else
			priority_ticks++;
	}
	/* Enforce preemption. */
	if (++thread_ticks >= TIME_SLICE)
		intr_yield_on_return ();
}

/* Prints thread statistics. */
void
thread_print_stats (void) {
	printf ("Thread: %lld idle ticks, %lld kernel ticks, %lld user ticks\n",
			idle_ticks, kernel_ticks, user_ticks);
}

/* Creates a new kernel thread named NAME with the given initial
   PRIORITY, which executes FUNCTION passing AUX as the argument,
   and adds it to the ready queue.  Returns the thread identifier
   for the new thread, or TID_ERROR if creation fails.

   If thread_start() has been called, then the new thread may be
   scheduled before thread_create() returns.  It could even exit
   before thread_create() returns.  Contrariwise, the original
   thread may run for any amount of time before the new thread is
   scheduled.  Use a semaphore or some other form of
   synchronization if you need to ensure ordering.

   The code provided sets the new thread's `priority' member to
   PRIORITY, but no actual priority scheduling is implemented.
   Priority scheduling is the goal of Problem 1-3. */
tid_t
thread_create (const char *name, int priority,
		thread_func *function, void *aux) {
	struct thread *t, *curr;
	tid_t tid;

	ASSERT (function != NULL);

	/* Allocate thread. */
	t = palloc_get_page (PAL_ZERO);
	if (t == NULL)
		return TID_ERROR;

	/* Initialize thread. */
	curr = thread_current ();
	if (!init_thread (t, name, priority, curr->recent_cpu, curr->nice)) {
		palloc_free_page (t);
		return TID_ERROR;
	}
	tid = t->tid = allocate_tid ();

	/* Call the kernel_thread if it scheduled.
	 * Note) rdi is 1st argument, and rsi is 2nd argument. */
	t->tf.rip = (uintptr_t) kernel_thread;
	t->tf.R.rdi = (uint64_t) function;
	t->tf.R.rsi = (uint64_t) aux;
	t->tf.ds = SEL_KDSEG;
	t->tf.es = SEL_KDSEG;
	t->tf.ss = SEL_KDSEG;
	t->tf.cs = SEL_KCSEG;
	t->tf.eflags = FLAG_IF;

	/* Add to run queue. */
	thread_unblock (t);

	return tid;
}

/* Puts the current thread to sleep.  It will not be scheduled
   again until awoken by thread_unblock().

   This function must be called with interrupts turned off.  It
   is usually a better idea to use one of the synchronization
   primitives in synch.h. */
void
thread_block (void) {
	ASSERT (!intr_context ());
  ASSERT (intr_get_level () == INTR_OFF);

  thread_current ()->status = THREAD_BLOCKED;
  schedule ();
}

/* Transitions a blocked thread T to the ready-to-run state.
   This is an error if T is not blocked.  (Use thread_yield() to
   make the running thread ready.)

   This function does not preempt the running thread.  This can
   be important: if the caller had disabled interrupts itself,
   it may expect that it can atomically unblock a thread and
   update other data. */
void
thread_unblock (struct thread *t) {
	enum intr_level old_level;

	ASSERT (is_thread (t));

	old_level = intr_disable ();
	ASSERT (t->status == THREAD_BLOCKED);
	list_push_back (&ready_list, &t->elem);
	t->status = THREAD_READY;
	intr_set_level (old_level);
	if (t->priority > thread_current ()->priority &&
			thread_current () != idle_thread) {
		if (intr_context ()) //Waking up sleeping threads (alarm)
			intr_yield_on_return ();
		else
			thread_yield ();
	}
}

/* Adds current thread to the sleep_list and blocks it.
   Interrupts must be turned off. */
void
thread_sleep (void) {
	ASSERT (intr_get_level () == INTR_OFF);

	list_insert_ordered (&sleep_list, &thread_current ()->elem,
			&compare_alarms, NULL);
	thread_block ();
}

/* Returns the name of the running thread. */
const char *
thread_name (void) {
	return thread_current ()->name;
}

/* Returns True if the current thread is an user thread, false
	 otherwise. */
bool
thread_is_user (struct thread *t)
{
	ASSERT (is_thread (t));

	return t != initial_thread && t != idle_thread;
}

/* Returns the running thread.
   This is running_thread() plus a couple of sanity checks.
   See the big comment at the top of thread.h for details. */
struct thread *
thread_current (void) {
	struct thread *t = running_thread ();

	/* Make sure T is really a thread.
	   If either of these assertions fire, then your thread may
	   have overflowed its stack.  Each thread has less than 4 kB
	   of stack, so a few big automatic arrays or moderate
	   recursion can cause stack overflow. */
	ASSERT (is_thread (t));
	ASSERT (t->status == THREAD_RUNNING);

	return t;
}

/* Returns the running thread's tid. */
tid_t
thread_tid (void) {
	return thread_current ()->tid;
}

/* Deschedules the current thread and destroys it.  Never
   returns to the caller. STATUS corresponds to the exit status of the
	 terminating thread, this is used in userprog/process.c. */
void
thread_exit (int status) {
	ASSERT (!intr_context ());

#ifdef USERPROG
	process_exit (status);
#endif
	/* Just set our status to dying and schedule another process.
	   We will be destroyed during the call to schedule_tail(). */
	intr_disable ();
	list_remove (&thread_current ()->all_elem);
	do_schedule (THREAD_DYING);
	NOT_REACHED ();
}

/* Yields the CPU.  The current thread is not put to sleep and
   may be scheduled again immediately at the scheduler's whim. */
void
thread_yield (void) {
	struct thread *curr = thread_current ();
	enum intr_level old_level;

	ASSERT (!intr_context ());

	old_level = intr_disable ();
	if (curr != idle_thread)
		list_push_back (&ready_list, &curr->elem);
	do_schedule (THREAD_READY);
	intr_set_level (old_level);
}

/* Sets the current thread's priority to NEW_PRIORITY. */
void
thread_set_priority (int new_priority) {
	int old_priority, old_original_priority;
	struct thread *curr;

	if (thread_mlfqs) return;
	curr = thread_current ();
	old_priority = curr->priority;
	old_original_priority = curr->original_priority;
	/* Keep the new priority inside the valid range and update it. */
	curr->priority = curr->original_priority = (new_priority > PRI_MAX)?
			PRI_MAX: (new_priority < PRI_MIN)? PRI_MIN: new_priority;
	//Set the priority later if the thread has been donated a greater one
	if(old_original_priority != old_priority && old_priority > new_priority)
		curr->priority = old_priority;
  /* Yield if the priority has been lowered down. */
  if (curr->priority < old_priority)
    thread_yield ();
}

/* Returns the current thread's priority (the Highest one as well in case
	 it has been donated). */
int
thread_get_priority (void) {
	return thread_current ()->priority;
}

/* Sets the priority of the TARGET thread to the greatest between its
	 current one and current thread's. If such TARGET is waiting for a lock
	 (i.e. nested locks), all the nested lock holders are also donated in
	 case it is necessary. */
void
thread_donate_priority (struct thread *target) {
	ASSERT (is_thread (target));
	ASSERT (intr_get_level () == INTR_OFF);
	ASSERT (!thread_mlfqs);

	//Donate priority
	if (thread_current ()->priority > target->priority)
		target->priority = thread_current ()->priority;
	//Handle nested locks
	if (target->waiting_lock)
		thread_donate_priority (target->waiting_lock->holder);
}

/* Updates the priority of the current thread to the maximum available
 	 it can receive from its locks held (being subject to a donation). If
	 it is not possible then it restores the thread's original priority. */
void
thread_update_priority (void) {
	struct thread *max_donor, *curr;

	ASSERT (intr_get_level () == INTR_OFF);
	ASSERT (!thread_mlfqs);

	curr = thread_current ();
	max_donor = get_max_donor ();
	curr->priority = (max_donor == curr)? curr->original_priority:
			(max_donor->priority > curr->original_priority)?
					max_donor->priority: curr->original_priority;
}

/* Returns a pointer to the thread with greatest priority inside the
	 waiting lists of those locks being held by the current thread, if no
	 donator is found, returns the current thread. */
static struct thread *
get_max_donor (void) {
	struct thread *curr, *max_donor, *t;
	struct list *lock_list, *waiters_list;
	struct list_elem *lock, *thread_elem;

	ASSERT (intr_get_level () == INTR_OFF);
	ASSERT (!thread_mlfqs);

	max_donor = curr = thread_current ();
	lock_list = &curr->locks_held;
  if (!list_empty (lock_list)) {
		/* Traverse all locks inside current thread's locks_held list. */
  	for (lock = list_front (lock_list);
				lock != list_end (lock_list);
				lock = list_next(lock)) {
    	waiters_list =
				&list_entry (lock, struct lock, lock_elem)->semaphore.waiters;
    	if (!list_empty (waiters_list)) {
      	/* Traverse all waiters for current lock and update max_donor
				 	in case there is one with a higher priority. */
      	for (thread_elem = list_front (waiters_list);
						thread_elem != list_end (waiters_list);
						thread_elem = list_next (thread_elem)) {
        	t = list_entry (thread_elem, struct thread, elem);
        	max_donor = (t->priority >= max_donor->priority)? t: max_donor;
      	}
    	}
  	}
	}
  return max_donor;
}

/* Sets the current thread's nice value to NICE. Recalculates the thread's
	 priority based on the new value. If the running thread no longer has
	 the highest priority, yields. */
void
thread_set_nice (int nice) {
	struct thread *curr;
	int old_priority;

	ASSERT (thread_mlfqs);
	ASSERT (nice >= -20 && nice <= 20);

	curr = thread_current ();
	old_priority = curr->priority;
	curr->nice = nice;
	curr->priority = mlfqs_calculate_priority (curr);
	if (curr->priority < old_priority)
		thread_yield ();
}

/* Returns the current thread's nice value. */
int
thread_get_nice (void) {
	ASSERT (thread_mlfqs);

	return thread_current ()->nice;
}

/* Returns 100 times the system load average. */
int
thread_get_load_avg (void) {
	ASSERT (thread_mlfqs);

	return fp_to_n_down (mult_fp_n (load_avg, 100));
}

/* Returns 100 times the current thread's recent_cpu value. */
int
thread_get_recent_cpu (void) {
	ASSERT (thread_mlfqs);

	return fp_to_n_down (mult_fp_n (thread_current ()->recent_cpu, 100));
}

/* Compares the ALARM values of two given threads. Returns true if
   a's is less than b's, false otherwise. */
static bool
compare_alarms (const struct list_elem *a, const struct list_elem *b,
		void *aux UNUSED) {
	struct thread *aThr, *bThr;

	ASSERT (a && b);

  aThr = list_entry (a, struct thread, elem);
  bThr = list_entry (b, struct thread, elem);
  ASSERT (is_thread (aThr) && is_thread (bThr));
  return aThr->alarm < bThr->alarm;
}

/* Wakes up those threads from sleep_list that have finished sleeping
	 (i.e. the alarm has run off). */
static void
wake_up_threads (void) {
	enum intr_level old_level;
  struct thread *t;
	int64_t ticks;

	ASSERT (intr_context ());

	old_level = intr_disable ();
	ticks = timer_ticks ();
  while (!list_empty (&sleep_list)) {
    t = list_entry (list_front (&sleep_list), struct thread, elem);
    if (t->alarm > ticks)
      break;
    list_remove (&t->elem);
    thread_unblock (t);
  }
	intr_set_level (old_level);
}

/* Idle thread.  Executes when no other thread is ready to run.

   The idle thread is initially put on the ready list by
   thread_start().  It will be scheduled once initially, at which
   point it initializes idle_thread, "up"s the semaphore passed
   to it to enable thread_start() to continue, and immediately
   blocks.  After that, the idle thread never appears in the
   ready list.  It is returned by next_thread_to_run() as a
   special case when the ready list is empty. */
static void
idle (void *idle_started_ UNUSED) {
	struct semaphore *idle_started = idle_started_;

	idle_thread = thread_current ();
	sema_up (idle_started);

	for (;;) {
		/* Let someone else run. */
		intr_disable ();
		thread_block ();

		/* Re-enable interrupts and wait for the next one.

		   The `sti' instruction disables interrupts until the
		   completion of the next instruction, so these two
		   instructions are executed atomically.  This atomicity is
		   important; otherwise, an interrupt could be handled
		   between re-enabling interrupts and waiting for the next
		   one to occur, wasting as much as one clock tick worth of
		   time.

		   See [IA32-v2a] "HLT", [IA32-v2b] "STI", and [IA32-v3a]
		   7.11.1 "HLT Instruction". */
		asm volatile ("sti; hlt" : : : "memory");
	}
}

/* Function used as the basis for a kernel thread. */
static void
kernel_thread (thread_func *function, void *aux) {
	ASSERT (function != NULL);

	intr_enable ();       /* The scheduler runs with interrupts off. */
	function (aux);       /* Execute the thread function. */
	thread_exit (0);      /* If function() returns, kill the thread. */
}


/* Does basic initialization of T as a blocked thread named
   NAME. Returns TRUE on success, FALSE otherwise. */
static bool
init_thread (struct thread *t, const char *name, int priority,
		int recent_cpu, int nice) {
	ASSERT (t != NULL);
	ASSERT (PRI_MIN <= priority && priority <= PRI_MAX);
	ASSERT (name != NULL);
	ASSERT (nice >= -20 && nice <= 20);

	memset (t, 0, sizeof *t);
	t->status = THREAD_BLOCKED;
	strlcpy (t->name, name, sizeof t->name);
	t->tf.rsp = (uint64_t) t + PGSIZE - sizeof (void *);
	t->recent_cpu = recent_cpu;
	t->nice = nice;
	t->magic = THREAD_MAGIC;
	t->priority = (thread_mlfqs)? mlfqs_calculate_priority(t): priority;
	t->original_priority = priority;
	t->waiting_lock = NULL;
	list_init (&t->locks_held);
#ifdef USERPROG
	t->executable = NULL;
	list_init (&t->active_children);
	list_init (&t->terminated_children_st);
	t->fd_t.table = NULL;
	if (t != initial_thread) {
		if (t != idle_thread && !init_fd_table (&t->fd_t))
			return false;
		t->parent = thread_current ();
		list_push_back (&t->parent->active_children, &t->active_child_elem);
	}
	else
		t->parent = NULL;
	sema_init (&t->fork_sema, 0);
	t->exit_status = 0;
#endif
	list_push_back (&all_list, &t->all_elem);
	return true;
}

#ifdef USERPROG
/* Initializes the file descriptor table of a process. Returns FALSE on
 	 error, TRUE otherwise. */
static bool
init_fd_table (struct fd_table *fd_t) {
	struct file_descriptor *fd;
	int i;

	ASSERT (fd_t);

	fd_t->size = 2; /* Default: 0: stdin, 1: stdout. */
	fd_t->table = (struct file_descriptor*)calloc (MAX_FD + 1, sizeof (struct file_descriptor));
	if (!fd_t->table)
		return false;
	/* Open stdin and stdout. */
	fd = &fd_t->table[0];
	fd->fd_st = FD_OPEN;
	fd->fd_t = FDT_STDIN;
	fd = &fd_t->table[1];
	fd->fd_st = FD_OPEN;
	fd->fd_t = FDT_STDOUT;
	/* Initialize remaining fds. */
	for (i = 2; i <= MAX_FD; i++) {
		fd = &fd_t->table[i];
		fd->fd_st = FD_CLOSE;
		fd->fd_t = FDT_OTHER;
	}
	return true;
}
#endif

/* Calculates and returns the new priority for a given THREAD (mlfqs). */
static int
mlfqs_calculate_priority (struct thread *t) {
	int new_priority;

	ASSERT (is_thread (t));
	ASSERT (thread_mlfqs);

	new_priority = fp_to_n_down (div_fp_n (t->recent_cpu, 4));
	new_priority = PRI_MAX - new_priority - (t->nice * 2);
	return (new_priority > PRI_MAX)? PRI_MAX:
			(new_priority < PRI_MIN)? PRI_MIN: new_priority;
}

/* Updates the priorities of all existing threads (mlfqs). */
static void
mlfqs_update_priorities (void) {
	struct thread *t;
	struct list_elem *t_all_elem;

	ASSERT (thread_mlfqs);
	ASSERT (intr_context ());

	if (!list_empty (&all_list)) {
		for (t_all_elem = list_front (&all_list);
				t_all_elem != list_end (&all_list);
				t_all_elem = list_next (t_all_elem)) {
			t = list_entry (t_all_elem, struct thread, all_elem);
			t->priority = mlfqs_calculate_priority (t);
		}
	}
}

/* Updates the recent_cpu values of all existing threads (mlfqs). */
static void
mlfqs_update_recent_cpu (void) {
	struct thread *t;
	struct list_elem *t_all_elem;
	int coeff;

	ASSERT (thread_mlfqs);
	ASSERT (intr_context ());

	if (!list_empty (&all_list)) {
		for (t_all_elem = list_front (&all_list);
				t_all_elem != list_end (&all_list);
				t_all_elem = list_next (t_all_elem)) {
			t = list_entry (t_all_elem, struct thread, all_elem);
			coeff = mult_fp_n (load_avg, 2);
			coeff = div_fp (coeff, add_fp_n (coeff, 1));
			t->recent_cpu = add_fp_n (mult_fp (coeff, t->recent_cpu), t->nice);
		}
	}
}

/* Updates the global variable load_avg (mlfqs). */
static void
mlfqs_update_load_avg (void) {
	int temp, ready_list_sz;

	ASSERT (thread_mlfqs);
	ASSERT (intr_context ());

	ready_list_sz = (thread_current () != idle_thread)?
			n_to_fp (list_size (&ready_list) + 1):
			n_to_fp (list_size (&ready_list));
	temp = mult_fp (div_fp (n_to_fp (59), n_to_fp (60)), load_avg);
	load_avg = add_fp (temp,
			mult_fp (div_fp (n_to_fp (1), n_to_fp (60)),
					ready_list_sz));
}

/* Chooses and returns the next thread to be scheduled.  Should
   return a thread from the run queue, unless the run queue is
   empty.  (If the running thread can continue running, then it
   will be in the run queue.)  If the run queue is empty, return
   idle_thread. */
static struct thread *
next_thread_to_run (void) {
	struct thread *next_thread;

	if (list_empty (&ready_list))
		return idle_thread;
	else {
		//Choose the thread with Highest priority in the ready_list
		next_thread = list_entry (
				list_max (&ready_list, &compare_priorities, NULL),
        struct thread, elem);
		list_remove (&next_thread->elem);
		return next_thread;
	}
}

/* Compares the PRIORITY values of two given threads. Returns true if
   a's is less than b's, false otherwise. */
static bool
compare_priorities (const struct list_elem *a, const struct list_elem *b,
		void *aux UNUSED) {
  ASSERT (a && b);

  struct thread *aThr, *bThr;
  aThr = list_entry (a, struct thread, elem);
  bThr = list_entry (b, struct thread, elem);
  ASSERT (is_thread (aThr) && is_thread (bThr));
  return aThr->priority < bThr->priority;
}

/* Use iretq to launch the thread */
void
do_iret (struct intr_frame *tf) {
	__asm __volatile(
			"movq %0, %%rsp\n"
			"movq 0(%%rsp),%%r15\n"
			"movq 8(%%rsp),%%r14\n"
			"movq 16(%%rsp),%%r13\n"
			"movq 24(%%rsp),%%r12\n"
			"movq 32(%%rsp),%%r11\n"
			"movq 40(%%rsp),%%r10\n"
			"movq 48(%%rsp),%%r9\n"
			"movq 56(%%rsp),%%r8\n"
			"movq 64(%%rsp),%%rsi\n"
			"movq 72(%%rsp),%%rdi\n"
			"movq 80(%%rsp),%%rbp\n"
			"movq 88(%%rsp),%%rdx\n"
			"movq 96(%%rsp),%%rcx\n"
			"movq 104(%%rsp),%%rbx\n"
			"movq 112(%%rsp),%%rax\n"
			"addq $120,%%rsp\n"
			"movw 8(%%rsp),%%ds\n"
			"movw (%%rsp),%%es\n"
			"addq $32, %%rsp\n"
			"iretq"
			: : "g" ((uint64_t) tf) : "memory");
}

/* Switching the thread by activating the new thread's page
   tables, and, if the previous thread is dying, destroying it.

   At this function's invocation, we just switched from thread
   PREV, the new thread is already running, and interrupts are
   still disabled.

   It's not safe to call printf() until the thread switch is
   complete.  In practice that means that printf()s should be
   added at the end of the function. */
static void
thread_launch (struct thread *th) {
	uint64_t tf_cur = (uint64_t) &running_thread ()->tf;
	uint64_t tf = (uint64_t) &th->tf;
	ASSERT (intr_get_level () == INTR_OFF);

	/* The main switching logic.
	 * We first restore the whole execution context into the intr_frame
	 * and then switching to the next thread by calling do_iret.
	 * Note that, we SHOULD NOT use any stack from here
	 * until switching is done. */
	__asm __volatile (
			/* Store registers that will be used. */
			"push %%rax\n"
			"push %%rbx\n"
			"push %%rcx\n"
			/* Fetch input once */
			"movq %0, %%rax\n"
			"movq %1, %%rcx\n"
			"movq %%r15, 0(%%rax)\n"
			"movq %%r14, 8(%%rax)\n"
			"movq %%r13, 16(%%rax)\n"
			"movq %%r12, 24(%%rax)\n"
			"movq %%r11, 32(%%rax)\n"
			"movq %%r10, 40(%%rax)\n"
			"movq %%r9, 48(%%rax)\n"
			"movq %%r8, 56(%%rax)\n"
			"movq %%rsi, 64(%%rax)\n"
			"movq %%rdi, 72(%%rax)\n"
			"movq %%rbp, 80(%%rax)\n"
			"movq %%rdx, 88(%%rax)\n"
			"pop %%rbx\n"              // Saved rcx
			"movq %%rbx, 96(%%rax)\n"
			"pop %%rbx\n"              // Saved rbx
			"movq %%rbx, 104(%%rax)\n"
			"pop %%rbx\n"              // Saved rax
			"movq %%rbx, 112(%%rax)\n"
			"addq $120, %%rax\n"
			"movw %%es, (%%rax)\n"
			"movw %%ds, 8(%%rax)\n"
			"addq $32, %%rax\n"
			"call __next\n"         // read the current rip.
			"__next:\n"
			"pop %%rbx\n"
			"addq $(out_iret -  __next), %%rbx\n"
			"movq %%rbx, 0(%%rax)\n" // rip
			"movw %%cs, 8(%%rax)\n"  // cs
			"pushfq\n"
			"popq %%rbx\n"
			"mov %%rbx, 16(%%rax)\n" // eflags
			"mov %%rsp, 24(%%rax)\n" // rsp
			"movw %%ss, 32(%%rax)\n"
			"mov %%rcx, %%rdi\n"
			"call do_iret\n"
			"out_iret:\n"
			: : "g"(tf_cur), "g" (tf) : "memory"
			);
}

/* Schedules a new process. At entry, interrupts must be off.
 * This function modify current thread's status to status and then
 * finds another thread to run and switches to it.
 * It's not safe to call printf() in the schedule(). */
static void
do_schedule(int status) {
	ASSERT (intr_get_level () == INTR_OFF);
	ASSERT (thread_current()->status == THREAD_RUNNING);
	while (!list_empty (&destruction_req)) {
		struct thread *victim =
			list_entry (list_pop_front (&destruction_req), struct thread, elem);
		palloc_free_page(victim);
	}
	thread_current ()->status = status;
	schedule ();
}

static void
schedule (void) {
	struct thread *curr = running_thread ();
	struct thread *next = next_thread_to_run ();

	ASSERT (intr_get_level () == INTR_OFF);
	ASSERT (curr->status != THREAD_RUNNING);
	ASSERT (is_thread (next));
	/* Mark us as running. */
	next->status = THREAD_RUNNING;

	/* Start new time slice. */
	thread_ticks = 0;

#ifdef USERPROG
	/* Activate the new address space. */
	process_activate (next);
#endif

	if (curr != next) {
		/* If the thread we switched from is dying, destroy its struct
		   thread. This must happen late so that thread_exit() doesn't
		   pull out the rug under itself.
		   We just queuing the page free reqeust here because the page is
		   currently used bye the stack.
		   The real destruction logic will be called at the beginning of the
		   schedule(). */
		if (curr && curr->status == THREAD_DYING && curr != initial_thread) {
			ASSERT (curr != next);
			list_push_back (&destruction_req, &curr->elem);
		}

		/* Before switching the thread, we first save the information
		 * of current running. */
		thread_launch (next);
	}
}

/* Returns a tid to use for a new thread. */
static tid_t
allocate_tid (void) {
	static tid_t next_tid = 1;
	tid_t tid;

	lock_acquire (&tid_lock);
	tid = next_tid++;
	lock_release (&tid_lock);

	return tid;
}
