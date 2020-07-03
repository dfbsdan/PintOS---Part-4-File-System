/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "threads/vaddr.h"
#include "threads/mmu.h"
#include <hash.h>
#include <string.h>
#include <stdio.h>//////////////////////////////////////////////////////////////TEMPORAL: TESTING

static hash_hash_func spt_hash_func;
static hash_less_func spt_less_func;
static hash_action_func spt_page_destructor;
static vm_initializer page_copy;

/* Checks if a given address corresponds to the one of a page. */
bool
vm_is_page_addr (const void *va) {
	return va && pg_round_down (va) == va;
}

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void
vm_init (void) {
	vm_anon_init ();
	vm_file_init ();
#ifdef EFILESYS  /* For project 4 */
	pagecache_init ();
#endif
	register_inspect_intr ();
	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type (struct page *page) {
	int ty = VM_TYPE (page->operations->type);
	switch (ty) {
		case VM_UNINIT:
			return VM_TYPE (page->uninit.type);
		default:
			return ty;
	}
}

/* Helpers */
static struct frame *vm_get_victim (void);
static bool vm_do_claim_page (struct page *page);
static struct frame *vm_evict_frame (void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool
vm_alloc_page_with_initializer (enum vm_type type, void *va, bool writable,
		vm_initializer *init UNUSED, void *aux UNUSED) {
	struct supplemental_page_table *spt = &thread_current ()->spt;
	struct page *new_page;

	ASSERT (VM_TYPE (type) != VM_UNINIT);
	ASSERT (vm_is_page_addr (va));

	/* Check wheter the upage is already occupied or not. */
	if (!spt_find_page (spt, va)) {
		bool (*init_pointer)(struct page *, enum vm_type, void *);
		/* Create the page, fetch the initialier according to the VM type,
		 * and then create "uninit" page struct by calling uninit_new. */
		new_page = (struct page*)malloc (sizeof (struct page));
		if (!new_page)
			return false;
		switch (VM_TYPE (type)) {
			case VM_ANON:
				init_pointer = anon_initializer;
				break;
			case VM_FILE:
				init_pointer = file_map_initializer;
				break;
			default:
				ASSERT (0);
		}
		uninit_new (new_page, va, init, type, aux, init_pointer);
		new_page->writable = writable;
		new_page->t = thread_current ();
		/* Insert the page into the spt. */
		ASSERT (spt_insert_page (spt, new_page));
		return true;
	}
	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page (struct supplemental_page_table *spt, void *va) {
	struct page temp;
	struct hash_elem *elem;

	ASSERT (spt);

	va = pg_round_down (va);
	if (!va)
		return NULL;

	temp.va = va;
	elem = hash_find (&spt->table, &temp.h_elem);
	return (elem)? hash_entry(elem, struct page, h_elem): NULL;
}

/* Insert PAGE into spt with validation. */
bool
spt_insert_page (struct supplemental_page_table *spt, struct page *page) {
	ASSERT (spt);
	ASSERT (page);
	ASSERT (vm_is_page_addr (page->va));
	return hash_insert (&spt->table, &page->h_elem) == NULL;
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	ASSERT (spt);
	ASSERT (page);
	spt_page_destructor (&page->h_elem, spt);
}

/* Returns an integer in the range [0, 2] which specifies how 'good' a page is
 * to be evicted, being that each value means:
 * 		0: The page has been accessed and written.
 *		1: The page has been accessed but not written.
 *		2: The page has not been accessed nor written.
 * The page must be mapped to a kernel virtual addr through a frame. */
static int
rank_page (struct page *page, uint64_t *pml4) {
	ASSERT (pml4);
	ASSERT (page && page->frame && page->frame->page == page
			&& pml4_get_page (pml4, page->va) == page->frame->kva);

	if (pml4_is_dirty (pml4, page->va))
		return 0;
	else if (pml4_is_accessed (pml4, page->va))
		return 1;
	return 2;
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim (void) {
	struct supplemental_page_table *spt = &thread_current ()->spt;
	uint64_t *pml4 = thread_current ()->pml4;
	struct hash_iterator it;
	struct hash_elem *e;
	struct page *page;
	struct frame *victim = NULL;
	int curr_rank, victim_rank = -1;

	hash_first (&it, &spt->table);
	while ((e = hash_next (&it))) {
		page = hash_entry (e, struct page, h_elem);
		ASSERT (vm_is_page_addr (page->va));
		if (page->frame && pml4_get_page (pml4, page->va)) {
			/* Mapped page found. */
			curr_rank = rank_page (page, pml4);
			if (!victim || curr_rank > victim_rank) {
				/* Chose as victim if it's the first mapped page found or if the current
				page has a better 'rank' than the current victim. Return if the highest
				rank was found. */
				victim = page->frame;
				if ((victim_rank = curr_rank) == 2)
					break;
			}
		}
	}
	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
	struct frame *victim = vm_get_victim ();
	uint64_t *pml4 = thread_current ()->pml4;
	struct page *page;

	/* Swap out the victim and return the evicted frame. */
	if (victim) {
		page = victim->page;
		ASSERT (page && page->frame == victim
				&& victim->kva == pml4_get_page (pml4, page->va));
		if (swap_out (page)) {
			/* Remove all links between page and frame. */
			pml4_clear_page (pml4, page->va);
			page->frame = NULL;
			victim->page = NULL;
			return victim;
		}
	}
	return NULL;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame (void) {
	struct frame *frame;
	void *kva;

	kva = palloc_get_page (PAL_USER);
	if (!kva) {
		frame = vm_evict_frame ();
		if (!frame)
			PANIC ("Could not evict a frame");
	} else {
		ASSERT (vm_is_page_addr (kva));
		frame = (struct frame*)malloc (sizeof (struct frame));
		if (!frame)
			PANIC ("Insufficient space for a frame");
		frame->kva = kva;
	}
	frame->page = NULL;
	return frame;
}

/* Growing the stack. */
static bool
vm_stack_growth (void *addr) {
	addr = pg_round_down (addr);
	ASSERT (addr);
	return vm_alloc_page (VM_ANON | VM_ANON_STACK, addr, true)
			&& vm_claim_page (addr, &thread_current ()->spt);
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
	ASSERT (0);///////////////////////////////////////////////////////////////////Not implemented
}

/* Return true on success */
bool
vm_try_handle_fault (struct intr_frame *f UNUSED, void *addr, bool user,
		bool write, bool not_present) {
	struct supplemental_page_table *spt = &thread_current ()->spt;
	struct page *page = NULL;
	void *pg_va = pg_round_down (addr);

	if (user) {
		if (!is_user_vaddr (pg_va))
			return false;
		if (not_present) {
			page = spt_find_page (spt, pg_va);
			if (!page) { //Unexisting page
				/* Recover if stack overflow. */
				if (addr >= (void*)f->rsp - 8 && addr <= (void*)USER_STACK)
					return vm_stack_growth (addr);
				return false; //Unexisting non-stack page
			}
			if (write && !page->writable) {
				return false; //Writing r/o page
			}
			return vm_do_claim_page (page);
		} else
			return false; //Writing r/o page
	} else { //Kernel fault
		ASSERT (not_present);
		page = spt_find_page (spt, pg_va);
		ASSERT (page);
		return vm_do_claim_page (page);
	}
}

/* Free the page.
 * The page MUST NOT belong to any spt, in such case use spt_remove_page instead.
 * DO NOT MODIFY THIS FUNCTION. */
void
vm_dealloc_page (struct page *page) {
	destroy (page);
	free (page);
}

/* Claim the page that allocate on VA. */
bool
vm_claim_page (void *va, struct supplemental_page_table *spt) {
	struct page *page;

	ASSERT (vm_is_page_addr (va));
	ASSERT (spt);

	page = spt_find_page (spt, va);
	if (!page) //The page does not exist
		return false;
	ASSERT (page->va == va);
	return vm_do_claim_page (page);
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page (struct page *page) {
	struct frame *frame = vm_get_frame ();
	uint64_t *pml4;

	ASSERT (page);
	ASSERT (thread_is_user (page->t));
	ASSERT (vm_is_page_addr (page->va));
	pml4 = page->t->pml4;
	ASSERT (!pml4_get_page (pml4, page->va)); //Must NOT be mapped already

	/* Set links */
	frame->page = page;
	page->frame = frame;
	/* Insert page table entry to map page's VA to frame's PA. */
	if (pml4_set_page (pml4, page->va, frame->kva, page->writable))
		return swap_in (page, frame->kva);
	palloc_free_page (frame->kva);
	free (frame);
	page->frame = NULL;
	return false;
}

/* Hash function for a supplemental_page_table page holding a hash_elem E. */
static uint64_t
spt_hash_func (const struct hash_elem *e, void *spt_ UNUSED) {
	struct page *page;

	ASSERT (e);

	page = hash_entry (e, struct page, h_elem);
	ASSERT (vm_is_page_addr (page->va));
	return hash_bytes (&page->va, sizeof (page->va));
}

/* Default function for comparison between two hash elements A and B that belong
 * to a supplemental_page_table entry (page).
 * Returns TRUE if A belongs to a page whose va value is less than B's. */
static bool
spt_less_func (const struct hash_elem *a, const struct hash_elem *b,
		void *spt_ UNUSED) {
	struct page *a_page, *b_page;

	ASSERT (a && b);

	a_page = hash_entry (a, struct page, h_elem);
	b_page = hash_entry (b, struct page, h_elem);
	ASSERT (vm_is_page_addr (a_page->va));
	ASSERT (vm_is_page_addr (b_page->va));
	return a_page->va < b_page->va;
}

/* Initialize new supplemental page table */
bool
supplemental_page_table_init (struct supplemental_page_table *spt) {
	ASSERT (spt);
	return hash_init (&spt->table, spt_hash_func, spt_less_func, spt);
}

/* Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst,
		struct supplemental_page_table *src) {
	struct hash_iterator it;
	struct hash_elem *elem;
	struct page *parent_pg;
	enum vm_type type;

	ASSERT (dst && src);

	/* Copy all pages. */
	hash_first (&it, &src->table);
	while ((elem = hash_next (&it))) {
		parent_pg = hash_entry (elem, struct page, h_elem);
		/* Get page type to be passed to initializer. */
		switch (parent_pg->operations->type) {
			case VM_UNINIT:
				type = parent_pg->uninit.type;
				if (VM_TYPE (type) == VM_FILE)
					continue; //Mapping are not inherited
				break;
			case VM_ANON:
				switch (parent_pg->anon.a_type) {
					case ANON_STACK:
						type = VM_ANON | VM_ANON_STACK;
						break;
					case ANON_EXEC:
						type = VM_ANON | VM_ANON_EXEC;
						break;
					default:
						ASSERT (0);
				}
				break;
			case VM_FILE:
				continue; //Mapping are not inherited
			default:
				ASSERT (0);
		}
		ASSERT (VM_TYPE (type) != VM_FILE);
		/* Initialize and copy page. */
		if (!(vm_alloc_page_with_initializer (type, parent_pg->va, parent_pg->writable,
				page_copy, parent_pg) && vm_claim_page (parent_pg->va, dst)))
			return false;
	}
	return true;
}

/* Copies the information and data of the PARENT_PG page into the CHILD_PG page,
 * which must be mapped in its thread's pml4. */
static bool
page_copy (struct page *child_pg, void *parent_pg_) {
	struct page *parent_pg = (struct page *)parent_pg_;
	void *child_kva, *parent_kva;

	ASSERT (child_pg && child_pg->frame && child_pg->frame->page == child_pg);
	ASSERT (parent_pg);
	ASSERT (child_pg->va == parent_pg->va);
	ASSERT (thread_is_user (child_pg->t) && thread_is_user (parent_pg->t));
	child_kva = child_pg->frame->kva;
	ASSERT (pml4_get_page (child_pg->t->pml4, child_pg->va) == child_kva);

	if (pml4_get_page (parent_pg->t->pml4, parent_pg->va)
			|| vm_claim_page (parent_pg->va, &parent_pg->t->spt)) {
		/* Both pages are now in the main memory. */
		ASSERT (child_pg->operations == parent_pg->operations);
		ASSERT (parent_pg->frame && parent_pg->frame->page == parent_pg);
		parent_kva = parent_pg->frame->kva;
		ASSERT (pml4_get_page (parent_pg->t->pml4, parent_pg->va) == parent_kva);
		ASSERT (child_kva != parent_kva);
		memcpy (child_kva, parent_kva, PGSIZE);
		return true;
	}
	return false;
}

/* Free the resource held by the supplemental page table.
 * The EXIT argument defines if the table is being killed in order to finish a
 * process completely (i.e. by process_exit ()), or in order to change its
 * execution context (i.e. process_exec ()). */
void
supplemental_page_table_kill (struct supplemental_page_table *spt, bool exit) {
	ASSERT (spt);
	/* Destroy all the supplemental_page_table held by thread. */
	if (spt->table.buckets) { //I.e. make sure there was no error on hash_init()
		if (exit)
			hash_destroy (&spt->table, spt_page_destructor);
		else
			hash_clear (&spt->table, spt_page_destructor);
	} else
		ASSERT (exit); //Error in hash_init() so the process must be terminating
}

/* Default destructor for a page holding a h_elem E. */
static void
spt_page_destructor (struct hash_elem *e, void *spt_) {
	struct page *page;
	struct supplemental_page_table *spt = (struct supplemental_page_table*)spt_;

	ASSERT (e);
	ASSERT (spt);

	page = hash_entry (e, struct page, h_elem);
	if (hash_find (&spt->table, &page->h_elem)) { //Page not yet removed from spt
		ASSERT (hash_delete (&spt->table, &page->h_elem) == &page->h_elem);
	}
	vm_dealloc_page (page);
}
