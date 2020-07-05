/* anon.c: Implementation of page for non-disk image (a.k.a. anonymous page). */

#include "threads/mmu.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "devices/disk.h"
#include <hash.h>
#include <bitmap.h>

/* Number of disk sectors that make up a page. */
#define SECTORS_PER_PAGE 8

/* DO NOT MODIFY BELOW LINE */
static struct disk *swap_disk;
static bool anon_swap_in (struct page *page, void *kva);
static bool anon_swap_out (struct page *page);
static void anon_destroy (struct page *page);
static hash_hash_func swap_hash_func;
static hash_less_func swap_less_func;

/* DO NOT MODIFY this struct */
static const struct page_operations anon_ops = {
	.swap_in = anon_swap_in,
	.swap_out = anon_swap_out,
	.destroy = anon_destroy,
	.type = VM_ANON,
};

static struct swap_table {
	size_t size;						/* Number of pages in the swap_disk. */
	struct bitmap *bitmap;	/* Bitmap that specifies if a swap memory slot is free
													 * or not. The index in the map is the one of the page
													 * in the swap memory. */
	struct hash table;			/* Table that maps a page into its swap slot. */
} swap_t;

/* Checks and asserts if the swap_table "swap_t" is correct. */
static void
swap_check_table (void) {
	ASSERT (
		bitmap_count (swap_t.bitmap, 0, swap_t.size, true)
				== hash_size (&swap_t.table));//////////////////////////////////////////May have synchronization issues
}

/* Hash function for a swap_table page holding a swap_elem E. */
static uint64_t
swap_hash_func (const struct hash_elem *e, void *aux UNUSED) {
	struct page *page;

	ASSERT (e);

	page = hash_entry (e, struct anon_page, swap_elem)->page;
	ASSERT (VM_TYPE (page->operations->type) == VM_ANON);
	ASSERT (vm_is_page_addr (page->va));
	return hash_bytes (&page, sizeof (page));
}

/* Default function for comparison between two hash elements A and B that belong
 * to a swap_table entry (page).
 * Returns TRUE if A belongs to a page whose address value is less than B's. */
static bool
swap_less_func (const struct hash_elem *a, const struct hash_elem *b,
		void *aux UNUSED) {
	struct page *a_page, *b_page;

	ASSERT (a && b);

	a_page = hash_entry (a, struct anon_page, swap_elem)->page;
	b_page = hash_entry (b, struct anon_page, swap_elem)->page;
	ASSERT (VM_TYPE (a_page->operations->type) == VM_ANON);
	ASSERT (VM_TYPE (b_page->operations->type) == VM_ANON);
	ASSERT (vm_is_page_addr (a_page->va));
	ASSERT (vm_is_page_addr (b_page->va));
	return a_page < b_page;
}

/* Maps the index of swap memory slot into the corresponding swap_disk sector. */
static disk_sector_t
index_to_sector (size_t idx) {
	ASSERT (idx < swap_t.size);
	return (disk_sector_t)(idx * SECTORS_PER_PAGE);
}

/* Initialize the data for anonymous pages */
void
vm_anon_init (void) {
	/* Set up the swap_disk. */
	swap_disk = disk_get (1, 1);
	if (!swap_disk)
		PANIC ("Unable to get swap disk");
	/* Set up the swap table. */
	swap_t.size = disk_size (swap_disk) / SECTORS_PER_PAGE;
	if (swap_t.size == 0)
		PANIC ("The swap disk is too small to store a page");
	if (!((swap_t.bitmap = bitmap_create (swap_t.size))
			&& hash_init (&swap_t.table, swap_hash_func, swap_less_func, NULL)))
		PANIC ("Unable to create swap table");
}

/* Initialize the file mapping */
bool
anon_initializer (struct page *page, enum vm_type type, void *kva) {
	ASSERT (page && kva);
	ASSERT (vm_is_page_addr (page->va));
	ASSERT (VM_TYPE (type) == VM_ANON);
	ASSERT (page->frame && page->frame->kva == kva);

	/* Set up the handler */
	page->operations = &anon_ops;
	page->anon.page = page;
	switch (VM_SUBTYPE (type)) {
		case VM_ANON_STACK:
			page->anon.a_type = ANON_STACK;
			break;
		case VM_ANON_EXEC:
			page->anon.a_type = ANON_EXEC;
			break;
		default:////////////////////////////////////////////////////////////////////May need to be updated on addition of more anon types
			PANIC ("Unrecognized anon page type");
	}
	return true;
}

/* Swap in the page by read contents from the swap disk. */
static bool
anon_swap_in (struct page *page, void *kva) {
	struct anon_page *anon_page;
	disk_sector_t sector;

	ASSERT (page);
	ASSERT (VM_TYPE (page->operations->type) == VM_ANON);
	ASSERT (vm_is_page_addr (kva));
	anon_page = &page->anon;
	ASSERT (anon_page->page == page);
	ASSERT (thread_is_user (page->t)
			&& spt_find_page (&page->t->spt, page->va) == page
			&& pml4_get_page (page->t->pml4, page->va) == kva);
	ASSERT (hash_find (&swap_t.table, &anon_page->swap_elem));
	ASSERT (bitmap_test (swap_t.bitmap, anon_page->idx));
	swap_check_table ();

	/* Read from disk. */
	sector = index_to_sector (anon_page->idx);
	for (unsigned i = 0; i < SECTORS_PER_PAGE; i++)
		disk_read (swap_disk, sector + i, kva + i * DISK_SECTOR_SIZE);
	/* Allow usage of swap slot. */
	ASSERT (hash_delete (&swap_t.table, &anon_page->swap_elem));
	bitmap_set (swap_t.bitmap, anon_page->idx, false);
	return true;
}

/* Swap out the page by writing contents to the swap disk. */
static bool
anon_swap_out (struct page *page) {
	struct anon_page *anon_page;
	void *kva;
	disk_sector_t sector;

	ASSERT (page && page->frame);
	ASSERT (VM_TYPE (page->operations->type) == VM_ANON);
	kva = page->frame->kva;
	ASSERT (vm_is_page_addr (kva));
	anon_page = &page->anon;
	ASSERT (anon_page->page == page);
	ASSERT (thread_is_user (page->t)
			&& spt_find_page (&page->t->spt, page->va) == page
			&& pml4_get_page (page->t->pml4, page->va) == kva);
	swap_check_table ();

	if (!hash_find (&swap_t.table, &anon_page->swap_elem)) {
		/* Obtain a table entry to store the data. */
		anon_page->idx = bitmap_scan_and_flip (swap_t.bitmap, 0, 1, false); ////////May have synchronization issues
		if (anon_page->idx == BITMAP_ERROR)
			PANIC ("Not enough space in the swap memory to store page");
		ASSERT (!hash_insert (&swap_t.table, &anon_page->swap_elem));
		/* Copy the page into the swap memory. */
		sector = index_to_sector (anon_page->idx);
		for (unsigned i = 0; i < SECTORS_PER_PAGE; i++)
			disk_write (swap_disk, sector + i, kva + i * DISK_SECTOR_SIZE);
		return true;
	}
	return false;
}

/* Destroy the anonymous page, which must NOT be in the current thread's spt.
 * PAGE will be freed by the caller. */
static void
anon_destroy (struct page *page) {
	struct anon_page *anon_page;

	ASSERT (page);
	ASSERT (vm_is_page_addr (page->va));
	ASSERT (thread_is_user (page->t));
	ASSERT (!spt_find_page (&page->t->spt, page->va));
	ASSERT (VM_TYPE (page->operations->type) == VM_ANON);
	anon_page = &page->anon;
	ASSERT (anon_page->page == page);
	swap_check_table ();

	if (pml4_get_page (page->t->pml4, page->va)) {
		/* The page is in the main memory. */
		struct frame *frame = page->frame;
		ASSERT (frame && frame->page == page);
		ASSERT (!hash_find (&swap_t.table, &anon_page->swap_elem));
		pml4_clear_page (page->t->pml4, page->va);
		palloc_free_page (frame->kva);
		free (frame);
	} else { /* The page has been swapped. */
		ASSERT (bitmap_test (swap_t.bitmap, anon_page->idx));
		/* Remove from swap table. */
		ASSERT (hash_delete (&swap_t.table, &anon_page->swap_elem));
		bitmap_reset (swap_t.bitmap, anon_page->idx);
	}
}
