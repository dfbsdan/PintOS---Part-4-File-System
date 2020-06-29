/* file.c: Implementation of memory mapped file object (mmaped object). */

#include "vm/vm.h"
#include "filesys/file.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "threads/mmu.h"
#include <string.h>
#include <hash.h>

static hash_hash_func m_hash_func;
static hash_less_func m_less_func;
static bool file_map_swap_in (struct page *page, void *kva);
static bool file_map_swap_out (struct page *page);
static void file_map_destroy (struct page *page);

/* Keeps track of swapped in/out mapped pages by holding those that are not
 * currently mapped. */
static struct hash um_table;

/* DO NOT MODIFY this struct */
static const struct page_operations file_ops = {
	.swap_in = file_map_swap_in,
	.swap_out = file_map_swap_out,
	.destroy = file_map_destroy,
	.type = VM_FILE,
};

/* Hash function for a um_table page holding an um_elem E. */
static uint64_t
m_hash_func (const struct hash_elem *e, void *aux UNUSED) {
	struct page *page;

	ASSERT (e);

	page = hash_entry (e, struct file_page, um_elem)->page;
	ASSERT (VM_TYPE (page->operations->type) == VM_FILE);
	ASSERT (vm_is_page_addr (page->va)); /////////////////////////////////////////Debugging purposes: May be incorrect
	return hash_bytes (&page, sizeof (page));
}

/* Default function for comparison between two hash elements A and B that belong
 * to a um_table entry (page).
 * Returns TRUE if A belongs to a page whose address value is less than B's. */
static bool
m_less_func (const struct hash_elem *a, const struct hash_elem *b,
		void *aux UNUSED) {
	struct page *a_page, *b_page;

	ASSERT (a && b);

	a_page = hash_entry (a, struct file_page, um_elem)->page;
	b_page = hash_entry (b, struct file_page, um_elem)->page;
	ASSERT (VM_TYPE (a_page->operations->type) == VM_FILE);
	ASSERT (VM_TYPE (b_page->operations->type) == VM_FILE);
	ASSERT (vm_is_page_addr (a_page->va)); //////////////////////////////////////////Debugging purposes: May be incorrect
	ASSERT (vm_is_page_addr (b_page->va)); //////////////////////////////////////////Debugging purposes: May be incorrect
	return a_page < b_page;
}

/* The initializer of file vm */
void
vm_file_init (void) {
	if (!hash_init (&um_table, m_hash_func, m_less_func, NULL))
		PANIC ("Unable to initialize file vm");
}

/* Initialize the file mapped page */
bool
file_map_initializer (struct page *page, enum vm_type type, void *kva) {
	struct file_page *file_page, *aux = (struct file_page*)page->uninit.aux;

	ASSERT (VM_TYPE (type) == VM_FILE);
	ASSERT (page && vm_is_page_addr (page->va) && page->frame);
	ASSERT (VM_TYPE (page->operations->type) == VM_UNINIT);
	ASSERT (kva && page->frame->kva == kva);
	ASSERT (thread_is_user (page->t)
			&& spt_find_page (&page->t->spt, page->va) == page
			&& pml4_get_page (page->t->pml4, page->va) == kva);
	ASSERT (aux);

	/* Set up the handler */
	page->operations = &file_ops;
	file_page = &page->file;
	file_page->page = page;
	file_page->file = aux->file;
	file_page->offset = aux->offset;
	file_page->length = aux->length;
	free (aux);
	ASSERT (!hash_insert (&um_table, &file_page->um_elem));
	return file_map_swap_in (page, kva);
}

/* Swap in the page by read contents from the file. */
static bool
file_map_swap_in (struct page *page, void *kva) {
	struct file_page *file_page;
	struct file *file;
	off_t offset;
	size_t length;

	ASSERT (page && vm_is_page_addr (page->va) && page->frame);
	ASSERT (VM_TYPE (page->operations->type) == VM_FILE);
	ASSERT (kva && page->frame->kva == kva);
	ASSERT (thread_is_user (page->t)
			&& spt_find_page (&page->t->spt, page->va) == page
			&& pml4_get_page (page->t->pml4, page->va) == kva);
	file_page = &page->file;
	ASSERT (hash_find (&um_table, &file_page->um_elem));
	file = file_page->file;
	offset = file_page->offset;
	length = file_page->length;
	ASSERT (file);
	ASSERT (length <= PGSIZE);
	ASSERT (((size_t)offset + length) <= (size_t)file_length (file));/////////////May not be correct

	/* Read the data and fill the rest of the page with zeroes. */
	ASSERT ((size_t)file_read_at (file, kva, length, offset) == length);
	if (length < PGSIZE)
		memset (kva + length, 0, PGSIZE - length);
	/* Remove from unmapped table. */
	ASSERT (hash_delete (&um_table, &file_page->um_elem));
	return true;
}

/* Swap out the page by writeback contents to the file. */
static bool
file_map_swap_out (struct page *page) {
	struct file_page *file_page;
	struct file *file;
	off_t offset;
	size_t length;
	void *kva;

	ASSERT (page && vm_is_page_addr (page->va) && page->frame);
	ASSERT (VM_TYPE (page->operations->type) == VM_FILE);
	kva = page->frame->kva;
	ASSERT (vm_is_page_addr (kva)); //////////////////////////////////////////////Debugging purposes: May be incorrect
	ASSERT (thread_is_user (page->t)
			&& spt_find_page (&page->t->spt, page->va) == page
			&& pml4_get_page (page->t->pml4, page->va) == kva);
			file_page = &page->file;
	ASSERT (!hash_find (&um_table, &file_page->um_elem));

	file = file_page->file;
	offset = file_page->offset;
	length = file_page->length;
	ASSERT (file);
	ASSERT (length > 0 && length <= PGSIZE);
	ASSERT (((size_t)offset + length) <= (size_t)file_length (file));/////////////May not be correct

	ASSERT ((size_t)file_write_at (file, kva, length, offset) == length);
	ASSERT (!hash_insert (&um_table, &file_page->um_elem));
	return true;
}

/* Destory the file mapped page, which must NOT be in the current thread's spt.
 * PAGE will be freed by the caller. */
static void
file_map_destroy (struct page *page) {
	struct file_page *file_page;
	struct file *file;
	off_t offset;
	size_t length;
	void *kva;

	ASSERT (page && vm_is_page_addr (page->va));
	ASSERT (VM_TYPE (page->operations->type) == VM_FILE);
	ASSERT (thread_is_user (page->t) &&
			!spt_find_page (&thread_current ()->spt, page->va));

	file_page = &page->file;
	file = file_page->file;
	offset = file_page->offset;
	length = file_page->length;
	ASSERT (file);
	ASSERT (length <= PGSIZE);
	ASSERT (((size_t)offset + length) <= (size_t)file_length (file));/////////////May not be correct
	/* Writeback all the modified contents to the storage, if on main memory. */
	if (pml4_get_page (page->t->pml4, page->va)) {
		ASSERT (page->frame);
		kva = page->frame->kva;
		ASSERT (vm_is_page_addr (kva)
				&& pml4_get_page (page->t->pml4, page->va) == kva);
		ASSERT (!hash_find (&um_table, &file_page->um_elem));
		ASSERT ((size_t)file_write_at (file, kva, length, offset) == length);
		pml4_clear_page (page->t->pml4, page->va);
		palloc_free_page (kva);
		free (page->frame);
	} else
		ASSERT (hash_delete (&um_table, &file_page->um_elem));
	file_close (file_page->file);
}

/* Do the mmap */
void *
do_mmap (void *addr, size_t length, int writable, struct file *file,
		off_t offset) {
	struct file_page *m_elem;
	size_t page_cnt, read_bytes;
	void *uaddr = addr;

	ASSERT (vm_is_page_addr (addr) && length && file);
	ASSERT (file_length (file) > 0);

	page_cnt = (length % PGSIZE)? 1 + length / PGSIZE: length / PGSIZE;
	if (((size_t)offset + length) > (size_t)file_length (file))
		length = (size_t)(file_length (file) - offset);
	for (size_t i = 0; i < page_cnt; i++) {
		if (i != 0) {
			/* Make sure that FILE is not destroyed until all pages are removed. */
			ASSERT (file_dup2 (file));
		}
		/* Set up aux data and page. */
		m_elem = (struct file_page*)malloc (sizeof (struct file_page));
		if (m_elem) {
			m_elem->file = file;
			m_elem->offset = offset;
			m_elem->length = (length > PGSIZE)? PGSIZE: length;
			if (vm_alloc_page_with_initializer (VM_FILE, uaddr, writable, NULL, m_elem)) {
				uaddr += PGSIZE;
				offset += PGSIZE;
				length -= m_elem->length;
				continue;
			}
			free (m_elem);
		}
		file_close (file);
		return NULL;
	}
	ASSERT (length == 0);
	return addr;
}

/* Do the munmap */
void
do_munmap (void *addr) {
	struct supplemental_page_table *spt = &thread_current ()->spt;

	ASSERT (vm_is_page_addr (addr));

	spt_remove_page (spt, spt_find_page (spt, addr));
}
