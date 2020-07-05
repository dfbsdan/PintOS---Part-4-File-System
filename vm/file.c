/* file.c: Implementation of memory mapped file object (mmaped object). */

#include "vm/vm.h"
#include "filesys/file.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "threads/mmu.h"
#include <string.h>
#include <hash.h>
#include <stdio.h>//////////////////////////////////////////////////////////////TEMPORAL

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
	ASSERT (vm_is_page_addr (page->va));
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
	ASSERT (vm_is_page_addr (a_page->va));
	ASSERT (vm_is_page_addr (b_page->va));
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
	file_page->page_cnt = aux->page_cnt;
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
	size_t file_len = (size_t)file_length (file);
	ASSERT (file_len > 0);
	if (length) {
		ASSERT ((length + offset) <= file_len);
	}
	else
		ASSERT ((size_t)offset >= file_len);

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
	ASSERT (vm_is_page_addr (kva));
	ASSERT (thread_is_user (page->t)
			&& spt_find_page (&page->t->spt, page->va) == page
			&& pml4_get_page (page->t->pml4, page->va) == kva);
			file_page = &page->file;
	ASSERT (!hash_find (&um_table, &file_page->um_elem));

	file = file_page->file;
	offset = file_page->offset;
	length = file_page->length;
	ASSERT (file);
	ASSERT (length <= PGSIZE);
	size_t file_len = (size_t)file_length (file);
	ASSERT (file_len > 0);
	if (length) {
		ASSERT ((length + offset) <= file_len);
	}
	else
		ASSERT ((size_t)offset >= file_len);

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
	size_t file_len = (size_t)file_length (file);
	ASSERT (file_len > 0);
	if (length) {
		ASSERT ((length + offset) <= file_len);
	}
	else
		ASSERT ((size_t)offset >= file_len);
	/* Handle mapped page. */
	if (pml4_get_page (page->t->pml4, page->va)) {
		ASSERT (page->frame);
		kva = page->frame->kva;
		ASSERT (vm_is_page_addr (kva)
				&& pml4_get_page (page->t->pml4, page->va) == kva);
		ASSERT (!hash_find (&um_table, &file_page->um_elem));
		/* Writeback all the modified contents to the storage, if modified. */
		if (pml4_is_dirty (page->t->pml4, page->va)) {
			ASSERT ((size_t)file_write_at (file, kva, length, offset) == length);
		}
		pml4_clear_page (page->t->pml4, page->va);
		palloc_free_page (kva);
		free (page->frame);
	} else
		ASSERT (hash_delete (&um_table, &file_page->um_elem));
	file_close (file_page->file);
}

/* Set up the auxiliary data for a file mapped page and the page itself.
 * Returns TRUE on success, FALSE otherwise. */
static bool
set_up_mapped_page (void *uaddr, struct file *file,	off_t offset,
		size_t read_bytes, const bool writable, size_t page_cnt) {
	struct file_page *m_elem;

	ASSERT (vm_is_page_addr (uaddr));
	if (!is_user_vaddr (uaddr))
		return NULL;
	ASSERT (file && offset >= 0);
	ASSERT (read_bytes <= PGSIZE);

	size_t file_len = (size_t)file_length (file);
	ASSERT (file_len > 0);
	if (read_bytes) {
		ASSERT ((read_bytes + offset) <= file_len);
	}
	else
		ASSERT ((size_t)offset >= file_len);
	/* Setup aux data. */
	m_elem = (struct file_page*)malloc (sizeof (struct file_page));
	if (m_elem) {
		m_elem->file = file;
		m_elem->offset = offset;
		m_elem->length = read_bytes;
		m_elem->page_cnt = page_cnt;
		/* Setup page. */
		if (vm_alloc_page_with_initializer (VM_FILE, uaddr, writable, NULL, m_elem))
			return true;
		free (m_elem);
	}
	return false;
}

/* Do the mmap */
void *
do_mmap (void *addr, size_t length, int writable, struct file *file,
		off_t offset) {
	size_t file_len, page_cnt, read_bytes;
	void *uaddr = addr;

	ASSERT (vm_is_page_addr (addr) && is_user_vaddr (addr) && length && file);
	ASSERT (file_length (file) > 0 && pg_ofs (offset) == 0);

	page_cnt = (length % PGSIZE)? 1 + length / PGSIZE: length / PGSIZE;
	file_len = (size_t)file_length (file);
	/* Set offset from start of file. */
	if (offset < 0)
		offset = file_len + offset;
	ASSERT (offset >= 0);
	/* Set length to be the actual number of bytes to read. */
	if (length + offset > file_len)
		length = file_len - offset;
	/* Set up the first page. */
	read_bytes = length < PGSIZE ? length : PGSIZE;
	if (!set_up_mapped_page (uaddr, file, offset, read_bytes, writable, page_cnt)) {
		file_close (file);
		return NULL;
	}
	uaddr += PGSIZE;
	offset += read_bytes;
	length -= read_bytes;
	/* Setup all remaining pages. */
	for (size_t i = 1; i < page_cnt; i++) {
		read_bytes = length < PGSIZE ? length : PGSIZE;
		if (!set_up_mapped_page (uaddr, file, offset, read_bytes, writable, 0)) {
			do_munmap (addr, true);
			return NULL;
		}
		/* Make sure that FILE is not destroyed until all pages are removed. */
		ASSERT (file_dup2 (file));
		/* Advance. */
		uaddr += PGSIZE;
		offset += read_bytes;
		length -= read_bytes;
	}
	ASSERT (length == 0);
	return addr;
}

/* Do the munmap. ERROR must be true ONLY when called inside do_mmap(), i.e.
 * an error occurred when setting up a page. */
void
do_munmap (void *addr, bool error) {
	struct supplemental_page_table *spt = &thread_current ()->spt;
	struct page *page;
	size_t page_cnt;
	struct file_page *m_elem;

	ASSERT (vm_is_page_addr (addr));

	/* Get number of pages and remove the first one. */
	page = spt_find_page (spt, addr);
	ASSERT (page);
	switch (VM_TYPE (page->operations->type)) {
		case VM_UNINIT:
			m_elem = (struct file_page *)page->uninit.aux;
			ASSERT (m_elem->page_cnt > 0);
			break;
		case VM_FILE:
			ASSERT (page->file.page_cnt > 0);
			break;
		default:
			ASSERT (0);
	}
	page_cnt = page->file.page_cnt;
	spt_remove_page (spt, page);
	addr += PGSIZE;
	/* Remove all remaining pages. */
	for (size_t i = 1; i < page_cnt; i++) {
		page = spt_find_page (spt, addr);
		if (!page) {
			ASSERT (error);
			return;
		}
		switch (VM_TYPE (page->operations->type)) {
			case VM_UNINIT:
				m_elem = (struct file_page *)page->uninit.aux;
				ASSERT (m_elem->page_cnt == 0);
				break;
			case VM_FILE:
				ASSERT (page->file.page_cnt == 0);
				break;
			default:
				ASSERT (0);
		}
		spt_remove_page (spt, page);
		addr += PGSIZE;
	}
}
