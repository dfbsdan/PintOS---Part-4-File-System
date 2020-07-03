#ifndef VM_FILE_H
#define VM_FILE_H
#include "vm/vm.h"
#include "filesys/file.h"

struct page;
enum vm_type;

struct file_page {
	struct page *page;					/* Points to the page that holds it. */
	struct file *file;					/* Pointer to the attached file. */
	off_t offset;								/* Offset inside the file. */
	size_t length;							/* Number of bytes starting at offset. */
	size_t page_cnt;						/* Number of contiguous pages allocated for the
															 * mapping. Must be different to 0 ONLY for the
															 * first page mapped. */
	struct hash_elem um_elem;		/* Element used by the um_table in order to keep
															 * track of the swapped pages. */
};

void vm_file_init (void);
bool file_map_initializer (struct page *page, enum vm_type type, void *kva);
void *do_mmap(void *addr, size_t length, int writable,
		struct file *file, off_t offset);
void do_munmap (void *addr, bool error);
#endif
