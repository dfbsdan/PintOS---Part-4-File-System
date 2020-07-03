/* uninit.c: Implementation of uninitialized page.
 *
 * All of the pages are born as uninit page. When the first page fault occurs,
 * the handler chain calls uninit_initialize (page->operations.swap_in).
 * The uninit_initialize function transmutes the page into the specific page
 * object (anon, file, page_cache), by initializing the page object,and calls
 * initialization callback that passed from vm_alloc_page_with_initializer
 * function.
 * */

#include "vm/vm.h"
#include "vm/uninit.h"
#include "threads/malloc.h"

static bool uninit_initialize (struct page *page, void *kva);
static void uninit_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations uninit_ops = {
	.swap_in = uninit_initialize,
	.swap_out = NULL,
	.destroy = uninit_destroy,
	.type = VM_UNINIT,
};

/* DO NOT MODIFY this function */
void
uninit_new (struct page *page, void *va, vm_initializer *init,
		enum vm_type type, void *aux,
		bool (*initializer)(struct page *, enum vm_type, void *)) {
	ASSERT (page != NULL);
	ASSERT (vm_is_page_addr (va));

	*page = (struct page) {
		.operations = &uninit_ops,
		.va = va,
		.frame = NULL, /* no frame for now */
		.uninit = (struct uninit_page) {
			.init = init,
			.type = type,
			.aux = aux,
			.page_initializer = initializer,
		}
	};
}

/* Initalize the page on first fault */
static bool
uninit_initialize (struct page *page, void *kva) {
	struct uninit_page *uninit = &page->uninit;

	/* Fetch first, page_initialize may overwrite the values */
	vm_initializer *init = uninit->init;
	void *aux = uninit->aux;

	/* TODO: You may need to fix this function. */
	return uninit->page_initializer (page, uninit->type, kva) &&
		(init ? init (page, aux) : true);
}

/* Free the resources hold by uninit_page, which must NOT be in the current
 * thread's spt.
 * Although most of pages are transmuted
 * to other page objects, it is possible to have uninit pages when the process
 * exit, which are never referenced during the execution.
 * PAGE will be freed by the caller. */
static void
uninit_destroy (struct page *page) {
	struct uninit_page *uninit;
	struct file_page *m_elem;

	ASSERT (page);
	ASSERT (thread_is_user (page->t));
	ASSERT (!spt_find_page (&page->t->spt, page->va));

	uninit = &page->uninit;
	switch (VM_TYPE (uninit->type)) {
		case VM_ANON:
			switch (VM_SUBTYPE (uninit->type)) {
				case VM_ANON_EXEC:
					/* Uninitlialized segment. */
					free (uninit->aux);
					break;
				case VM_ANON_STACK:
					break;
				default:
					ASSERT (0);
			}
			break;
		case VM_FILE:
			/* Uninitlialized file page. */
			m_elem = (struct file_page *)uninit->aux;
			file_close (m_elem->file);
			free (m_elem);
			break;
		default:
			ASSERT (0);
	}
}
