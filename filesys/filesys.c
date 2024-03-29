#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "devices/disk.h"

/* The disk that contains the file system. */
struct disk *filesys_disk;

static void do_format (void);

/* Initializes the file system module.
 * If FORMAT is true, reformats the file system. */
void
filesys_init (bool format) {
	filesys_disk = disk_get (0, 1);
	if (filesys_disk == NULL)
		PANIC ("hd0:1 (hdb) not present, file system initialization failed");

	inode_init ();

	fat_init ();

	if (format)
		do_format ();

	fat_open ();
}

/* Shuts down the file system module, writing any unwritten data
 * to disk. */
void
filesys_done (void) {
	/* Original FS */
	fat_close ();
}

/* Creates a file named NAME with the given INITIAL_SIZE.
 * If DIR is not null, the file is added to it (not closed), otherwise, to root.
 * Returns true if successful, false otherwise.
 * Fails if a file named NAME already exists,
 * or if internal memory allocation fails. */
bool
filesys_create (const char *name, off_t initial_size, struct dir *dir) {
	cluster_t inode_clst = 0;
	bool success;

	if (dir) {
		success = ((inode_clst = fat_create_chain (0))
				&& inode_create (inode_clst, initial_size, false)
				&& dir_add (dir, name, inode_clst));
	} else {
		dir = dir_open_root ();
		success = (dir != NULL
				&& (inode_clst = fat_create_chain (0))
				&& inode_create (inode_clst, initial_size, false)
				&& dir_add (dir, name, inode_clst));
		dir_close (dir);
	}
	if (!success && inode_clst != 0)
		fat_remove_chain (inode_clst, 0);

	return success;
}

/* Opens the file with the given NAME.
 * If DIR is not null, the file is searched in it (not closed), otherwise,
 * from root.
 * Returns the new file if successful or a null pointer
 * otherwise.
 * Fails if no file named NAME exists,
 * or if an internal memory allocation fails. */
struct file *
filesys_open (const char *name, struct dir *dir) {
	struct inode *inode = NULL;

	if (dir) {
		dir_lookup (dir, name, &inode);
	} else {
		dir = dir_open_root ();
		if (dir != NULL)
			dir_lookup (dir, name, &inode);
		dir_close (dir);
	}
	return file_open (inode);
}

/* Deletes the file named NAME.
 * If DIR is not null, the file is removed from it (not closed), otherwise,
 * from root.
 * Returns true if successful, false on failure.
 * Fails if no file named NAME exists,
 * or if an internal memory allocation fails. */
bool
filesys_remove (const char *name, struct dir *dir) {
	bool success;
	if (dir) {
		success = dir_remove (dir, name);
	} else {
		dir = dir_open_root ();
		success = dir != NULL && dir_remove (dir, name);
		dir_close (dir);
	}
	return success;
}

/* Formats the file system. */
static void
do_format (void) {
	printf ("Formatting file system...");

	/* Create FAT and save it to the disk. */
	fat_create ();
	fat_close ();

	printf ("done.\n");
}
