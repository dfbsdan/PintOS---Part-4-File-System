#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "threads/malloc.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

/* On-disk inode.
 * Must be exactly DISK_SECTOR_SIZE bytes long. */
struct inode_disk {
	cluster_t start;                		/* First data cluster. */
	off_t length;                       /* File size in bytes. */
	uint32_t is_dir;										/* True: is dir, false otherwise. */
	unsigned magic;                     /* Magic number. */
	uint32_t unused[124];               /* Not used. */
};

/* Returns the number of sectors to allocate for an inode SIZE
 * bytes long. */
static inline size_t
bytes_to_sectors (off_t size) {
	return DIV_ROUND_UP (size, DISK_SECTOR_SIZE);
}

/* In-memory inode. */
struct inode {
	struct list_elem elem;              /* Element in inode list. */
	cluster_t clst;               			/* Cluster number of disk location. */
	int open_cnt;                       /* Number of openers. */
	bool removed;                       /* True if deleted, false otherwise. */
	int deny_write_cnt;                 /* 0: writes ok, >0: deny writes. */
	struct inode_disk data;             /* Inode content. */
};

/* Returns the cluster that contains byte offset POS within INODE.
 * Returns 0 if INODE does not contain data for a byte at offset
 * POS. */
static cluster_t
byte_to_cluster (const struct inode *inode, off_t pos) {
	cluster_t clst;

	ASSERT (inode != NULL);
	ASSERT (pos >= 0);	//////////////////////////////////////////////////////////TESTING LINE

	if (pos < inode->data.length) {
		clst = inode->data.start;
		for (int i = 0; i < pos / DISK_SECTOR_SIZE; i++) {
			clst = fat_get (clst);
			ASSERT (clst != EOChain);
		}
		ASSERT (fat_get (clst));
		return clst;
	}
	else
		return 0;
}

/* List of open inodes, so that opening a single inode twice
 * returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void
inode_init (void) {
	list_init (&open_inodes);
}

/* Initializes an inode with LENGTH bytes of data and
 * writes the new inode to cluster CLST on the file system.
 * If DIR is true, the inode is created as a directory, otherwise as a file.
 * Returns true if successful.
 * Returns false if memory or disk allocation fails. */
bool
inode_create (cluster_t clst, off_t length, bool dir) {
	struct inode_disk *disk_inode = NULL;
	bool success = false;

	ASSERT (length >= 0);
	ASSERT (clst && fat_get (clst) == EOChain);
	if (dir) {
		ASSERT (length == 0);
	}

	/* If this assertion fails, the inode structure is not exactly
	 * one sector in size, and you should fix that. */
	ASSERT (sizeof *disk_inode == DISK_SECTOR_SIZE);

	disk_inode = calloc (1, sizeof *disk_inode);
	if (disk_inode != NULL) {
		size_t sectors = bytes_to_sectors (length);
		disk_inode->length = length;
		disk_inode->is_dir = dir;
		disk_inode->magic = INODE_MAGIC;
		if (fat_allocate (sectors, &disk_inode->start)) {
			disk_write (filesys_disk, cluster_to_sector (clst), disk_inode);
			if (sectors > 0) {
				static char zeros[DISK_SECTOR_SIZE];
				size_t i;
				clst = disk_inode->start;
				for (i = 0; i < sectors; i++) {
					ASSERT (clst != EOChain);
					disk_write (filesys_disk, cluster_to_sector (clst), zeros);
					clst = fat_get (clst);
				}
				ASSERT (clst == EOChain);
			}
			success = true;
		}
		free (disk_inode);
	}
	return success;
}

/* Reads an inode from cluster CLST
 * and returns a `struct inode' that contains it.
 * Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (cluster_t clst) {
	struct list_elem *e;
	struct inode *inode;

	ASSERT (clst && fat_get (clst) == EOChain);

	/* Check whether this inode is already open. */
	for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
			e = list_next (e)) {
		inode = list_entry (e, struct inode, elem);
		if (inode->clst == clst) {
			inode_reopen (inode);
			return inode;
		}
	}

	/* Allocate memory. */
	inode = malloc (sizeof *inode);
	if (inode == NULL)
		return NULL;

	/* Initialize. */
	list_push_front (&open_inodes, &inode->elem);
	inode->clst = clst;
	inode->open_cnt = 1;
	inode->deny_write_cnt = 0;
	inode->removed = false;
	disk_read (filesys_disk, cluster_to_sector (inode->clst), &inode->data);
	ASSERT (inode->data.magic == INODE_MAGIC || inode->clst == ROOT_DIR_CLUSTER);
	return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode) {
	if (inode != NULL) {
		ASSERT (inode->data.magic == INODE_MAGIC || inode->clst == ROOT_DIR_CLUSTER);
		inode->open_cnt++;
	}
	return inode;
}

/* Returns INODE's inode number. */
cluster_t
inode_get_inumber (const struct inode *inode) {
	ASSERT (inode &&
			(inode->data.magic == INODE_MAGIC || inode->clst == ROOT_DIR_CLUSTER));
	return inode->clst;
}

/* Closes INODE and writes it to disk.
 * If this was the last reference to INODE, frees its memory.
 * If INODE was also a removed inode, frees its blocks. */
void
inode_close (struct inode *inode) {
	/* Ignore null pointer. */
	if (inode == NULL)
		return;

		ASSERT (inode &&
				(inode->data.magic == INODE_MAGIC || inode->clst == ROOT_DIR_CLUSTER));

	/* Release resources if this was the last opener. */
	if (--inode->open_cnt == 0) {
		/* Remove from inode list and release lock. */
		list_remove (&inode->elem);

		/* Deallocate blocks if removed. */
		if (inode->removed) {
			fat_remove_chain (inode->clst, 0);
			if (inode->data.start)
				fat_remove_chain (inode->data.start, 0);
		}

		free (inode);
	}
}

/* Marks INODE to be deleted when it is closed by the last caller who
 * has it open. */
void
inode_remove (struct inode *inode) {
	ASSERT (inode &&
			(inode->data.magic == INODE_MAGIC || inode->clst == ROOT_DIR_CLUSTER));
	inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
 * Returns the number of bytes actually read, which may be less
 * than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset) {
	uint8_t *buffer = buffer_;
	off_t bytes_read = 0;
	uint8_t *bounce = NULL;

	ASSERT (inode &&
			(inode->data.magic == INODE_MAGIC || inode->clst == ROOT_DIR_CLUSTER));

	while (size > 0) {
		/* Disk sector to read, starting byte offset within sector. */
		cluster_t clst = byte_to_cluster (inode, offset);
		if (!clst)
			break;
		ASSERT (fat_get (clst));
		int sector_ofs = offset % DISK_SECTOR_SIZE;

		/* Bytes left in inode, bytes left in sector, lesser of the two. */
		off_t inode_left = inode_length (inode) - offset;
		int sector_left = DISK_SECTOR_SIZE - sector_ofs;
		int min_left = inode_left < sector_left ? inode_left : sector_left;

		/* Number of bytes to actually copy out of this sector. */
		int chunk_size = size < min_left ? size : min_left;
		if (chunk_size <= 0)
			break;

		if (sector_ofs == 0 && chunk_size == DISK_SECTOR_SIZE) {
			/* Read full sector directly into caller's buffer. */
			disk_read (filesys_disk, cluster_to_sector (clst), buffer + bytes_read);
		} else {
			/* Read sector into bounce buffer, then partially copy
			 * into caller's buffer. */
			if (bounce == NULL) {
				bounce = malloc (DISK_SECTOR_SIZE);
				if (bounce == NULL)
					break;
			}
			disk_read (filesys_disk, cluster_to_sector (clst), bounce);
			memcpy (buffer + bytes_read, bounce + sector_ofs, chunk_size);
		}

		/* Advance. */
		size -= chunk_size;
		offset += chunk_size;
		bytes_read += chunk_size;
	}
	free (bounce);

	return bytes_read;
}
 /* Grows the given INODE until OFFSET + SIZE can be found inside it. */
static bool
inode_grow (struct inode *inode, off_t offset, off_t size) {
	size_t bytes_left, new_bytes;
	off_t *data_len;
	cluster_t clst;
	static char zeros[DISK_SECTOR_SIZE];

	ASSERT (inode &&
			(inode->data.magic == INODE_MAGIC || inode->clst == ROOT_DIR_CLUSTER));
	data_len = &inode->data.length;
	ASSERT (offset >= *data_len);
	ASSERT (size >= 1);

	/* Make sure there is at least one cluster allocated. */
	if (!inode->data.start) {
		ASSERT (*data_len == 0);
		if (!(inode->data.start = fat_create_chain (0)))
			return false;
		disk_write (filesys_disk, cluster_to_sector (inode->data.start), zeros);
	}

	bytes_left = (size_t)offset + size - *data_len;
	offset = *data_len % DISK_SECTOR_SIZE;
	/* Fill current cluster completely. */
	new_bytes = (DISK_SECTOR_SIZE - (size_t)offset < bytes_left)?
			DISK_SECTOR_SIZE - (size_t)offset: bytes_left;
	*data_len += new_bytes;
	bytes_left -= new_bytes;
	/* Expand inode until OFFSET can be mapped. */
	clst = inode->data.start;
	ASSERT (fat_get (clst));
	while (bytes_left && (clst = fat_create_chain (clst))) {
		disk_write (filesys_disk, cluster_to_sector (clst), zeros);
		new_bytes = (DISK_SECTOR_SIZE < bytes_left)? DISK_SECTOR_SIZE: bytes_left;
		*data_len += new_bytes;
		bytes_left -= new_bytes;
	}
	disk_write (filesys_disk, cluster_to_sector (inode->clst), &inode->data);
	return bytes_left == 0;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
 * Returns the number of bytes actually written, which may be
 * less than SIZE if end of file is reached or an error occurs.
 * (Normally a write at end of file would extend the inode, but
 * growth is not yet implemented.) */
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
		off_t offset) {
	const uint8_t *buffer = buffer_;
	off_t bytes_written = 0;
	uint8_t *bounce = NULL;

	ASSERT (inode &&
			(inode->data.magic == INODE_MAGIC || inode->clst == ROOT_DIR_CLUSTER));
	if (inode->deny_write_cnt)
		return 0;

	while (size > 0) {
		/* Sector to write, starting byte offset within sector. */
		cluster_t clst = byte_to_cluster (inode, offset);
		if (!clst) {
			if (!inode_grow (inode, offset, size))
				break;
			clst = byte_to_cluster (inode, offset);
		}
		ASSERT (fat_get (clst));
		int sector_ofs = offset % DISK_SECTOR_SIZE;

		/* Bytes left in inode, bytes left in sector, lesser of the two. */
		off_t inode_left = inode_length (inode) - offset;
		int sector_left = DISK_SECTOR_SIZE - sector_ofs;
		int min_left = inode_left < sector_left ? inode_left : sector_left;

		/* Number of bytes to actually write into this sector. */
		int chunk_size = size < min_left ? size : min_left;
		if (chunk_size <= 0)
			break;

		if (sector_ofs == 0 && chunk_size == DISK_SECTOR_SIZE) {
			/* Write full sector directly to disk. */
			disk_write (filesys_disk, cluster_to_sector (clst), buffer + bytes_written);
		} else {
			/* We need a bounce buffer. */
			if (bounce == NULL) {
				bounce = malloc (DISK_SECTOR_SIZE);
				if (bounce == NULL)
					break;
			}

			/* If the sector contains data before or after the chunk
			   we're writing, then we need to read in the sector
			   first.  Otherwise we start with a sector of all zeros. */
			if (sector_ofs > 0 || chunk_size < sector_left)
				disk_read (filesys_disk, cluster_to_sector (clst), bounce);
			else
				memset (bounce, 0, DISK_SECTOR_SIZE);
			memcpy (bounce + sector_ofs, buffer + bytes_written, chunk_size);
			disk_write (filesys_disk, cluster_to_sector (clst), bounce);
		}

		/* Advance. */
		size -= chunk_size;
		offset += chunk_size;
		bytes_written += chunk_size;
	}
	free (bounce);

	return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
	void
inode_deny_write (struct inode *inode)
{
	ASSERT (inode &&
			(inode->data.magic == INODE_MAGIC || inode->clst == ROOT_DIR_CLUSTER));
	inode->deny_write_cnt++;
	ASSERT (inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
 * Must be called once by each inode opener who has called
 * inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode) {
	ASSERT (inode &&
			(inode->data.magic == INODE_MAGIC || inode->clst == ROOT_DIR_CLUSTER));
	ASSERT (inode->deny_write_cnt > 0);
	ASSERT (inode->deny_write_cnt <= inode->open_cnt);
	inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (const struct inode *inode) {
	ASSERT (inode &&
			(inode->data.magic == INODE_MAGIC || inode->clst == ROOT_DIR_CLUSTER));
	return inode->data.length;
}

/* Returns the number of times the inode has been opened. */
int
inode_open_cnt (const struct inode *inode) {
	ASSERT (inode &&
			(inode->data.magic == INODE_MAGIC || inode->clst == ROOT_DIR_CLUSTER));
	ASSERT (inode->deny_write_cnt <= inode->open_cnt);
	return inode->open_cnt;
}

/* Returns TRUE if the given INODE is a directory. */
bool
inode_is_dir (const struct inode *inode) {
	ASSERT (inode &&
			(inode->data.magic == INODE_MAGIC || inode->clst == ROOT_DIR_CLUSTER));
	return inode->data.is_dir || inode->clst == ROOT_DIR_CLUSTER;
}
