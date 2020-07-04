#include "filesys/fat.h"
#include "devices/disk.h"
#include "filesys/filesys.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include <stdio.h>
#include <string.h>

/* Should be less than DISK_SECTOR_SIZE */
struct fat_boot {
	unsigned int magic;
	unsigned int sectors_per_cluster; /* Fixed to 1 */
	unsigned int total_sectors;
	unsigned int fat_start;
	unsigned int fat_sectors; /* Size of FAT in sectors. */
	unsigned int root_dir_cluster;
};

/* FAT FS */
struct fat_fs {
	struct fat_boot bs;
	unsigned int *fat;
	unsigned int fat_length;
	disk_sector_t data_start;
	cluster_t last_clst;
	struct lock write_lock;
};

static struct fat_fs *fat_fs = NULL;

void fat_boot_create (void);
void fat_fs_init (void);

void
fat_init (void) {
	fat_fs = calloc (1, sizeof (struct fat_fs));
	if (fat_fs == NULL)
		PANIC ("FAT init failed");

	// Read boot sector from the disk
	unsigned int *bounce = malloc (DISK_SECTOR_SIZE);
	if (bounce == NULL)
		PANIC ("FAT init failed");
	disk_read (filesys_disk, FAT_BOOT_SECTOR, bounce);
	memcpy (&fat_fs->bs, bounce, sizeof (fat_fs->bs));
	free (bounce);

	// Extract FAT info
	if (fat_fs->bs.magic != FAT_MAGIC)
		fat_boot_create ();
	fat_fs_init ();
}

void
fat_open (void) {
	fat_fs->fat = calloc (fat_fs->fat_length, sizeof (cluster_t));
	if (fat_fs->fat == NULL)
		PANIC ("FAT load failed");

	// Load FAT directly from the disk
	uint8_t *buffer = (uint8_t *) fat_fs->fat;
	off_t bytes_read = 0;
	off_t bytes_left = sizeof (fat_fs->fat);
	const off_t fat_size_in_bytes = fat_fs->fat_length * sizeof (cluster_t);
	for (unsigned i = 0; i < fat_fs->bs.fat_sectors; i++) {
		bytes_left = fat_size_in_bytes - bytes_read;
		if (bytes_left >= DISK_SECTOR_SIZE) {
			disk_read (filesys_disk, fat_fs->bs.fat_start + i,
			           buffer + bytes_read);
			bytes_read += DISK_SECTOR_SIZE;
		} else {
			uint8_t *bounce = malloc (DISK_SECTOR_SIZE);
			if (bounce == NULL)
				PANIC ("FAT load failed");
			disk_read (filesys_disk, fat_fs->bs.fat_start + i, bounce);
			memcpy (buffer + bytes_read, bounce, bytes_left);
			bytes_read += bytes_left;
			free (bounce);
		}
	}
}

void
fat_close (void) {
	// Write FAT boot sector
	uint8_t *bounce = calloc (1, DISK_SECTOR_SIZE);
	if (bounce == NULL)
		PANIC ("FAT close failed");
	memcpy (bounce, &fat_fs->bs, sizeof (fat_fs->bs));
	disk_write (filesys_disk, FAT_BOOT_SECTOR, bounce);
	free (bounce);

	// Write FAT directly to the disk
	uint8_t *buffer = (uint8_t *) fat_fs->fat;
	off_t bytes_wrote = 0;
	off_t bytes_left = sizeof (fat_fs->fat);
	const off_t fat_size_in_bytes = fat_fs->fat_length * sizeof (cluster_t);
	for (unsigned i = 0; i < fat_fs->bs.fat_sectors; i++) {
		bytes_left = fat_size_in_bytes - bytes_wrote;
		if (bytes_left >= DISK_SECTOR_SIZE) {
			disk_write (filesys_disk, fat_fs->bs.fat_start + i,
			            buffer + bytes_wrote);
			bytes_wrote += DISK_SECTOR_SIZE;
		} else {
			bounce = calloc (1, DISK_SECTOR_SIZE);
			if (bounce == NULL)
				PANIC ("FAT close failed");
			memcpy (bounce, buffer + bytes_wrote, bytes_left);
			disk_write (filesys_disk, fat_fs->bs.fat_start + i, bounce);
			bytes_wrote += bytes_left;
			free (bounce);
		}
	}
}

void
fat_create (void) {
	// Create FAT boot
	fat_boot_create ();
	fat_fs_init ();

	// Create FAT table
	fat_fs->fat = calloc (fat_fs->fat_length, sizeof (cluster_t));
	if (fat_fs->fat == NULL)
		PANIC ("FAT creation failed");

	// Set up ROOT_DIR_CLST
	fat_put (ROOT_DIR_CLUSTER, EOChain);

	// Fill up ROOT_DIR_CLUSTER region with 0
	uint8_t *buf = calloc (1, DISK_SECTOR_SIZE);
	if (buf == NULL)
		PANIC ("FAT create failed due to OOM");
	disk_write (filesys_disk, cluster_to_sector (ROOT_DIR_CLUSTER), buf);
	free (buf);
}

void
fat_boot_create (void) {
	unsigned int fat_sectors =
	    (disk_size (filesys_disk) - 1)
	    / (DISK_SECTOR_SIZE / sizeof (cluster_t) * SECTORS_PER_CLUSTER + 1) + 1;
	fat_fs->bs = (struct fat_boot){
	    .magic = FAT_MAGIC,
	    .sectors_per_cluster = SECTORS_PER_CLUSTER,
	    .total_sectors = disk_size (filesys_disk),
	    .fat_start = 1,
	    .fat_sectors = fat_sectors,
	    .root_dir_cluster = ROOT_DIR_CLUSTER,
	};
}

/*
Initialize FAT file system.
You have to initialize fat_length and data_start field of fat_fs.
fat_length stores how many clusters in the filesystem and
data_start stores in which sector we can start to store files.
You may want to exploit some values stored in fat_fs->bs.
Also, you may want to initialize some other useful data in this function.
*/

void
fat_fs_init (void) {
	ASSERT (fat_fs);
	ASSERT (fat_fs->bs.sectors_per_cluster == 1);
	ASSERT (fat_fs->bs.fat_sectors < fat_fs->bs.total_sectors);

	fat_fs->data_start = 1 + fat_fs->bs.fat_sectors;
	fat_fs->fat_length = fat_fs->bs.total_sectors - fat_fs->data_start;
	lock_init (&fat_fs->write_lock);
}

/*----------------------------------------------------------------------------*/
/* FAT handling                                                               */
/*----------------------------------------------------------------------------*/

/* Add a cluster to the chain.
 * If CLST is 0, start a new chain.
 * Returns 0 if fails to allocate a new cluster. */
cluster_t
fat_create_chain (cluster_t clst) {
	cluster_t new_clst;

	ASSERT (clst < fat_fs->fat_length);

	lock_acquire (&fat_fs->write_lock);
	/* Look for an empty cluster. */
	for (new_clst = ROOT_DIR_CLUSTER + 1; new_clst < fat_fs->fat_length; new_clst++) {
		if (fat_fs->fat[new_clst] == 0) {
			fat_fs->fat[new_clst] = EOChain;
			break;
		}
	}
	ASSERT (new_clst <= fat_fs->fat_length);
	if (new_clst == fat_fs->fat_length) {
		/* No empty cluster found. */
		lock_release (&fat_fs->write_lock);
		return 0;
	}
	if (clst != 0)
		/* Add to chain. */
		fat_fs->fat[clst] = new_clst;
	lock_release (&fat_fs->write_lock);
	return new_clst;
}

/* Starting from CLST, remove clusters from a chain. PCLST should be the direct
 * previous cluster in the chain. This means, after the execution of this
 * function, PCLST should be the last element of the updated chain. If CLST is
 * the first element in the chain, PCLST should be 0. */
void
fat_remove_chain (cluster_t clst, cluster_t pclst) {
	cluster_t next;

	ASSERT (clst && clst < fat_fs->fat_length);
	ASSERT (pclst < fat_fs->fat_length);

	lock_acquire (&fat_fs->write_lock);
	if (pclst != 0) {
		ASSERT (fat_fs->fat[pclst] == clst);
		fat_fs->fat[pclst] = EOChain;
	}
	while (fat_fs->fat[clst] != EOChain) {
		next = fat_fs->fat[clst];
		ASSERT (next && next < fat_fs->fat_length);
		fat_fs->fat[clst] = 0;
		clst = next;
	}
	fat_fs->fat[clst] = 0; //EOChain
	lock_release (&fat_fs->write_lock);
}

/* Allocates CNT linked clusters from the FAT and stores
 * the first into *CLSTP.
 * Returns true if successful, false otherwise. */
bool
fat_allocate (size_t cnt, cluster_t *clstp) {
	cluster_t clst;

	ASSERT (clstp);

	*clstp = fat_create_chain (0);
	if (*clstp) {
		clst = *clstp;
		for (size_t i = 1; i < cnt; i++) {
			clst = fat_create_chain (clst);
			if (clst == 0) { //Error
				fat_remove_chain (*clstp, 0);
				*clstp = 0;
				return false;
			}
		}
		return true;
	}
	return false;
}

/* Update FAT entry pointed by cluster number CLST to VAL. Since each entry in
 * FAT points the next cluster in a chain (if exist; otherwise EOChain), this
 * could be used to update connectivity. */
void
fat_put (cluster_t clst, cluster_t val) {
	ASSERT (clst && clst < fat_fs->fat_length);
	ASSERT (val && (val == EOChain || val < fat_fs->fat_length));

	lock_acquire (&fat_fs->write_lock);
	fat_fs->fat[clst] = val;
	lock_release (&fat_fs->write_lock);
}

/* Fetch a value in the FAT table. */
cluster_t
fat_get (cluster_t clst) {
	ASSERT (clst && clst < fat_fs->fat_length);
	cluster_t val = fat_fs->fat[clst];
	ASSERT (val && (val == EOChain || val < fat_fs->fat_length));
	return val;
}

/* Covert a cluster # to a sector number. */
disk_sector_t
cluster_to_sector (cluster_t clst) {
	ASSERT (clst && clst < fat_fs->fat_length);
	return fat_fs->data_start + clst - 1;
}
