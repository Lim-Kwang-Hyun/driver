/****************************************************************************
 * SRC (SSD RAID Cache): Device mapper target for block-level disk caching
 * Yongseok Oh (ysoh@uos.ac.kr) 2013 - 2014
 * filename: target.h 
 * 
 * Based on DM-Writeboost:
 *   Log-structured Caching for Linux
 *   Copyright (C) 2012-2013 Akira Hayakawa <ruby.wktk@gmail.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; under version 2 of the License.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 ****************************************************************************/

#ifndef DM_SRC_HEADER_H
#define DM_SRC_HEADER_H


/* SRC Data Layout */
/*
SSD0 | Reserved sectors for superblock | Chunk0 | Chunk1 | ... | ChunkN |
SSD1 | Reserved sectors for superblock | Chunk0 | Chunk1 | ... | ChunkN |
SSD2 | Reserved sectors for superblock | Chunk0 | Chunk1 | ... | ChunkN |
				...	 ...
SSDN | Reserved sectors for superblock | Chunk0 | Chunk1 | ... | ChunkN |
*/


// Reserved Sectors for Superblock 
#define RESERVED_START	0 
#define RESERVED_LENGTH	GROUP_SZ_SECTOR // sector unit 

#define MAX_CACHE_DEVS	8

#ifndef __KERNEL__
typedef u_int64_t sector_t;
#endif
/*
 * Superblock Header
 * First one sector of the super block region.
 * The value is fixed after formatted.
 */
 /*
  * Magic Number
  * "WBst"
  */
#define SRC_MAGIC 0x57427374
struct superblock_device {
	// read only data
	__u32 magic;
	__u32 uuid;
	__u32 create_time;
	sector_t ssd_devsize; // sector unit
	sector_t hdd_devsize; // sector unit
	__u32 block_size; // sector unit
	__u32 chunk_size; // sector unit
	__u32 chunk_group_size; // sector unit
	__u32 chunks_per_group;
	__u32 parity_allocation;
	__u32 striping_policy;
	__u32 data_allocation;
	__u32 erasure_code;
	__u32 hot_identification;
	__u32 reclaim_policy;
	__u32 victim_policy;
	__u32 rambuf_pool_amount; // page unit (4KB)
	__u32 flush_command;

	__u32 aligned_io_dummy;

	__u32 num_chunks;
	__u32 num_blocks_per_chunk;
	__u32 num_blocks_per_ssd;

	__u32 num_groups;

	__u32 num_summary_per_chunk;
	__u32 num_entry_per_page;
} __attribute__((packed));

#define MB_SEAL			0
#define MB_DIRTY		1
#define MB_VALID		2
#define MB_PARITY		3
#define MB_DUMMY		4
#define MB_SKIP			5
#define MB_SUMMARY		6
#define MB_BROKEN		7
#define MB_PARITY_NEED	8
#define MB_PARITY_WRITTEN	9
#define MB_HIT				10

/*
 * Metadata of a 4KB cache line
 *
 * Dirtiness is defined for each sector
 * in this cache line.
 */
struct metablock {
#ifdef __KERNEL__
	struct hlist_node ht_list;
#else
	__u64 ht_list;
#endif
	unsigned long mb_flags;
	sector_t sector; /* key */
	__u32 idx;
	__u16 checksum;
} __attribute__((packed));

/*
 * On-disk metablock
 *
 * Its size must be a factor of one sector
 * to avoid starddling neighboring two sectors.
 * Facebook's flashcache does the same thing.
 */
struct metablock_device {
	__u32 sector;
	__u8 dirty_bits;
	__u8 checksum;
	__u8 padding[8 - (4 + 1 + 1)]; /* 16B */
} __attribute__((packed));


#define SEGMENT_HEADER_SIZE	4096

/* Various Options  */

// Flush Command Options 
#define FLUSH_NONE		0
#define FLUSH_FINE		1
#define FLUSH_COARSE	2

// Erasure Coding Schemes
#define ERASURE_CODE_NONE	0
#define ERASURE_CODE_PARITY 1
#define ERASURE_CODE_RAID6	2

// Parity Allocation
#define PARITY_ALLOC_FIXED 0
#define PARITY_ALLOC_ROTAT 1

// Aligned I/O with Dummy 
#define ALIGNED_IO_DUMMY	0
#define ALIGNED_IO_SKIP		1

// Data Allocation Strategy
#define DATA_ALLOC_VERT				0
#define DATA_ALLOC_HORI				1
#define DATA_ALLOC_FLEX_VERT		2 /* Experimental */
#define DATA_ALLOC_FLEX_HORI		3 /* Experimental */

// Read & Write Data Separation (clean & dirty data separation)
#define SEPAR_STRIPING	0 // read write separated striping 
#define MIXED_STRIPING	1 // read write mixed striping 

// Victim Selection Policy to make room for new ones 
#define VICTIM_CLOCK	0
#define VICTIM_LRU		1
#define VICTIM_GREEDY	2

// Free Space Reclaimation Policy
#define RECLAIM_SELECTIVE	0 // when current u of SRC is greater than U_MAX, destage performs. Otherwise, GC will do.
#define RECLAIM_DESTAGE		1 // data movement from SSDs to HDDs
#define RECLAIM_GC			2 // data movement from SSDs to SSDs

// Garbage Collection Option
#define GC_WITHOUT_DIRTY_SYNC	0
#define GC_WITH_DIRTY_SYNC		1

#define DEFAULT_U_MAX	90
#define MIN_FREE		10 // Reserved for GC and Initial Allocation

#define NUM_GC_THREAD	8

#define MAX_MIGRATE_INFLIGHT_NUM 10

#define DEFAULT_MIGRATE_LOWWATER 20
#define DEFAULT_MIGRATE_HIGHWATER 40

// A read hit bit is matained
#define HIT_BITMAP_PER_STRIPE	0
#define HIT_BITMAP_PER_BLOCK	1

// Summary Type
#define SUMMARY_PER_CHUNK 	1
#define SUMMARY_PER_STRIPE	2  // Unsupported 
#define SUMMARY_SCHEME  SUMMARY_PER_CHUNK

// DRAM Buffer or Stripe Type
#define WCBUF	0 // write cold buffer
#define WHBUF	1 // write hot buffer
#define RCBUF	2 // read cold buffer 
#define RHBUF	3 // read hot buffer 
#define GWBUF	4 // GC write buffer
#define GRBUF	5 // GC read buffer
#define RCVBUF	6 // recovery buffer
#define NBUF	7

#define is_write_stripe(x) (x==WCBUF||x==WHBUF||x==GWBUF)
#define is_read_stripe(x)  (x==RCBUF||x==RHBUF||x==GRBUF)
#define is_normal_stripe(x) (x==RCBUF || x==RHBUF || x==WCBUF|| x==WHBUF)
#define is_gc_stripe(x) (x==GRBUF || x==GWBUF)
#define is_cold_stripe(x) (x==WCBUF || x==RCBUF)

// Sector Size 
#define SECTOR_SHIFT		9
#define SECTOR_SIZE		(1 << SECTOR_SHIFT)
#define SECTORS_PER_PAGE_SHIFT	(PAGE_SHIFT - SECTOR_SHIFT)
#define SECTORS_PER_PAGE	(1 << SECTORS_PER_PAGE_SHIFT)

// SRC Page Size
#define SRC_SIZE_SHIFT 0 // 4KB
//#define SRC_SIZE_SHIFT 1 // 8KB 
//#define SRC_SIZE_SHIFT 2 // 16KB
//#define SRC_SIZE_SHIFT 3 // 32KB

#define SRC_PAGE_SIZE ((SECTOR_SIZE * SECTORS_PER_PAGE)<<SRC_SIZE_SHIFT)
#define SRC_SECTORS_PER_PAGE (SRC_PAGE_SIZE/SECTOR_SIZE)
#define SRC_SECTORS_PER_PAGE_SHIFT (SECTORS_PER_PAGE_SHIFT+SRC_SIZE_SHIFT)

//#define USE_RAID_FTL
//#define USE_DIRECT_PARITY
//#define USE_CHECKSUM
#define USE_GHOST_BUFFER
#define USE_PENDING_WORKER

#define USE_LAST_SUMMARY	0
#define USE_FIRST_SUMMARY	1
#define SUMMARY_LOCATION USE_LAST_SUMMARY

#ifdef USE_CHECKSUM
#define NUM_SUMMARY 2
#else
//#define NUM_SUMMARY 1
#define NUM_SUMMARY (super->param.num_summary_per_chunk)
#define NUM_ENTRY_PER_PAGE (super->param.num_entry_per_page)
#endif 

#define USE_SEG_WRITER 0


#endif 
