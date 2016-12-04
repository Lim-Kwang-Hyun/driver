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

#ifndef DM_SRC_H
#define DM_SRC_H

#define DM_MSG_PREFIX "dm-src"

#include <linux/module.h>
#include <linux/version.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/mutex.h>
#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/timer.h>
#include <linux/workqueue.h>
#include <linux/device-mapper.h>
#include <linux/dm-io.h>
#include <linux/types.h>
#include "raid.h"
#include "header.h"


#define CRC_SEED 17

#define NUM_SSD (super->dev_info.num_cache_devs)
#define NUM_DATA_SSD (super->dev_info.num_data_cache_devs) // excluding parity SSD

#define NUM_BLOCKS (super->cache_stat.num_blocks_per_ssd * NUM_SSD)
#define NUM_USED_BLOCKS (atomic_read(&super->cache_stat.num_used_blocks))
#define NUM_BLOCKS_PER_SSD (super->cache_stat.num_blocks_per_ssd)

#define CHUNK_SZ (super->cache_stat.num_blocks_per_chunk)
#define CHUNK_SZ_SECTOR (super->cache_stat.num_blocks_per_chunk<<3)

#define SEGMENT_GROUP_SIZE (super->cache_stat.num_chunks_per_group)
#define GROUP_SZ (SEGMENT_GROUP_SIZE*super->cache_stat.num_blocks_per_chunk)
#define GROUP_SZ_SECTOR (SEGMENT_GROUP_SIZE*(super->cache_stat.num_blocks_per_chunk<<3))

#define STRIPE_SZ (CHUNK_SZ * NUM_SSD)
#define STRIPE_SZ_SECTOR (CHUNK_SZ_SECTOR * NUM_SSD)

#define SEG_START_IDX(s) (s->seg_id * STRIPE_SZ)

// parameter macros
#define NO_USE_ERASURE_CODE(param) ((param)->erasure_code==ERASURE_CODE_NONE)
#define USE_ERASURE_CODE(param) ((param)->erasure_code!=ERASURE_CODE_NONE)
#define USE_ERASURE_PARITY(param) ((param)->erasure_code==ERASURE_CODE_PARITY)
#define USE_ERASURE_RAID6(param) ((param)->erasure_code==ERASURE_CODE_RAID6)

#define STRIPING_POLICY (super->param.striping_policy)

#define MIGRATE_LOWWATER (super->param.migrate_lowwater)
#define MIGRATE_HIGHWATER (super->param.migrate_highwater)

// sequential cutoff size 
#define SEQ_CUTOFF  (8192*512) //sectors e.g, 4MB same as bcache 
#define SEQ_CUTOFF_MIN  (256*512) //128KB
#define SEQ_CUTOFF_MAX (SEQ_CUTOFF*4) // 16MB

// timeout value to wait 
#define TIMEOUT_US 10

// Reasons why a pending I/O request is not processed 
#define RES_MIG			1
#define RES_PARTIAL		2
#define RES_SEAL		3
#define RES_NOFREE1		4
#define RES_NOFREE2		5
#define RES_FLUSH		6
#define RES_BYPASS		7
#define RES_ACTIVE		8
#define RES_DRAM		9
#define RES_COUNT		10


// Segment State
#define SEG_CLEAN		0
#define SEG_USED		1
#define SEG_SEALED		2
#define SEG_MIGRATING	3
#define SEG_PARTIAL 	4
#define SEG_RECOVERY 	5
#define SEG_HIT			6
#define SEG_LOCK		7

struct group_header {
	spinlock_t lock;
	u32 group_id;
	u32 current_seg_id;
	atomic_t free_seg_count;
	atomic_t sealed_seg_count;
	atomic_t valid_count;

	atomic_t num_used_ssd;
	atomic_t skewed_segment;

	struct list_head alloc_list;
	struct list_head group_head;
};


struct segment_header {
	spinlock_t lock;
	struct list_head alloc_list;
	struct list_head group_list;
	struct list_head migrate_list;

	struct group_header *group;

	u64 seg_id;
	u64 group_id;
	u64 sequence; // sequence number 
	u32 seg_type;
	u32 seg_load;
	unsigned long flags;

	atomic_t valid_count;
	atomic_t valid_clean_count;
	atomic_t valid_dirty_count;
	atomic_t dummy_count;
	atomic_t dirty_count;
	atomic_t hot_count;
	atomic_t hot_clean_count;

	atomic_t part_start;
	atomic_t part_length;
	atomic_t length;
	
	atomic_t bios_count;

	atomic_t num_read_inflight;
	atomic_t num_filling;
	atomic_t num_writeback;
	atomic_t num_bufcopy;
	atomic_t num_migios;

	atomic_t summary_start[MAX_CACHE_DEVS];
};

/*
 * (Locking)
 * Locking metablocks by their granularity
 * needs too much memory space for lock structures.
 * We only locks a metablock by locking the parent segment
 * that includes the metablock.
 */
#define lockseg(seg, flags) spin_lock_irqsave(&(seg)->lock, flags)
#define unlockseg(seg, flags) spin_unlock_irqrestore(&(seg)->lock, flags)

/*
 * On-disk segment header.
 *
 * Must be at most 4KB large.
 */
struct segment_header_device {
	/* - FROM ------------------------------------ */
	__le64 sequence;
	__le64 uuid;
	__le32 magic;
	__le32 type;
	/*
	 * On what lap in rorating on cache device
	 * used to find the head and tail in the
	 * segments in cache device.
	 */
	__le32 lap;
	u8 padding[SEGMENT_HEADER_SIZE - (8 + 8 + 4 + 4 + 4)]; /* 512B */
	/* - TO -------------------------------------- */
	//struct metablock_device mbarr[0]; /* 16B * N */
} __packed;

struct rambuffer {
	struct list_head list;
	struct rambuf_page **pages;
	int rambuf_id;
	int alloc_count;
	atomic_t ref_count;

	void *seg_buf[MAX_CACHE_DEVS];

	struct bio **bios;
	atomic_t bios_count[MAX_CACHE_DEVS];
	atomic_t bios_start[MAX_CACHE_DEVS];
	atomic_t bios_total_count;
	atomic_t bios_total_start;
	spinlock_t lock;
//	struct li lock[MAX_CACHE_DEVS];
};

struct ht_head {
	struct hlist_head ht_list;
};

struct io {
	/* Used to track sequential IO so it can be skipped */
	struct hlist_node	hash;
	struct list_head	lru;

	unsigned long		jiffies;
	unsigned		sequential;
	sector_t		last;
};

struct read_caching_job_list{
	spinlock_t rm_spinlock;
	atomic_t rm_copy_count;
	struct list_head rm_copy_head;
};

struct read_caching_job{
	struct list_head gn_list;

	struct bio *gn_bio;
	struct dmsrc_super *gn_super;
	unsigned long gn_bio_error;

	struct metablock *gn_mb;
	struct segment_header *gn_seg;
	struct rambuffer *gn_rambuf;

	sector_t gn_sector;
};

struct super_stat{
	u32 hit;
	u32 count;
	u32 read_hit;
	u32 read_count;
	u32 write_hit;
	u32 write_count;

	atomic64_t average_arrival_time; // us
	atomic64_t average_arrival_count; // us

	atomic_t seq_bypass_count;
	atomic_t cold_bypass_count;

	atomic_t destage_count;
	atomic_t gc_count;
	atomic_t gc_empty_count;
	atomic_t total_migration;
	atomic64_t victim_util;
	atomic64_t victim_count;

	atomic64_t gc_io_count;

	atomic64_t destage_io_count;
	
	atomic64_t ssd_write_hit_count;
	atomic64_t ssd_write_miss_count;

	atomic64_t ssd_read_hit_count;
	atomic64_t ssd_read_miss_count;

	atomic_t seg_count[NBUF];

	atomic_t partial_write_count;;
	atomic_t bypass_write_count;;

//	u64 write_util_sum;
//	u64 write_util_count;
};

// actual summary I/O job
#if 0 
struct summary_io_job{
	int seg_length;
	int cache_type;
	struct segment_header *seg;
	struct rambuffer *rambuf;
	struct bio_list barrier_ios;
	void *super;
	atomic_t count;
	atomic_t release;
	//struct dm_io_request *io_array;
	//struct dm_io_region *region_array;
};
#endif

// invation of segment summary I/O
struct flush_invoke_job {
	struct list_head list;
	struct segment_header *seg;
	struct rambuffer *rambuf;
	struct bio_list barrier_ios;

	int seg_length;
	int flush_data;
	int build_summary;
	int cache_type;
	int force_seal;
	u64 global_seg_sequence;
	atomic_t bios_start[MAX_CACHE_DEVS];
	atomic_t bios_count[MAX_CACHE_DEVS];
};

// writeback I/O job
struct wb_job{
	struct dmsrc_super *super;
	struct segment_header *seg;
	struct metablock *mb;
	struct bio *bio;
	struct rambuffer *rambuf;
//	struct page_list *pl;
	atomic_t rambuf_release;
	u32 start_idx;
	u32 count;
	int flush_command;
	int error;
	struct list_head list;
};

struct recovery_job{
	struct dmsrc_super *super;
	struct segment_header *seg;
	struct rambuffer *rambuf;
	struct metablock *mb;
	struct list_head recovery_list;
	atomic_t num_remaining_ios;
	int is_read;
	int error;
};

struct degraded_job{
	struct dmsrc_super *super;
	struct segment_header *seg;
	struct metablock *mb;
	struct list_head degraded_list;
	struct bio *org_bio;
	atomic_t num_remaining_ios;
	void *buf;
	int error;
};

#if 0
struct plug_job{
	struct list_head plug_list;
	struct segment_header *seg;
	struct rambuffer *rambuf;
	struct bio *bio;
	u32 idx;
};
#endif


struct rambuf_page{
	struct list_head list;
//	struct page *page;
	struct page_list *pl;
//	void *data;
};

struct multi_allocator{
	spinlock_t lock[MAX_CACHE_DEVS];
	s32 cursor[MAX_CACHE_DEVS]; 
	atomic_t count[MAX_CACHE_DEVS];
	atomic_t total_count; 
	atomic_t *row_count;
	atomic_t cur_dev;
	int seg_empty_chunk_map[NBUF][MAX_CACHE_DEVS];
	int group_empty_chunk_map[NBUF][MAX_CACHE_DEVS];
	//int empty_chunk_map[NBUF][MAX_CACHE_DEVS];
};

#define MAX_ARRIVAL_TIME 16384
#define DEFAULT_ARRIVAL_US 100

/* Pending I/O Manager  */
struct pending_manager{
	spinlock_t lock;
	struct bio_list bios;
	struct workqueue_struct *wq;
	struct work_struct work;
	atomic64_t io_count;

	//struct timeval arrival_times[MAX_ARRIVAL_TIME];
	struct timespec arrival_times[MAX_ARRIVAL_TIME];
	atomic_t arrival_start;
	atomic_t arrival_count;
	atomic_t arrival_cur;

	/* Barrier I/O Manager  */
	spinlock_t barrier_lock;
	struct bio_list barrier_ios;
	atomic_t barrier_count;

	struct dmsrc_super *super;

	/* Writeback Job Pool */
	mempool_t *wb_job_pool;
	int initialized;
};


/* For tracking sequential IO */
/* Adopted from Bcache */
#define RECENT_IO_BITS	7
#define RECENT_IO	(1 << RECENT_IO_BITS)
struct seq_io_detector{
	spinlock_t seq_lock;
	struct io		io[RECENT_IO];
	struct hlist_head	io_hash[RECENT_IO + 1];
	struct list_head	io_lru;
};


/* Segment Buffer Manager */
struct segbuf_manager{
	spinlock_t lock;

	int initialized;

	struct rambuffer *current_rambuf[NBUF];
	struct rambuffer *rambuf_pool;
	u32 num_rambuf_pool; 

	void **pages;
	void **bios;

	struct list_head active_list;;
	struct list_head inactive_list;
	atomic_t active_total_count;
	atomic_t active_count[NBUF];
	atomic_t inactive_count;

	struct list_head active_page_list;
	struct list_head inactive_page_list;
	atomic_t active_page_count;
	atomic_t inactive_page_count;
	atomic_t total_page_count;

	atomic_t gc_active_page_count;

	wait_queue_head_t wait_queue;
};

/* Segment Allocation Structure */
struct segment_allocator{
	spinlock_t alloc_lock;

	struct list_head group_alloc_queue;
	struct list_head group_used_queue;
	struct list_head group_sealed_queue;
	struct list_head group_migrate_queue;

	atomic_t group_alloc_count;
	u32 group_used_count;
	u32	group_sealed_count;
	atomic_t group_migrate_count;

	struct list_head seg_alloc_queue;
	struct list_head seg_used_queue;
	struct list_head seg_sealed_queue;
	struct list_head seg_migrate_queue;

	atomic_t seg_alloc_count;
	u32 seg_used_count;
	u32	seg_sealed_count;
	atomic_t seg_migrate_count;
	wait_queue_head_t alloc_wait_queue;
};

/* Degraded I/O Manager	*/
struct degraded_manager{
	mempool_t *job_pool; /* 8 sector buffer pool */
	mempool_t *buf_pool; /* 8 sector buffer pool */

	struct workqueue_struct *wq;
	struct work_struct work;
	spinlock_t lock;
	struct list_head queue;
	struct dmsrc_super *super;
	int initialized;
};

/* Recovery Manager */
struct recovery_manager{
	atomic_t broken_block_count;
	struct task_struct *daemon;

	mempool_t *job_pool;

	struct workqueue_struct *wq;
	struct work_struct work;

	spinlock_t lock;
	struct list_head queue;

	int failure_ssd;

	unsigned long start_jiffies;
	unsigned long end_jiffies;

	struct dmsrc_super *super;

	int initialized;
};

/* Flush Meta & Parity Mager */
struct flush_manager{
	struct task_struct *daemon;

	spinlock_t lock;
	struct list_head queue;
	atomic_t invoke_count;
	atomic64_t global_seg_sequence;
	atomic_t io_count;
	mempool_t *invoke_pool;
//	mempool_t *io_pool;

	int initialized;
};

/*	Migration Worker */
struct migration_manager{
	struct task_struct *daemon;

	atomic_t migrate_triggered;
	atomic_t background_gc_on;
	int allow_migrate;

	spinlock_t mig_queue_lock;
	spinlock_t group_queue_lock;
	struct list_head mig_queue;
	struct list_head copy_queue;
	struct list_head group_queue;

	struct segment_header *gc_cur_seg;
	int gc_cur_offset;
	int gc_alloc_count;

	mempool_t *copy_job_pool;
	mempool_t *group_job_pool;
	atomic_t group_job_count;
	atomic_t copy_job_count;
	atomic_t group_job_seq;
//	mempool_t *mig_job_pool;

	struct workqueue_struct *mig_wq;
	struct work_struct mig_work;
	atomic_t mig_inflights;
	atomic_t mig_completes;
//	atomic_t mig_cur_kcopyd;
	struct list_head migrate_queue;

	atomic_t migrate_queue_count;

	struct dmsrc_super *super;

	int initialized;
};


/* Pluging Worker */
struct plugging_manager{
	struct timer_list timer;
	spinlock_t lock[MAX_CACHE_DEVS];
	struct list_head queue[MAX_CACHE_DEVS];
	atomic_t total_length;
	atomic_t queue_length[MAX_CACHE_DEVS];
	unsigned long last_jiffies[MAX_CACHE_DEVS];
	unsigned long deadline_us; /* param */
	//mempool_t *mem_pool;

	struct dmsrc_super *super;
	
	int initialized;
};

/* seg write  wokrer  */
struct seg_write_manager{
	struct work_struct work;
	struct workqueue_struct *wq;

	spinlock_t spinlock;
	atomic_t count;
	struct list_head head;
	struct dmsrc_super *super;
	int initialized;
};

/* Read caching wokrer  */
struct read_miss_manager{
	struct work_struct work;
	struct workqueue_struct *wq;
	mempool_t *job_pool;
	struct read_caching_job_list queue;
	struct dmsrc_super *super;
	int initialized;
};

/* Partial Sync Manager */
struct sync_manager{
	struct hrtimer hr_timer;

	ktime_t period;
	struct work_struct work;
	spinlock_t lock;
	unsigned long target_jiffies;
	struct dmsrc_super *super;
	int initialized;
};

#define REQ_CATEGORY_NORMAL	0
#define REQ_CATEGORY_GC		1
#define REQ_CATEGORY_TOTAL	2
#define REQ_CATEGORY_NUM	3

#define REQ_TYPE_READ	0
#define REQ_TYPE_WRITE	1
#define REQ_TYPE_TOTAL	2
#define REQ_TYPE_NUM	3

struct io_stat_t{
	atomic64_t iops[REQ_CATEGORY_NUM][REQ_TYPE_NUM];
};

#define MAX_WINDOW_NUM (MSEC_PER_SEC*5)

/* I/O Workload Predictor */
struct workload_predictor{
	struct hrtimer hr_timer_track;
	ktime_t track_period;

	struct hrtimer hr_timer_meter;
	ktime_t display_period;

	spinlock_t lock;
	atomic_t start_window;
	atomic_t cur_window;
	u32 num_window;
	u32 window_per_sec;

	struct io_stat_t iostat[MAX_WINDOW_NUM];
	struct dmsrc_super *super;
	int initialized;
};

struct scan_metadata_job{
	struct list_head list;
	struct dmsrc_super *super;
	unsigned long bio_error;
	void *data;
	u32 seg_id;
	u32 ssd_id;

	int index;
};

/* Scan Metadata manager  */
struct scan_metadata_manager{
	spinlock_t lock;
	//struct list_head active_queue;
	struct list_head complete_queue;
	struct list_head inactive_queue;
	atomic_t active_count;
	atomic_t inactive_count;
	atomic_t complete_count;
	int qdepth;
};


#define MAX_BITMAP_TABLE	4

struct hot_data_filter{
	spinlock_t lock;
	unsigned int io_count;;
	unsigned int decay_period;
	unsigned int hot_threshold;
	unsigned int hash_num;
	unsigned int bitmap_table_num;
	unsigned int num_bits_per_table;
	unsigned int num_bytes_per_table;
	unsigned int cur_table;
	unsigned int last_table;
	unsigned long *bitmap[MAX_BITMAP_TABLE];
};

struct device_info{
	unsigned int num_cache_devs;
	unsigned int num_spare_cache_devs; 
	unsigned int num_data_cache_devs;

	char origin_name[128];
	char cache_name[MAX_CACHE_DEVS][128];
	char spare_name[MAX_CACHE_DEVS][128];

	struct dm_dev *origin_dev;
	struct dm_dev *cache_dev[MAX_CACHE_DEVS];
	struct dm_dev *spare_cache_dev[MAX_CACHE_DEVS];

	struct superblock_device sb_device[MAX_CACHE_DEVS];

	u32 per_cache_bw; // per cache (SSD) bandwith (MB)
	sector_t origin_sectors;
	sector_t per_ssd_sectors;
};


struct cache_stat{
	u64	uuid;
	atomic64_t alloc_sequence; // global seq number 

	atomic_t num_free_segments;
	atomic_t num_used_blocks;
	u32 num_blocks_per_chunk; /* Const */ // 4KB unit 
	u32 num_blocks_per_ssd;
	u32 num_segments; /* Const */
	u32 num_groups; /* Const */
	u32 num_chunks_per_ssd; /* Const */
	u32 num_chunks_per_group; /* Const */

	atomic64_t num_dirty_blocks;

	atomic_t inflight_ios;
	atomic_t inflight_bios;

	atomic_t total_ios;
	atomic_t total_bios;
	atomic_t total_bios2;
};

struct dmsrc_param{
	// optional args (Read Only)
	u32 block_size; // sector unit
	u32 chunk_size; // sector unit
	u32 chunk_group_size; // sector unit
	u32 num_summary_per_chunk;
	u32 num_entry_per_page;
	u32 parity_allocation;
	u32 striping_policy;
	u32 data_allocation;
	u32 aligned_io_dummy;
	u32 erasure_code;

	u32 flush_command;

	// tunable args
	u32 rambuf_pool_amount; /* 4KB */
	//unsigned long update_record_interval; /* param */

	/* Sequential I/O detection */
	unsigned		sequential_cutoff;
	unsigned 		sequential_enable;

	u32 victim_policy;
	u32 reclaim_policy;
	u32 u_max;
	u32 gc_with_dirtysync;
	u32 max_migrate_inflights;
	u32 migrate_lowwater;
	u32 migrate_highwater;
	u32 hit_bitmap_type;
	u32 bio_plugging;
	u32 hot_identification;
	u32 enable_read_cache;

	u32 sync_interval; /* us */ /* param */
	u32 checker_interval; /* param */
};

struct dmsrc_super {

	atomic_t degraded_mode;
	atomic_t resize_mode;

	struct dm_target *ti;
	struct dm_io_client *io_client;

	spinlock_t io_lock;

	/* Current Segment Pointer  */
	struct segment_header *current_seg[NBUF];
	/* In-memory Segment Info Header  */
	struct large_array *segment_header_array;

	/* Current Group Pointer  */
	struct group_header *current_group;
	/* In-memory Group Info Header  */
	struct group_header *group_header_array;

	/* In-memory Cached Block (4KB) Info */
	struct large_array *metablock_array[MAX_CACHE_DEVS];
	int meta_initialized;

	/* Chained hashtable */
	struct large_array *htable;
	size_t htsize;
	struct ht_head *null_head;
	int ht_initialized;

	/* Block Allocator */
	struct multi_allocator ma[NBUF];

	struct cache_manager *clean_dram_cache_manager;

	/* Ghost Buffer */
	struct cache_manager *lru_manager;

	/* Hot Data Filter */
	struct hot_data_filter hot_filter;

	/* Device Information */
	struct device_info dev_info;
	
	/* RAID Configration, identical to MD RAID */
	struct r5conf raid_conf;

	/* Paramters */
	struct dmsrc_param param;

	struct cache_stat cache_stat;
	/* Stat Information */
	struct super_stat wstat;

	/* Pending Worker (mapping worker) */
	struct pending_manager pending_mgr;

	/* Sequential I/O Detector */
	struct seq_io_detector seq_detector;

	/* Degraded I/O Manager */
	struct degraded_manager degraded_mgr;

	/* Recovery Manager Structure */
	struct recovery_manager recovery_mgr;

	/* Segment Allocator */
	struct segment_allocator seg_allocator;

	/* Segment RAM Buffer */
	struct segbuf_manager segbuf_mgr;

	/* Flush meta daemon */
	struct flush_manager flush_mgr;

	/* Migration Manager */
	struct migration_manager migrate_mgr;

	/* I/O requests Plugging */
	struct plugging_manager plugger;

	/* Read caching worker */
	struct read_miss_manager read_miss_mgr;

	struct seg_write_manager seg_write_mgr[MAX_CACHE_DEVS];

	/* Partial Segment Manager */
	struct sync_manager sync_mgr;

	/* Checher Daemon for debug */
	struct task_struct *checker_daemon;

	/* Metadata Scanner */
	struct scan_metadata_manager *scan_manager;

	/* Workload Predictor */
	struct workload_predictor wp;

};


/* Spinlock macros */
#define iolock(x, f) spin_lock_irqsave(&x->io_lock, f)
#define iounlock(x, f) spin_unlock_irqrestore(&x->io_lock, f)
#define LOCK(super, x) iolock(super, x)
#define UNLOCK(super, x) iounlock(super, x)

struct copy_job_group{
	struct dmsrc_super *super;
	struct list_head group_list;
	struct list_head cp_head;
	struct segment_header *dst_seg;
	struct rambuffer *dst_rambuf;
	atomic_t cp_job_count;
	int cache_type;
//	int cur_kcopyd;
	int rw;
	int seq;
	int error;
	int gc;
};

struct copy_job{
	struct list_head cp_list;
	struct dm_io_request io_req;
	struct dm_io_region dst_region[2];
	int dst_count;
	struct dm_io_region src_region;
	struct metablock *src_mb;
	struct metablock *dst_mb;
	struct rambuf_page *page;
};



// Per bio context
struct bio_ctx {
	void *ptr;
	int seq_io;
	int hot_io;
	int inflight;
	u32 crc32;
};



/*----------------------------------------------------------------*/

void flush_partial_meta(struct dmsrc_super *, int cache_type);
void inc_num_dirty_caches(struct dmsrc_super *);
void cleanup_mb_if_dirty(struct dmsrc_super *,
			 struct segment_header *,
			 struct metablock *);
u8 atomic_read_mb_dirtiness(struct segment_header *, struct metablock *);
u8 atomic_read_mb_validness(struct segment_header *seg, struct metablock *mb);
void invalidate_previous_cache(struct dmsrc_super *super,
			       struct segment_header *seg,
			       struct metablock *old_mb);

struct metablock *alloc_mb_data(struct dmsrc_super *super, 
		sector_t key,
		int cache_type, 
		bool clean, 
		u32 *total_count);


extern struct workqueue_struct *safe_io_wq;
extern struct dm_io_client *super_io_client;
extern struct dm_kcopyd_client *super_cp_client[];


sector_t dmsrc_devsize_sectors(struct dm_dev *);

struct read_caching_job *alloc_ghost_node(struct dmsrc_super *super);
void update_data_in_mb(struct dmsrc_super *super,
						u32 update_mb_idx,
						struct segment_header *seg,
						struct rambuffer *rambuf,
						int cache_type,
						void *data,
						u32 crc32);

void update_buf_in_mb(struct dmsrc_super *super,
						u32 update_mb_idx,
						struct segment_header *seg,
						void *buf,
						int cache_type,
						bool migrate);

void flush_pending_bios(struct dmsrc_super *super);
void refresh_segment(struct dmsrc_super *super, 
					struct segment_header *seg,
					struct rambuffer *rambuf,
					int cache_type, bool migrate, bool force, int count,
					struct bio_list *);
void update_parity(struct dmsrc_super *super, int cache_type);
bool need_refresh_segment(struct dmsrc_super *super, int cache_type, int count);
void generate_parity_data(struct dmsrc_super *super, struct segment_header *seg, struct rambuf_page **, int full_seg, int cache_type);
void reset_parity(struct dmsrc_super *super, struct segment_header *seg, int cache_type, int clear_written);
void write_async_bio(struct dmsrc_super *super, struct segment_header *seg, u32 idx, struct bio *bio, 
		struct rambuffer *rambuf, int full);

sector_t calc_cache_alignment(struct dmsrc_super *super, sector_t bio_sector);
struct segment_header *get_seg_by_mb(struct dmsrc_super *super, struct metablock *mb);
void pending_bio_add(struct dmsrc_super *super, struct bio *bio);
u64 alloc_new_segment(struct dmsrc_super *super, int cache_type, bool use_migrate);
void wait_rambuf_event(struct dmsrc_super *super, int cache_type);
void wait_alloc_event(struct dmsrc_super *super, int min);
void make_flush_invoke_job(struct dmsrc_super *super, struct segment_header *seg, 
		struct rambuffer *rambuf, int seg_length, atomic_t *bios_start, atomic_t *bios_count, 
		int cache_type, int force_seal, int summary, int flush_data, u64 global_seg_sequence);
int try_get_free_segment(struct dmsrc_super *super, bool found, int rw);
void build_metadata(struct dmsrc_super *super, 
		struct segment_header *seg, 
		int seg_length,
		struct rambuffer *rambuf,
		atomic_t *bios_start,
		atomic_t *bios_count,
		int force_seal,
		int build_summary,
		int flush_data);

int cursor_init(struct dmsrc_super *super, u64 seg_id, int cache_type);
int cursor_parity_start(struct dmsrc_super *super, u64 seg_id, int cache_type);
int cursor_data_start_ssd(struct dmsrc_super *super, u64 seg_id, int cache_type);
int cursor_summary_offset(struct dmsrc_super *super, u64 seg_id, int cache_type);
int get_devno(struct dmsrc_super *super, u32 idx);
struct block_device *get_bdev(struct dmsrc_super *super, u32 idx);
struct dm_dev *get_dmdev(struct dmsrc_super *super, u32 idx);
sector_t get_sector(struct dmsrc_super *super, u32 seg_id, u32 idx);
void do_degraded_worker(struct work_struct *work);
bool need_chunk_summary(struct dmsrc_super *super, u32 idx);
bool chunk_summary_range(struct dmsrc_super *super, u32 idx);
void alloc_mb_summary(struct dmsrc_super *super, struct segment_header *seg, 
		int cache_type, u32 idx, u32 *total_count);
int get_parity_ssd(struct dmsrc_super *super, u64 seg_id);
int get_parityq_ssd(struct dmsrc_super *super, u64 seg_id);
void run_xor(void **pages, void *dest, int src_cnt, ssize_t len);
void _write_async_bio(struct dmsrc_super *super, struct segment_header *seg, u32 idx, struct bio *bio,
		struct rambuffer *rambuf, u32 rambuf_idx);
void _alloc_mb_summary(struct dmsrc_super *super, struct segment_header *seg, int cache_type, u32 idx, int full, int dummy);
void prepare_chunk_summary(
					struct dmsrc_super *super,
					struct segment_header *seg,
					struct rambuf_page **pages,
					int ssd_id,
					 int cache_type);
void cursor_inc(struct dmsrc_super *super,int seg_id, int cache_type);
u32 data_to_summary_idx(struct dmsrc_super *super, u32 idx);
int get_start_ssd(struct dmsrc_super *super, u64 seg_id);
void initialize_mb_summary(struct dmsrc_super *super, struct segment_header *seg,
		int cache_type, u32 idx, int full);
void initialize_mb(struct dmsrc_super *super, struct metablock *new_mb, int cache_type, bool clean);
int dmsrc_io(struct dm_io_request *io_req, unsigned num_regions,
	  struct dm_io_region *where, unsigned long *sync_error_bits);
void raid_conf_init(struct dmsrc_super *super, struct r5conf *conf);
void pending_worker_schedule(struct dmsrc_super *super);
void seg_allocator_init(struct dmsrc_super *super);
int degraded_mgr_init(struct dmsrc_super *super);
void degraded_mgr_deinit(struct dmsrc_super *super);
int recovery_mgr_init(struct dmsrc_super *super);
void recovery_mgr_deinit(struct dmsrc_super *super);
int flush_mgr_init(struct dmsrc_super *super);
void flush_mgr_deinit(struct dmsrc_super *super);
int migrate_mgr_init(struct dmsrc_super *super);
void migrate_mgr_deinit(struct dmsrc_super *super);
int plugger_init(struct dmsrc_super *super);
void plugger_deinit(struct dmsrc_super *super);
int read_miss_mgr_init(struct dmsrc_super *super);
void read_miss_mgr_deinit(struct dmsrc_super *super);
int sync_mgr_init(struct dmsrc_super *super);
void sync_mgr_deinit(struct dmsrc_super *super);
void print_param(struct dmsrc_super *super);
u64 alloc_next_segment(struct dmsrc_super *super, bool migrate);
void init_new_segment(struct dmsrc_super *super, u64 next_id, int cache_type);
void seg_length_inc(struct dmsrc_super *super, struct segment_header *seg, struct metablock *mb, bool inflight);
void dmsrc_dtr(struct dm_target *ti);
void do_background_gc(struct dmsrc_super *super);
void wp_update(struct dmsrc_super *super, int is_write, int category);
u32 wp_get_iops(struct dmsrc_super *super, u32 *bw_mb, int category, int type);
int calc_need_num_ssds(struct dmsrc_super *super);
void _build_summary_job(struct dmsrc_super *super, struct segment_header *seg, 
		struct rambuffer *rambuf, int full);
int process_write_request(struct dmsrc_super *super, 
								struct bio *bio,
								struct page *page,
								sector_t key,
								int is_dirty,
								unsigned long f, 
								int cache_type, 
								u32 crc32);
bool should_need_refresh_seg(struct dmsrc_super *super, int cache_type);
int can_get_free_segment(struct dmsrc_super *super, int cache_type, int gc);
struct wb_job *writeback_make_job(struct dmsrc_super *super, 
		struct segment_header *seg, 
		u32 idx, 
		struct bio *bio, 
		struct rambuffer *rambuf, 
		int rambuf_release);
void writeback_issue_job(struct dmsrc_super *super, struct wb_job *job);
u32 get_summary_offset(struct dmsrc_super *super, u32 ssd_id);
void bio_plugging(struct dmsrc_super *super, struct segment_header *seg, struct rambuffer *rambuf, 
				struct bio *bio, u32 update_mb_idx);
inline int get_parity_ssd(struct dmsrc_super *super, u64 seg_id);

int try_wait_free_seg(struct dmsrc_super *super, int is_write);
struct wb_job *writeback_make_job_extent(struct dmsrc_super *super, 
		struct segment_header *seg, 
		struct rambuffer *rambuf, 
		u32 start_idx, 
		u32 count);
void writeback_issue_job_extent(struct dmsrc_super *super, struct wb_job *job, int group_sealed);
int need_clean_seg_write(struct dmsrc_super *super);
int clean_seg_write(struct dmsrc_super *super, int need_count, int cache_type);
u32 alloc_next_mb(struct dmsrc_super *super, struct segment_header *seg, sector_t key, int cache_type, u32 *total_count);
void hot_filter_update(struct dmsrc_super *super, unsigned int sector);
int hot_filter_check(struct dmsrc_super *super, unsigned int sector);
void update_sync_deadline(struct dmsrc_super *super);

/*----------------------------------------------------------------*/
/*
 * Nice printk macros
 *
 * Production code should not include lineno
 * but name of the caller is OK.
 */

#define wbdebug(f, args...) \
	DMINFO("debug@%s() L.%d" f, __func__, __LINE__, ## args)

#define WBERR(f, args...) \
	DMERR("err@%s() " f, __func__, ## args)
#define WBWARN(f, args...) \
	DMWARN("warn@%s() " f, __func__, ## args)
#define WBINFO(f, args...) \
	DMINFO("info@%s() " f, __func__, ## args)

/* Device Blockup */



#endif
