/****************************************************************************
 * SRC (SSD RAID Cache): Device mapper target for block-level disk caching
 * Yongseok Oh (ysoh@uos.ac.kr) 2013 - 2014
 * filename: metadata.h
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

#ifndef DM_SRC_METADATA_H
#define DM_SRC_METADATA_H

#define VMALLOC
//#define KMALLOC

struct part {
	void *memory;
};

struct large_array {
	struct part *parts;
	u64 num_elems;
	u32 elemsize;
};
#define ALLOC_SIZE (1 << 16)


/*----------------------------------------------------------------*/

struct metablock *mb_at(struct dmsrc_super *super, u32 idx);
struct segment_header *get_segment_header_by_id(struct dmsrc_super *,
						u64 segment_id);
struct segment_header *get_segment_header_by_mb_idx(struct dmsrc_super *super,
							   u32 mb_idx);
sector_t calc_mb_start_sector(struct dmsrc_super *,
			      struct segment_header *, u32 mb_idx);
bool is_on_buffer(struct dmsrc_super *, u32 mb_idx);

u32 get_curr_util(struct dmsrc_super *);

/*----------------------------------------------------------------*/

struct ht_head *ht_get_head(struct dmsrc_super *, sector_t);
struct metablock *ht_lookup(struct dmsrc_super *, sector_t);
void ht_register(struct dmsrc_super *, sector_t, struct metablock *);
void ht_del(struct dmsrc_super *, struct metablock *);
void discard_caches_inseg(struct dmsrc_super *, struct segment_header *);

/*----------------------------------------------------------------*/

int __must_check scan_superblock(struct dmsrc_super *);
int __must_check format_cache_device(struct dmsrc_super *);

/*----------------------------------------------------------------*/

void prepare_segment_header_device(struct segment_header_device *dest,
				   struct dmsrc_super *,
				   struct segment_header *src, int cache_type, struct rambuf_page **rambuf);

u8 calc_checksum(u8 *ptr, int size);
/*----------------------------------------------------------------*/

int alloc_migration_buffer(struct dmsrc_super *, size_t num_batch);
void free_migration_buffer(struct dmsrc_super *);

/*----------------------------------------------------------------*/

int __must_check resume_cache(struct dmsrc_super *);
void free_cache(struct dmsrc_super *);

/*----------------------------------------------------------------*/

void insert_seg_to_alloc_queue(struct dmsrc_super *super, struct segment_header *seg);
void insert_seg_to_used_queue(struct dmsrc_super *super, struct segment_header *seg);
void move_seg_used_to_sealed_queue(struct dmsrc_super *super, struct segment_header *seg);
void move_seg_sealed_to_migrate_queue(struct dmsrc_super *super, struct segment_header *seg, int lock);
void move_seg_migrate_to_alloc_queue(struct dmsrc_super *super, struct segment_header *seg);
struct segment_header *remove_alloc_queue(struct dmsrc_super *super, struct segment_header *seg);
int empty_sealed_queue(struct dmsrc_super *super);
int empty_alloc_queue(struct dmsrc_super *super);
int get_alloc_count(struct dmsrc_super *super);
void print_alloc_queue(struct dmsrc_super *super);
void move_seg_mru_sealed(struct dmsrc_super *super, struct segment_header *seg);
void release_reserve_segs(struct dmsrc_super *super);
int reserve_reserve_segs(struct dmsrc_super *super, int need_segs);
struct segment_header *remove_reserve_queue(struct dmsrc_super *super);
struct rambuffer *alloc_rambuffer(struct dmsrc_super *super, int cache_type, int stripe_size);
void alloc_rambuf_page(struct dmsrc_super *super, struct rambuffer *rambuf, int cache_type);
void release_rambuffer(struct dmsrc_super *super, struct rambuffer *, int cache_type);
int seg_stat(struct segment_header *seg);
struct metablock *get_mb(struct dmsrc_super *super, u32 seg_id, u32 idx);
struct large_array *large_array_alloc(u32 elemsize, u64 num_elems);
struct rambuf_page *_alloc_rambuf_page(struct dmsrc_super *super);
struct rambuf_page *_free_rambuf_page(struct dmsrc_super *super, struct rambuf_page *page);
void free_single_page(struct dmsrc_super *super, struct rambuf_page *page);
struct rambuf_page *alloc_single_page(struct dmsrc_super *super);

void *large_array_at(struct large_array *arr, u32 i);
void large_array_free(struct large_array *arr);
struct large_array *large_array_alloc(u32 elemsize, u64 num_elems);
int create_daemon(struct dmsrc_super *super, struct task_struct **taskp, int (*threadfn)(void *data), char *name);
u32 calc_num_chunks(struct dm_dev *dev, struct dmsrc_super *super);
int __must_check scan_metadata(struct dmsrc_super *super);
int __must_check resume_managers(struct dmsrc_super *super);
int __must_check init_rambuf_pool(struct dmsrc_super *super);
int __must_check init_segment_header_array(struct dmsrc_super *super);
int __must_check ht_empty_init(struct dmsrc_super *super);
void free_ht(struct dmsrc_super *super);
void free_segment_header_array(struct dmsrc_super *super);
void free_rambuf_pool(struct dmsrc_super *super);
int check_dirty_count(struct dmsrc_super *super, struct segment_header *cur_seg);
int check_valid_count(struct dmsrc_super *super, struct segment_header *cur_seg);
void move_seg_migrate_to_sealed_queue(struct dmsrc_super *super, struct segment_header *seg);
int check_rambuf_pool(struct dmsrc_super *super);

u32 segment_group_inc_free_segs(struct dmsrc_super *super, struct segment_header *seg);
void segment_group_dec_free_segs(struct dmsrc_super *super, struct segment_header *seg);
void segment_group_print_stat(struct dmsrc_super *super);
struct group_header *remove_alloc_group_queue(struct dmsrc_super *super);
void insert_group_to_used_queue(struct dmsrc_super *super, struct group_header *group);
void move_group_used_to_sealed_queue(struct dmsrc_super *super, struct group_header *group);
void move_group_sealed_to_migrate_queue(struct dmsrc_super *super, struct group_header *group, int lock);
void move_group_migrate_to_alloc_queue(struct dmsrc_super *super, struct group_header *group);
int get_group_alloc_count(struct dmsrc_super *super);
int assign_new_segment(struct dmsrc_super *super);


#endif
