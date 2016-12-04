/****************************************************************************
 * SRC (SSD RAID Cache): Device mapper target for block-level disk caching
 * Yongseok Oh (ysoh@uos.ac.kr) 2013 - 2014
 * filename: metadata.c 
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

#include <linux/vmalloc.h>
#include <linux/crc32.h>
#include "target.h"
#include "metadata.h"
#include "daemon.h"
#include "alloc.h"
#include "header.h"
#include <linux/list.h>
#include <linux/log2.h>
#include <linux/random.h>

u32 get_curr_util(struct dmsrc_super *super){
	u32 util=0;

	if(atomic_read(&super->cache_stat.num_used_blocks)){
		util = (u32)((u64)atomic_read(&super->cache_stat.num_used_blocks)*100/NUM_BLOCKS);

		if(util>=100)
			util = 0;
	}

	return util;
}

#ifdef KMALLOC
static u32 num_elems_in_part(struct large_array *arr)
{
	return div_u64(ALLOC_SIZE, arr->elemsize);
}


static u64 num_parts(struct large_array *arr)
{
	u64 a = arr->num_elems;
	u32 b = num_elems_in_part(arr);
	return div_u64(a + b - 1, b);
}
#endif 

struct large_array *large_array_alloc(u32 elemsize, u64 num_elems)
{
	struct part *part;
	u64 alloc_size = 0;

#ifdef VMALLOC
	struct large_array *arr = kmalloc(sizeof(*arr), GFP_KERNEL);
	if (!arr) {
		WBERR("failed to alloc arr");
		return NULL;
	}

	arr->elemsize = elemsize;
	arr->num_elems = num_elems;
	arr->parts = kmalloc(sizeof(struct part), GFP_KERNEL);
	if (!arr->parts) {
		WBERR("failed to alloc parts");
		goto bad_alloc_parts;
	}
	part = arr->parts + 0;
	part->memory = vmalloc(elemsize * num_elems);
	if (!part->memory) {
		WBERR("failed to alloc part memory");
		vfree(part->memory);
		goto bad_alloc_parts_memory;
	}

	alloc_size = elemsize * num_elems;
	printk(" Metadata Allocation: %lluMB (%llu)\n", alloc_size/1024/1024, alloc_size);
#else
	u64 i, j;
	struct large_array *arr = kmalloc(sizeof(*arr), GFP_KERNEL);
	if (!arr) {
		WBERR("failed to alloc arr");
		return NULL;
	}

	arr->elemsize = elemsize;
	arr->num_elems = num_elems;
	arr->parts = kmalloc(sizeof(struct part) * num_parts(arr), GFP_KERNEL);
	if (!arr->parts) {
		WBERR("failed to alloc parts");
		goto bad_alloc_parts;
	}

	for (i = 0; i < num_parts(arr); i++) {
		part = arr->parts + i;
		part->memory = kmalloc(ALLOC_SIZE, GFP_KERNEL);
		//part->memory = vmalloc(ALLOC_SIZE);
		alloc_size += ALLOC_SIZE;
		if (!part->memory) {
			WBERR("failed to alloc part memory");
			for (j = 0; j < i; j++) {
				part = arr->parts + j;
				kfree(part->memory);
			}
			goto bad_alloc_parts_memory;
		}
	}
	printk(" Metadata Allocation: %lluMB (%llu)\n", alloc_size/1024/1024, alloc_size);
#endif 

	return arr;

bad_alloc_parts_memory:
	kfree(arr->parts);
bad_alloc_parts:
	kfree(arr);

	return NULL;
}

void large_array_free(struct large_array *arr)
{

#ifdef VMALLOC
	struct part *part = arr->parts + 0;
	vfree(part->memory);
#else
	size_t i;
	for (i = 0; i < num_parts(arr); i++) {
		struct part *part = arr->parts + i;
		//vfree(part->memory);
		kfree(part->memory);
	}
	kfree(arr->parts);
	kfree(arr);
#endif
}
#ifdef KMALLOC
void *large_array_at(struct large_array *arr, u64 i)
{
	u32 n = num_elems_in_part(arr);
	u32 k;
	u64 j = div_u64_rem(i, n, &k);
	struct part *part = arr->parts + j;
	return part->memory + (arr->elemsize * k);
}
#else
void *large_array_at(struct large_array *arr, u32 i)
{
	struct part *part = arr->parts + 0;
	BUG_ON(i>=arr->num_elems);
	return part->memory + (arr->elemsize * i);
}
#endif 

/*----------------------------------------------------------------*/

/*
 * Get the in-core metablock of the given index.
 */
struct metablock *mb_at(struct dmsrc_super *super, u32 idx)
{
	struct metablock *mb;
	u32 devno = (idx / CHUNK_SZ) % NUM_SSD;
	u32 offset = idx / STRIPE_SZ * CHUNK_SZ + (idx % CHUNK_SZ);

	if(offset>=NUM_BLOCKS_PER_SSD){
		printk(" idx = %u\n", idx);
		printk(" devno = %u, offset = %u \n", devno, offset);
		printk(" num blocks per ssd = %u \n", NUM_BLOCKS_PER_SSD);
		printk(" num blocks = %u \n", NUM_BLOCKS);
		BUG_ON(1);
	}//else{
	//}
	mb = (struct metablock *)large_array_at(super->metablock_array[devno], offset);

	return mb;
}

inline struct metablock *get_mb(struct dmsrc_super *super, u32 seg_id, u32 idx){
	return mb_at(super, seg_id * STRIPE_SZ + idx);
}

static void mb_array_empty_init(struct dmsrc_super *super)
{
	u32 i;
	for (i = 0; i < NUM_BLOCKS; i++) {
		struct metablock *mb = mb_at(super, i);

		INIT_HLIST_NODE(&mb->ht_list);

		mb->idx = i;
		mb->sector = ~0;
		mb->mb_flags = 0;

#if 0
		clear_bit(MB_DIRTY, &mb->mb_flags);
		clear_bit(MB_VALID, &mb->mb_flags);
		clear_bit(MB_SEAL, &mb->mb_flags);
		clear_bit(MB_META, &mb->mb_flags);
		clear_bit(MB_SUMMARY, &mb->mb_flags);
		clear_bit(MB_BROKEN, &mb->mb_flags);
		clear_bit(MB_PARITY_NEED, &mb->mb_flags);
		clear_bit(MB_PARITY_WRITTEN, &mb->mb_flags);
#endif
	}
}

int check_dirty_count(struct dmsrc_super *super, struct segment_header *cur_seg){
	int i;
	int dirty_count = 0;

	for (i = 0; i < STRIPE_SZ; i++) {
		struct metablock *mb = get_mb(super, cur_seg->seg_id, i);
		if(test_bit(MB_DIRTY, &mb->mb_flags)|| 
				test_bit(MB_PARITY, &mb->mb_flags)||
				test_bit(MB_SUMMARY, &mb->mb_flags)){
			dirty_count++;
		}
	}

	if(is_write_stripe(cur_seg->seg_type)){
		dirty_count += NUM_SUMMARY*NUM_DATA_SSD;
		if(USE_ERASURE_PARITY(&super->param))
			dirty_count += CHUNK_SZ; 
	}else{
		dirty_count += (NUM_SUMMARY*NUM_SSD);
	}

	return dirty_count;
}

int check_valid_count(struct dmsrc_super *super, struct segment_header *cur_seg){
	int i;
	int valid_count = 0;

	for (i = 0; i < STRIPE_SZ; i++) {
		struct metablock *mb = get_mb(super, cur_seg->seg_id, i);
		if(test_bit(MB_VALID, &mb->mb_flags)|| 
				test_bit(MB_PARITY, &mb->mb_flags)||
				test_bit(MB_SUMMARY, &mb->mb_flags)){
			valid_count++;

#if 0
			if(is_write_stripe(cur_seg->seg_type)){
				if(test_bit(MB_DIRTY, &mb->mb_flags) != test_bit(MB_VALID, &mb->mb_flags)){
					printk(" seg id = %d  offset = %d Invalid mb dirty mb valid = %d %d \n",
							(int)cur_seg->seg_id,
							i,
							(int)test_bit(MB_VALID, &mb->mb_flags),
							(int)test_bit(MB_DIRTY, &mb->mb_flags));
				}
			}
#endif
		}
	}

	if(is_write_stripe(cur_seg->seg_type)){
		valid_count += NUM_SUMMARY*NUM_DATA_SSD;
		if(USE_ERASURE_PARITY(&super->param))
			valid_count += CHUNK_SZ; 
	}else{
		valid_count += (NUM_SUMMARY*NUM_SSD);
	}

	return valid_count;
}

static void mb_array_sanity_check(struct dmsrc_super *super)
{
	u32 i;
	u32 seg_id;
	struct segment_header *cur_seg;

	for (seg_id = 0; seg_id < super->cache_stat.num_segments; seg_id++) {
		int valid_count = 0;
		int dirty_count = 0;
		cur_seg = get_segment_header_by_id(super, seg_id);

		if(test_bit(SEG_CLEAN, &cur_seg->flags))
			continue;

		valid_count = check_valid_count(super, cur_seg);
		dirty_count = check_dirty_count(super, cur_seg);

		// There exist invalidated dirty blocks
		//if(is_write_stripe(cur_seg->seg_type) && valid_count != dirty_count)
		//	printk(" Invalid seg id = %d, valid = %d %d dirty = %d\n", seg_id, valid_count, 
		//			(int)atomic_read(&cur_seg->valid_count), dirty_count);
		

		//if(seg_id < 10){
			if(valid_count!=atomic_read(&cur_seg->valid_count)){
				printk(" Invalid seg id = %d, valid = %d %d \n", seg_id, valid_count, 
						(int)atomic_read(&cur_seg->valid_count));
			}
			if(dirty_count!=atomic_read(&cur_seg->dirty_count)){
				printk(" Invalid seg id = %d, dirty = %d %d \n", seg_id, dirty_count, 
						(int)atomic_read(&cur_seg->dirty_count));
			}
		//}
	}

	for (i = 0; i < NUM_BLOCKS; i++) {
		struct metablock *mb = mb_at(super, i);

		if(mb->sector== ~0 && (test_bit(MB_DIRTY, &mb->mb_flags) || 
				test_bit(MB_VALID, &mb->mb_flags)))
		{
			printk(" %d: sector = %d, dirty = %d, valid = %d \n", 
					i, (int)mb->sector, test_bit(MB_DIRTY, &mb->mb_flags),
				test_bit(MB_VALID, &mb->mb_flags));
		}
	}
}

int seg_stat(struct segment_header *seg){
	int res = 0;
	int count = 0;

	if(test_bit(SEG_CLEAN, &seg->flags)){
		res += SEG_CLEAN;
		count++;
	}
	
	if(test_bit(SEG_USED, &seg->flags)){
		res += SEG_USED;
		count++;
	}
	if(test_bit(SEG_SEALED, &seg->flags)){
		res += SEG_SEALED;
		count++;
	}
	
	if(test_bit(SEG_MIGRATING, &seg->flags)){
		res += SEG_MIGRATING;
		count++;
	}
	if(test_bit(SEG_PARTIAL, &seg->flags)){
		res += SEG_PARTIAL;
		count++;
	}
	if(test_bit(SEG_RECOVERY, &seg->flags)){
		res += SEG_RECOVERY;
		count++;
	}
	if(test_bit(SEG_HIT, &seg->flags)){
		res += SEG_HIT;
		count++;
	}

	if(count == 1){
		return res;
	}else{
		printk(" stat = %d count = %d \n", res, count);
		return -1;
	}
}

void print_alloc_queue(struct dmsrc_super *super){
	unsigned long flags;
	struct segment_header *seg;
	struct segment_allocator *seg_allocator = &super->seg_allocator;

	spin_lock_irqsave(&seg_allocator->alloc_lock, flags);
	printk(" seg: alloc = %d, used = %d, sealed = %d, migrate = %d\n", 
			(int)atomic_read(&seg_allocator->seg_alloc_count), (int)seg_allocator->seg_used_count, 
			(int)seg_allocator->seg_sealed_count,
			(int)atomic_read(&seg_allocator->seg_migrate_count));


#if 1 
	list_for_each_entry(seg, &seg_allocator->seg_used_queue, alloc_list){
		printk(" alloc_queue: seg id = %d inuse = %d length = %d type = %d, bufcopy = %d, bios = %d \n", (int)seg->seg_id, 
				seg_stat(seg), (int)atomic_read(&seg->length), (int)seg->seg_type,
				(int)atomic_read(&seg->num_bufcopy), (int)atomic_read(&seg->bios_count));
	}

	printk(" group: alloc = %d, used = %d, sealed = %d, migrate = %d\n", 
			(int)atomic_read(&seg_allocator->group_alloc_count), (int)seg_allocator->group_used_count, 
			(int)seg_allocator->group_sealed_count,
			(int)atomic_read(&seg_allocator->group_migrate_count));

	printk("\n");

#if 0
	{
		int count = 0;
		list_for_each_entry(seg, &seg_allocator->migrate_queue, alloc_list){
			printk(" migrate_queue: seg id = %d inuse = %d length = %d valid = %d type = %d, bufcopy = %d \n", (int)seg->seg_id, 
					seg_stat(seg), (int)atomic_read(&seg->length), 
					(int)atomic_read(&seg->valid_count),
					(int)seg->seg_type,
					(int)atomic_read(&seg->num_bufcopy));
			count++;
			if(count>100)
				break;
		}
	}
#endif
	printk("\n");
#endif 

	spin_unlock_irqrestore(&seg_allocator->alloc_lock, flags);
}

void insert_group_to_alloc_queue(struct dmsrc_super *super, struct group_header *group){
	unsigned long flags;
	struct segment_allocator *seg_allocator = &super->seg_allocator;
	struct list_head *queue = &seg_allocator->group_alloc_queue;

	spin_lock_irqsave(&seg_allocator->alloc_lock, flags);
	list_add(&group->alloc_list, queue);
	atomic_inc(&seg_allocator->group_alloc_count);
	spin_unlock_irqrestore(&seg_allocator->alloc_lock, flags);

	//if(atomic_read(&seg_allocator->seg_alloc_count)>=MIGRATE_LOWWATER)
	//	wake_up_interruptible(&seg_allocator->alloc_wait_queue);
}

void insert_seg_to_alloc_queue(struct dmsrc_super *super, struct segment_header *seg){
	unsigned long flags;
	struct segment_allocator *seg_allocator = &super->seg_allocator;
	struct list_head *queue = &seg_allocator->seg_alloc_queue;

	spin_lock_irqsave(&seg_allocator->alloc_lock, flags);
	list_add(&seg->alloc_list, queue);
	atomic_inc(&seg_allocator->seg_alloc_count);
	spin_unlock_irqrestore(&seg_allocator->alloc_lock, flags);

	if(atomic_read(&seg_allocator->seg_alloc_count)>=MIGRATE_LOWWATER)
		wake_up_interruptible(&seg_allocator->alloc_wait_queue);
}

int empty_alloc_queue(struct dmsrc_super *super){
	unsigned long flags;
	struct segment_allocator *seg_allocator = &super->seg_allocator;
	struct list_head *queue = &seg_allocator->seg_alloc_queue;
	int empty;

	spin_lock_irqsave(&seg_allocator->alloc_lock, flags);
	empty = list_empty(queue);
	spin_unlock_irqrestore(&seg_allocator->alloc_lock, flags);
	return empty;
}

#if 0 
void release_reserve_segs(struct dmsrc_super *super){
	unsigned long flags;
	struct segment_allocator *seg_allocator = &super->seg_allocator;
	struct list_head *alloc_queue = &seg_allocator->alloc_queue;
	struct list_head *reserve_queue = &seg_allocator->reserve_queue;
	struct segment_header *seg, *temp;
	int count = 0;

	if(!atomic_read(&seg_allocator->reserve_count))
		return;

	spin_lock_irqsave(&seg_allocator->alloc_lock, flags);

	list_for_each_entry_safe(seg, temp, reserve_queue, alloc_list){
		list_del(&seg->alloc_list);
		atomic_dec(&seg_allocator->reserve_count);

		list_add(&seg->alloc_list, alloc_queue);
		atomic_inc(&seg_allocator->alloc_count);
		count = 0;
	}

//	printk(" Realese: alloc count = %d, reserve count = %d \n", 
//			atomic_read(&super->alloc_count), 
//			atomic_read(&super->reserve_count));

	spin_unlock_irqrestore(&seg_allocator->alloc_lock, flags);

	if(atomic_read(&seg_allocator->alloc_count)>=MIGRATE_LOWWATER)
		wake_up_interruptible(&seg_allocator->alloc_wait_queue);
}

int reserve_reserve_segs(struct dmsrc_super *super, int need_segs){
	unsigned long flags;
	struct segment_allocator *seg_allocator = &super->seg_allocator;
	struct list_head *alloc_queue = &seg_allocator->alloc_queue;
	struct list_head *reserve_queue = &seg_allocator->reserve_queue;
	struct list_head *ptr; 
	struct segment_header *seg;
	int res = 1;
	int i;

	spin_lock_irqsave(&seg_allocator->alloc_lock, flags);

//	printk(" Alloc: alloc count = %d, migrate count = %d \n", 
//			atomic_read(&super->alloc_count), 
//			atomic_read(&super->reserve_count));

	if(atomic_read(&seg_allocator->alloc_count) < need_segs){
		res = 0;
		goto finish;
	}


#if 1 
	for(i = 0;i < need_segs;i++){
		ptr = alloc_queue->prev;
		seg	 = (struct segment_header *)
			list_entry(ptr, struct segment_header, alloc_list);
		list_del(&seg->alloc_list);
		atomic_dec(&seg_allocator->alloc_count);

		list_add(&seg->alloc_list, reserve_queue);
		atomic_inc(&seg_allocator->reserve_count);
	}
#endif 


finish:;
	spin_unlock_irqrestore(&seg_allocator->alloc_lock, flags);
	return res;
}
#endif

#if 0
struct segment_header *remove_reserve_queue(struct dmsrc_super *super){
	unsigned long flags;
	struct segment_allocator *seg_allocator = &super->seg_allocator;
	struct list_head *queue = &seg_allocator->reserve_queue;
	struct list_head *ptr; 
	struct segment_header *seg;

	spin_lock_irqsave(&seg_allocator->alloc_lock, flags);
	ptr = queue->prev;
	if(!list_empty(queue)){
		seg	 = (struct segment_header *)
			list_entry(ptr, struct segment_header, alloc_list);
		list_del(&seg->alloc_list);
		atomic_dec(&seg_allocator->reserve_count);
		//printk(" migrate count = %d \n", atomic_read(&super->reserve_count));
	}else{
		BUG_ON(1);
		seg = NULL;
	}
	spin_unlock_irqrestore(&seg_allocator->alloc_lock, flags);
	return seg;
}
#endif

struct group_header *remove_alloc_group_queue(struct dmsrc_super *super){
	unsigned long flags;
	struct segment_allocator *seg_allocator = &super->seg_allocator;
	struct list_head *queue = &seg_allocator->group_alloc_queue;
	struct list_head *ptr; 
	struct group_header *group;

	spin_lock_irqsave(&seg_allocator->alloc_lock, flags);
	ptr = queue->prev;
	if(!list_empty(queue)){
		group = (struct group_header *)
			list_entry(ptr, struct group_header, alloc_list);
		list_del(&group->alloc_list);
		atomic_dec(&seg_allocator->group_alloc_count);
	}else{
		group = NULL;
	}
	spin_unlock_irqrestore(&seg_allocator->alloc_lock, flags);
	return group;
}

struct segment_header *remove_alloc_queue(struct dmsrc_super *super, struct segment_header *seg){
	unsigned long flags;
	struct segment_allocator *seg_allocator = &super->seg_allocator;
	struct list_head *queue = &seg_allocator->seg_alloc_queue;
	struct list_head *ptr; 
	//struct segment_header *seg;

	BUG_ON(seg==NULL);
	spin_lock_irqsave(&seg_allocator->alloc_lock, flags);
	ptr = queue->prev;
	if(!list_empty(queue)){
		//seg	 = (struct segment_header *)
		//	list_entry(ptr, struct segment_header, alloc_list);
		list_del(&seg->alloc_list);
		atomic_dec(&seg_allocator->seg_alloc_count);
	}else{
		seg = NULL;
	}
	spin_unlock_irqrestore(&seg_allocator->alloc_lock, flags);
	return seg;
}

void insert_group_to_used_queue(struct dmsrc_super *super, struct group_header *group){
	unsigned long flags;
	struct segment_allocator *seg_allocator = &super->seg_allocator;
	struct list_head *queue = &seg_allocator->group_used_queue;

	spin_lock_irqsave(&seg_allocator->alloc_lock, flags);
	list_add(&group->alloc_list, queue);
	seg_allocator->group_used_count++;
	spin_unlock_irqrestore(&seg_allocator->alloc_lock, flags);
}

void insert_seg_to_used_queue(struct dmsrc_super *super, struct segment_header *seg){
	unsigned long flags;
	struct segment_allocator *seg_allocator = &super->seg_allocator;
	struct list_head *queue = &seg_allocator->seg_used_queue;

	spin_lock_irqsave(&seg_allocator->alloc_lock, flags);
	list_add(&seg->alloc_list, queue);
	seg_allocator->seg_used_count++;
	spin_unlock_irqrestore(&seg_allocator->alloc_lock, flags);
}

int empty_sealed_queue(struct dmsrc_super *super){
	unsigned long flags;
	struct segment_allocator *seg_allocator = &super->seg_allocator;
	struct list_head *queue = &seg_allocator->seg_sealed_queue;
	int empty;

	spin_lock_irqsave(&seg_allocator->alloc_lock, flags);
	empty = list_empty(queue);
	spin_unlock_irqrestore(&seg_allocator->alloc_lock, flags);
	return empty;
}

int get_group_alloc_count(struct dmsrc_super *super){
	struct segment_allocator *seg_allocator = &super->seg_allocator;
	unsigned long flags;
	int count;

	spin_lock_irqsave(&seg_allocator->alloc_lock, flags);
	count = atomic_read(&seg_allocator->group_alloc_count);
	spin_unlock_irqrestore(&seg_allocator->alloc_lock, flags);
	return count;
}

int get_alloc_count(struct dmsrc_super *super){
	struct segment_allocator *seg_allocator = &super->seg_allocator;
	unsigned long flags;
	int count;

	spin_lock_irqsave(&seg_allocator->alloc_lock, flags);
	count = atomic_read(&seg_allocator->seg_alloc_count);
	spin_unlock_irqrestore(&seg_allocator->alloc_lock, flags);
	return count;
}


void move_group_used_to_sealed_queue(struct dmsrc_super *super, struct group_header *group){
	unsigned long flags;
	struct segment_allocator *seg_allocator = &super->seg_allocator;
	struct list_head *queue = &seg_allocator->group_sealed_queue;

	spin_lock_irqsave(&seg_allocator->alloc_lock, flags);
	list_del(&group->alloc_list);
	list_add_tail(&group->alloc_list, queue);
	BUG_ON(seg_allocator->group_used_count==0);
	seg_allocator->group_used_count--;
	seg_allocator->group_sealed_count++;
	spin_unlock_irqrestore(&seg_allocator->alloc_lock, flags);
}

void move_seg_used_to_sealed_queue(struct dmsrc_super *super, struct segment_header *seg){
	unsigned long flags;
	struct segment_allocator *seg_allocator = &super->seg_allocator;
	struct list_head *queue = &seg_allocator->seg_sealed_queue;

	spin_lock_irqsave(&seg_allocator->alloc_lock, flags);
	list_del(&seg->alloc_list);
	list_add(&seg->alloc_list, queue);
	BUG_ON(seg_allocator->seg_used_count==0);
	seg_allocator->seg_used_count--;
	seg_allocator->seg_sealed_count++;
	spin_unlock_irqrestore(&seg_allocator->alloc_lock, flags);
}

void move_seg_mru_sealed(struct dmsrc_super *super, struct segment_header *seg){
	unsigned long flags;
	struct segment_allocator *seg_allocator = &super->seg_allocator;
	struct list_head *queue = &seg_allocator->seg_sealed_queue;

	spin_lock_irqsave(&seg_allocator->alloc_lock, flags);
	list_del(&seg->alloc_list);
	list_add(&seg->alloc_list, queue);
	spin_unlock_irqrestore(&seg_allocator->alloc_lock, flags);
}

void move_group_sealed_to_migrate_queue(struct dmsrc_super *super, struct group_header *group, int lock){
	unsigned long flags;
	struct segment_allocator *seg_allocator = &super->seg_allocator;
	struct list_head *queue = &seg_allocator->group_migrate_queue;

	if(lock)
		spin_lock_irqsave(&seg_allocator->alloc_lock, flags);

	list_del(&group->alloc_list);
	list_add(&group->alloc_list, queue);
	seg_allocator->group_sealed_count--;
	atomic_inc(&seg_allocator->group_migrate_count);

	if(lock)
		spin_unlock_irqrestore(&seg_allocator->alloc_lock, flags);
}


void move_seg_sealed_to_migrate_queue(struct dmsrc_super *super, struct segment_header *seg, int lock){
	unsigned long flags;
	struct segment_allocator *seg_allocator = &super->seg_allocator;
	struct list_head *queue = &seg_allocator->seg_migrate_queue;

	if(lock)
		spin_lock_irqsave(&seg_allocator->alloc_lock, flags);

	list_del(&seg->alloc_list);
	list_add(&seg->alloc_list, queue);
	seg_allocator->seg_sealed_count--;
	atomic_inc(&seg_allocator->seg_migrate_count);

	if(lock)
		spin_unlock_irqrestore(&seg_allocator->alloc_lock, flags);
}

void move_seg_migrate_to_sealed_queue(struct dmsrc_super *super, struct segment_header *seg){
	unsigned long flags;
	struct segment_allocator *seg_allocator = &super->seg_allocator;
	struct list_head *queue = &seg_allocator->seg_sealed_queue;

	spin_lock_irqsave(&seg_allocator->alloc_lock, flags);
	list_del(&seg->alloc_list);
	list_add(&seg->alloc_list, queue);
	atomic_dec(&seg_allocator->seg_migrate_count);
	seg_allocator->seg_sealed_count--;
	spin_unlock_irqrestore(&seg_allocator->alloc_lock, flags);
}

void move_group_migrate_to_alloc_queue(struct dmsrc_super *super, struct group_header *group){
	unsigned long flags;
	struct segment_allocator *seg_allocator = &super->seg_allocator;
	struct list_head *queue = &seg_allocator->group_alloc_queue;

	spin_lock_irqsave(&seg_allocator->alloc_lock, flags);
	list_del(&group->alloc_list);
	list_add(&group->alloc_list, queue);
	atomic_dec(&seg_allocator->group_migrate_count);
	atomic_inc(&seg_allocator->group_alloc_count);
	spin_unlock_irqrestore(&seg_allocator->alloc_lock, flags);
}

void move_seg_migrate_to_alloc_queue(struct dmsrc_super *super, struct segment_header *seg){
	unsigned long flags;
	struct segment_allocator *seg_allocator = &super->seg_allocator;
	struct list_head *queue = &seg_allocator->seg_alloc_queue;

	spin_lock_irqsave(&seg_allocator->alloc_lock, flags);
	list_del(&seg->alloc_list);
	list_add(&seg->alloc_list, queue);
	atomic_dec(&seg_allocator->seg_migrate_count);
	atomic_inc(&seg_allocator->seg_alloc_count);
	spin_unlock_irqrestore(&seg_allocator->alloc_lock, flags);
}

static sector_t calc_segment_header_start(struct dmsrc_super *super,
					  u32 segment_idx)
{
	return (super->param.chunk_size) * NUM_SSD * (segment_idx);
}

#if 0 
static u32 calc_segment_lap(struct dmsrc_super *super, u64 segment_id)
{
	u64 a = div_u64(segment_id - 1, super->nr_segments);
	return a + 1;
};
#endif 

u32 calc_num_chunks(struct dm_dev *dev, struct dmsrc_super *super)
{
	sector_t devsize = dmsrc_devsize_sectors(dev);
	return div_u64(devsize, super->param.chunk_size) - 1; // the last chunk is reserved for super block
}

sector_t calc_mb_start_sector(struct dmsrc_super *super,
			      struct segment_header *seg,
			      u32 mb_idx)
{
	u32 idx;
	sector_t start_sector; /* Const */

	div_u64_rem(mb_idx, STRIPE_SZ, &idx);
	start_sector = calc_segment_header_start(super, seg->seg_id); 

	return start_sector + ((idx) * SRC_SECTORS_PER_PAGE);
}


/*
 * Get the segment from the segment id.
 * The Index of the segment is calculated from the segment id.
 */
inline struct segment_header *get_segment_header_by_id(struct dmsrc_super *super,
						u64 segment_id)
{
	u32 idx;
	div_u64_rem(segment_id, super->cache_stat.num_segments, &idx);
	return large_array_at(super->segment_header_array, idx);
}

struct segment_header *get_segment_header_by_mb_idx(struct dmsrc_super *super,
							   u32 mb_idx)
{
	u32 idx;
	u32 seg_id;
	seg_id = div_u64_rem(mb_idx, STRIPE_SZ, &idx);
	return large_array_at(super->segment_header_array, seg_id);
}

struct segment_header *get_seg_by_mb(struct dmsrc_super *super,
							   struct metablock *mb)
{
	return get_segment_header_by_mb_idx(super, mb->idx);
}

int __must_check init_segment_header_array(struct dmsrc_super *super)
{
	u32 segment_idx, group_idx;
	u32 num_segments = super->cache_stat.num_segments;
	u32 num_groups = super->cache_stat.num_groups;
	int i;

	super->group_header_array = vmalloc(sizeof(struct group_header)*num_groups);
	if (!super->group_header_array) {
		WBERR();
		return -ENOMEM;
	}

	for(group_idx = 0;group_idx < num_groups;group_idx++){
		struct group_header *group_header = &super->group_header_array[group_idx];
		group_header->group_id = group_idx;
		atomic_set(&group_header->free_seg_count, 0);
		atomic_set(&group_header->valid_count, 0);
		INIT_LIST_HEAD(&group_header->group_head);
		spin_lock_init(&group_header->lock);
	}
	super->current_group = NULL;

	printk(" segment head allocation\n");
	super->segment_header_array =
		large_array_alloc(sizeof(struct segment_header), num_segments);
	if (!super->segment_header_array) {
		WBERR();
		return -ENOMEM;
	}

	for(i = 0;i < MAX_CACHE_DEVS;i++){
		if(i<NUM_SSD){
			printk(" metablock allocation %d\n", i);
			super->metablock_array[i] =
				large_array_alloc(sizeof(struct metablock), NUM_BLOCKS_PER_SSD);
			if (!super->metablock_array[i]) {
				WBERR();
				return -ENOMEM;
			}
			// debug ... 
			//for(j = 0;j < NUM_BLOCKS_PER_SSD;j++){
			//	struct metablock *mb = large_array_at(super->metablock_array[i], j);
			//	mb->sector = 0;
			//}
		}else{
			super->metablock_array[i] = NULL;
		}
	}

	for (segment_idx = 0; segment_idx < num_segments; segment_idx++) {
		struct segment_header *seg =
			large_array_at(super->segment_header_array, segment_idx);
		struct group_header *group_header;
		
		group_idx = segment_idx / SEGMENT_GROUP_SIZE;
		//printk(" group = %d, seg = %d \n", group_idx, segment_idx);
		group_header = &super->group_header_array[group_idx];
		list_add_tail(&seg->group_list, &group_header->group_head);

		seg->group = group_header;

		atomic_set(&seg->length, 0);
		atomic_set(&seg->valid_count, 0);
		atomic_set(&seg->dirty_count, 0);
		atomic_set(&seg->hot_count, 0);
		atomic_set(&seg->part_start, 0);
		atomic_set(&seg->part_length, 0);
		atomic_set(&seg->bios_count, 0);

		seg->seg_id = (u64)segment_idx;
		seg->group_id = (u64)segment_idx/SEGMENT_GROUP_SIZE;
		seg->flags = 0;
		seg->seg_load = 0;
		seg->sequence = 0;

		//set_bit(SEG_CLEAN, &seg->flags);

		atomic_set(&seg->num_read_inflight, 0);
		atomic_set(&seg->num_filling, 0);
		atomic_set(&seg->num_bufcopy, 0);

		for(i = 0;i < MAX_CACHE_DEVS;i++)
			atomic_set(&seg->summary_start[i], 0);

		spin_lock_init(&seg->lock);

		INIT_LIST_HEAD(&seg->migrate_list);
	}

	mb_array_empty_init(super);
//	printk(" mb init ... \n");
	super->meta_initialized = 1;

	return 0;
}

void free_segment_header_array(struct dmsrc_super *super)
{
	int i;

	if(!super->meta_initialized)
		return;

	vfree(super->group_header_array);
	large_array_free(super->segment_header_array);

	for(i = 0;i < MAX_CACHE_DEVS;i++){
		if(super->metablock_array[i]){
			large_array_free(super->metablock_array[i]);
		}
	}
}

/*----------------------------------------------------------------*/

/*
 * Initialize the Hash Table.
 */
int __must_check ht_empty_init(struct dmsrc_super *super)
{
	u32 idx;
	size_t i, num_heads;
	struct large_array *arr;

	super->htsize = NUM_BLOCKS;
	num_heads = super->htsize + 1;

	printk(" hash table allocation\n");
	arr = large_array_alloc(sizeof(struct ht_head), num_heads);
	if (!arr) {
		WBERR();
		return -ENOMEM;
	}

	super->htable = arr;

	for (i = 0; i < num_heads; i++) {
		struct ht_head *hd = large_array_at(arr, i);
		INIT_HLIST_HEAD(&hd->ht_list);
	}

	/*
	 * Our hashtable has one special bucket called null head.
	 * Orphan metablocks are linked to the null head.
	 */
	super->null_head = large_array_at(super->htable, super->htsize);

	for (idx = 0; idx < NUM_BLOCKS; idx++) {
		struct metablock *mb = mb_at(super, idx);
		hlist_add_head(&mb->ht_list, &super->null_head->ht_list);
	}

	super->ht_initialized = 1;

	return 0;
}

void free_ht(struct dmsrc_super *super)
{
	if(!super->ht_initialized)
		return;

	large_array_free(super->htable);
}

struct ht_head *ht_get_head(struct dmsrc_super *super, sector_t key)
{
	u32 idx;
	div_u64_rem(key, super->htsize, &idx);
	return large_array_at(super->htable, idx);
}

static bool mb_hit(struct metablock *mb, sector_t key)
{
	return mb->sector == key;
}

void ht_del(struct dmsrc_super *super, struct metablock *mb)
{
	struct ht_head *null_head;

	hlist_del(&mb->ht_list);

	null_head = super->null_head;
	hlist_add_head(&mb->ht_list, &null_head->ht_list);

//	mb->sector = ~0;
}

void ht_register(struct dmsrc_super *super,sector_t key, struct metablock *mb)
{
	struct ht_head *head;
	head = ht_get_head(super, key);

	hlist_del(&mb->ht_list);
	hlist_add_head(&mb->ht_list, &head->ht_list);

//	BUG_ON(key==~0);

	mb->sector = key;
};

struct metablock *ht_lookup(struct dmsrc_super *super,sector_t key)
{
	struct metablock *mb, *found = NULL;
	struct ht_head *head;
	head = ht_get_head(super, key);

	hlist_for_each_entry(mb, &head->ht_list, ht_list) {
		if (mb_hit(mb, key)) {
			found = mb;
			break;
		}
	}

	return found;
}

/*
 * Discard all the metablock in a segment.
 */
void discard_caches_inseg(struct dmsrc_super *super, struct segment_header *seg)
{
	unsigned long flags;
	u32 i;

	for (i = 0; i < STRIPE_SZ; i++) {
		struct metablock *mb = get_mb(super, seg->seg_id, i);
		ht_del(super, mb);
		lockseg(seg, flags);
		if(test_bit(MB_VALID, &mb->mb_flags)|| 
			test_bit(MB_PARITY, &mb->mb_flags)||
			test_bit(MB_SUMMARY, &mb->mb_flags)){

			atomic_dec(&seg->valid_count);
			atomic_dec(&seg->group->valid_count);

			clear_bit(MB_VALID, &mb->mb_flags);
			clear_bit(MB_PARITY, &mb->mb_flags);
			clear_bit(MB_SUMMARY, &mb->mb_flags);

			if(test_bit(MB_HIT, &mb->mb_flags)){
				clear_bit(MB_HIT, &mb->mb_flags);
				atomic_dec(&seg->hot_count);
			}

			atomic_dec(&super->cache_stat.num_used_blocks);
		}
		unlockseg(seg, flags);
	}
}

/*----------------------------------------------------------------*/

static int read_superblock_header(struct superblock_device *sup,
				  struct dmsrc_super *super, struct dm_dev *dev)
{
	int r = 0;
	struct dm_io_request io_req_sup;
	struct dm_io_region region_sup;
	sector_t sector = 0;

	void *buf = kmalloc((1 << SECTOR_SHIFT), GFP_KERNEL);
	if (!buf) {
		WBERR("failed to alloc buffer");
		return -ENOMEM;
	}

	//printk(" read superblock_header = %llu\n", sector);

	io_req_sup = (struct dm_io_request) {
		.client = super->io_client,
		.bi_rw = READ,
		.notify.fn = NULL,
		.mem.type = DM_IO_KMEM,
		.mem.ptr.addr = buf,
	};
	region_sup = (struct dm_io_region) {
		.bdev = dev->bdev,
		.sector = sector,
		.count = 1,
	};
	r = dmsrc_io(&io_req_sup, 1, &region_sup, NULL);
	if (r) {
		WBERR("io failed in reading superblock header");
		goto bad_io;
	}

	memcpy(sup, buf, sizeof(*sup));

bad_io:
	kfree(buf);

	return r;
}

/*
 * Check if the cache device is already formatted.
 * Returns 0 iff this routine runs without failure.
 * cache_valid is stored true iff the cache device
 * is formatted and needs not to be re-fomatted.
 */
int __must_check scan_superblock(struct dmsrc_super *super)
{
	struct superblock_device *sup = NULL;
	int num_cache_devs;
	int r = 0;
	int i;
	u32 uuid;

	num_cache_devs = super->dev_info.num_cache_devs;

	for(i = 0;i < num_cache_devs;i++){
		sup = &super->dev_info.sb_device[i];
		r = read_superblock_header(sup, super, super->dev_info.cache_dev[i]);
		if (r) {
			WBERR("failed to read superblock header");
			return r;
		}
#if 0 
		printk(" magic = %x\n", sup->magic);
		printk(" uuid = %d \n", sup->uuid);
		printk(" chunk size = %d sectors\n", sup->chunk_size);
		printk(" num chunks = %d \n", sup->num_chunks);
#endif 
		if (le32_to_cpu(sup->magic) != SRC_MAGIC) {
			WBERR("superblock header: magic number invalid");
			return -1;
		}
	}

	for(i = 0;i < num_cache_devs;i++){
		sup = &super->dev_info.sb_device[i];

		if(i==0)
			uuid = sup->uuid;

		if(sup->uuid != uuid){
			WBERR("superblock heaer: invalid uuid");
			return -1;
		}
	}

	//printk(" num segs = %d \n", sup->num_chunks);
	//printk(" uuid = %d \n", sup->uuid);
	//printk(" magic = %d \n", SRC_MAGIC);

	super->cache_stat.uuid = sup->uuid;
	super->cache_stat.num_chunks_per_ssd = sup->num_chunks;
	super->cache_stat.num_chunks_per_group = sup->chunks_per_group;
	super->cache_stat.num_segments = sup->num_chunks;
	super->cache_stat.num_groups = sup->num_groups;
	super->cache_stat.num_blocks_per_chunk = sup->num_blocks_per_chunk;
	super->cache_stat.num_blocks_per_ssd = sup->num_blocks_per_ssd;

	atomic64_set(&super->cache_stat.alloc_sequence, 0);
	atomic64_set(&super->cache_stat.num_dirty_blocks, 0);
	atomic_set(&super->cache_stat.num_used_blocks, 1) ;
	atomic_set(&super->cache_stat.inflight_ios, 0);
	atomic_set(&super->cache_stat.inflight_bios, 0);
	atomic_set(&super->cache_stat.total_ios, 0);
	atomic_set(&super->cache_stat.total_bios, 0);
	atomic_set(&super->cache_stat.num_free_segments, super->cache_stat.num_segments);

	super->dev_info.origin_sectors = sup->hdd_devsize;
	super->dev_info.per_ssd_sectors = sup->ssd_devsize;

	super->param.chunk_size = sup->chunk_size;
	super->param.chunk_group_size = sup->chunk_group_size;
	super->param.parity_allocation = sup->parity_allocation;
	super->param.striping_policy = sup->striping_policy;
	super->param.data_allocation = sup->data_allocation;
	super->param.erasure_code = sup->erasure_code;
	super->param.hot_identification = sup->hot_identification;
	super->param.reclaim_policy = sup->reclaim_policy;
	super->param.victim_policy= sup->victim_policy;
	super->param.rambuf_pool_amount = sup->rambuf_pool_amount;
	super->param.num_summary_per_chunk = sup->num_summary_per_chunk;
	super->param.num_entry_per_page = sup->num_entry_per_page;
	super->param.flush_command = sup->flush_command;

	return r;
}

u8 calc_checksum(u8 *ptr, int size){
	return crc32_le(17, ptr, size);
}


void copy_summary(struct dmsrc_super *super, void *buf, u32 seg_id, u32 ssd_id){
	struct segment_header *new_seg;
	struct segment_header_device *header;
	u64 sequence;
	u64 uuid;
	u32 magic;
	u32 type;
	u32 offset;

	header = (struct segment_header_device *)buf;
	sequence = le64_to_cpu(header->sequence);
	uuid = le64_to_cpu(header->uuid);
	magic = le32_to_cpu(header->magic);
	type = le32_to_cpu(header->type);

	if(magic!=SRC_MAGIC)
		return ;
	if(uuid!=super->cache_stat.uuid)
		return ;

	if(USE_ERASURE_CODE(&super->param) && ssd_id==get_parity_ssd(super, seg_id)){
		printk(" parity SSD id = %d segid %d \n", ssd_id, seg_id); 
		return;
	}

	new_seg = get_segment_header_by_id(super, seg_id);
	new_seg->sequence = sequence;
	new_seg->seg_type = type;
	new_seg->seg_load = 1;

	for(offset=0;offset<CHUNK_SZ;offset++){
		struct metablock_device *mbdev;// = &header->mbarr[offset];
		struct metablock *new_mb;
		u32 meta_page = offset / NUM_ENTRY_PER_PAGE;
		u32 meta_offset = offset % NUM_ENTRY_PER_PAGE;
		u32 new_idx;
												// Seg Heder + entry ...
		mbdev = (struct metablock_device *)(buf + PAGE_SIZE + meta_page * PAGE_SIZE);
		mbdev += meta_offset;

		new_idx = ssd_id * CHUNK_SZ + offset;
		new_mb = get_mb(super, seg_id, new_idx);
		if(mbdev->sector==(u32)~0)
			new_mb->sector = ~0;
		else
			new_mb->sector = mbdev->sector;

		if(seg_id==0)
			printk(" meta page = %d, offset = %d, sector = %d\n", meta_page, meta_offset, (int)new_mb->sector);


		if(mbdev->dirty_bits)
			set_bit(MB_DIRTY, &new_mb->mb_flags);
		else
			clear_bit(MB_DIRTY, &new_mb->mb_flags);
	}
}

void scan_metadata_complete_to_inactive(struct dmsrc_super *super,struct scan_metadata_manager *scan_manager){
	struct scan_metadata_job *job;
	unsigned long flags;
	int count;

	count = atomic_read(&scan_manager->complete_count);
	while(count--){

		spin_lock_irqsave(&scan_manager->lock, flags);
		job = list_first_entry(&scan_manager->complete_queue, struct scan_metadata_job, list);
		list_del(&job->list);
		atomic_dec(&scan_manager->complete_count);
		spin_unlock_irqrestore(&scan_manager->lock, flags);

		copy_summary(super, job->data, job->seg_id, job->ssd_id);

		spin_lock_irqsave(&scan_manager->lock, flags);
		list_add_tail(&job->list, &scan_manager->inactive_queue);
		atomic_inc(&scan_manager->inactive_count);
		spin_unlock_irqrestore(&scan_manager->lock, flags);
	}

}
struct scan_metadata_job *scan_manager_alloc(struct dmsrc_super *super){
	struct scan_metadata_manager *scan_manager;
	struct scan_metadata_job *job;
	unsigned long flags;

	scan_manager = super->scan_manager;


	//printk(" inactive count = %d, complete = %d \n", atomic_read(&scan_manager->inactive_count), 
	//		atomic_read(&scan_manager->complete_count));

	spin_lock_irqsave(&scan_manager->lock, flags);
	job = list_first_entry(&scan_manager->inactive_queue, struct scan_metadata_job, list);
	list_del(&job->list);
	atomic_dec(&scan_manager->inactive_count);
	atomic_inc(&scan_manager->active_count);
	spin_unlock_irqrestore(&scan_manager->lock, flags);

	return job;
}

int scan_manager_init(struct dmsrc_super *super){
	struct scan_metadata_manager *scan_manager;
	int r = 0;
	int i;

	scan_manager = kmalloc(sizeof(struct scan_metadata_manager), GFP_KERNEL);
	if(!scan_manager){
		WBERR();
		r = -ENOMEM;
		return r;
	}
	super->scan_manager = scan_manager;
	spin_lock_init(&scan_manager->lock);

	atomic_set(&scan_manager->inactive_count, 0);
	atomic_set(&scan_manager->active_count, 0);
	atomic_set(&scan_manager->complete_count, 0);

	INIT_LIST_HEAD(&scan_manager->inactive_queue);
	//INIT_LIST_HEAD(&scan_manager->active_queue);
	INIT_LIST_HEAD(&scan_manager->complete_queue);

	//scan_manager->qdepth = 128;
	scan_manager->qdepth = 256;

	//for(i = 1;i < 16;i++){
	//	printk(" ilog = %d, %d \n", ilog2(i), i);
	//}

	for(i = 0;i < scan_manager->qdepth;i++){
		struct scan_metadata_job *job;

		job = kmalloc(sizeof(struct scan_metadata_job), GFP_KERNEL);
		if(!job){
			BUG_ON(1);
			WBERR();
			return -ENOMEM;
		}
		memset(job, 0x00, sizeof(struct scan_metadata_job));

		job->index = i;

		list_add(&job->list, &scan_manager->inactive_queue);
		atomic_inc(&scan_manager->inactive_count);
		job->super = super;

		job->data = (void *)__get_free_pages(GFP_KERNEL, ilog2(roundup_pow_of_two(NUM_SUMMARY)));
		if (!job->data) {
			BUG_ON(1);
			WBERR();
			return -ENOMEM;
		}
	}

	return r;
}

void scan_manager_deinit(struct dmsrc_super *super){
	struct scan_metadata_manager *scan_manager;
	struct scan_metadata_job *job, *temp;

	scan_manager = super->scan_manager;

	list_for_each_entry_safe(job, temp, &scan_manager->inactive_queue, list){
//		printk(" del inactive count = %d, index = %d \n", atomic_read(&scan_manager->inactive_count), job->index);
		list_del(&job->list);
		free_pages((unsigned long)job->data, ilog2(roundup_pow_of_two(NUM_SUMMARY)));
		kfree(job);
		atomic_dec(&scan_manager->inactive_count);
	}

	BUG_ON(atomic_read(&scan_manager->inactive_count));

	kfree(scan_manager);
	super->scan_manager = NULL;
}


static void scan_metadata_endio(unsigned long error, void *context)
{
	struct scan_metadata_job *job = context;
	struct dmsrc_super *super = job->super;
	struct scan_metadata_manager *scan_manager = super->scan_manager;
	unsigned long flags;

	if(error){
		printk(" End io error \n");
	}

	//printk(" scan metadata endio \n");

	spin_lock_irqsave(&scan_manager->lock, flags);
	list_add_tail(&job->list, &scan_manager->complete_queue);
	spin_unlock_irqrestore(&scan_manager->lock, flags);

	atomic_dec(&scan_manager->active_count);
	atomic_inc(&scan_manager->complete_count);

}

static int __must_check
read_segment_header_device(struct dmsrc_super *super, u32 segment_idx, u32 offset, struct scan_metadata_job *job)
{
	struct dm_io_request io_req;
	struct dm_io_region region;
	int r = 0;

	io_req = (struct dm_io_request) {
		.client = super->io_client,
		.bi_rw = READ,
		.notify.fn = scan_metadata_endio,
		.notify.context = job,
		.mem.type = DM_IO_KMEM,
		.mem.ptr.addr = job->data,
	};
	region = (struct dm_io_region) {
		.bdev = get_bdev(super, offset),
		.sector = get_sector(super, segment_idx, offset),
		.count = SRC_SECTORS_PER_PAGE * NUM_SUMMARY,
	};
	r = dmsrc_io(&io_req, 1, &region, NULL);
	if (r) {
		WBERR();
	//	goto bad_io;
	}

	//printk(" read segid = %d, idx = %d, sector = %d \n", (int)segment_idx, (int)idx, (int)region.sector);

	return r;
}


int load_summary_from_ssd(struct dmsrc_super *super){
	struct scan_metadata_manager *scan_manager;
	struct scan_metadata_job *job;
	u32 summary_idx;
 	u32 num_segments = super->cache_stat.num_segments;
	u32 seg_id, ssd_id;
	int r = 0;

	r = scan_manager_init(super);
	if(r<0)
		return r;

	scan_manager = super->scan_manager;

	for (seg_id = 0; seg_id < num_segments; seg_id++) {
		for(ssd_id = 0;ssd_id < NUM_SSD;ssd_id++){

			while(!atomic_read(&scan_manager->inactive_count)){
				while(!atomic_read(&scan_manager->complete_count)){
					schedule_timeout_interruptible(usecs_to_jiffies(1000));
				}
				scan_metadata_complete_to_inactive(super, scan_manager);
			}

			job = (struct scan_metadata_job *)scan_manager_alloc(super);
			job->super = super;
			job->seg_id = seg_id;
			job->ssd_id = ssd_id;

		//	summary_idx = (ssd_id + 1) * CHUNK_SZ - NUM_SUMMARY;
			summary_idx = get_summary_offset(super, ssd_id);

			//printk(" summary idx = %d \n", summary_idx);

			r = read_segment_header_device(super, seg_id, summary_idx, job);
			if (r) {
				WBERR();
				r = -1;
				goto bad_super;
			}
		}
	}
	while(atomic_read(&scan_manager->active_count)){
		//printk(" active count = %d \n", atomic_read(&scan_manager->active_count));
		schedule_timeout_interruptible(usecs_to_jiffies(1000));
	}

	while(scan_manager->qdepth != atomic_read(&scan_manager->inactive_count)){
		schedule_timeout_interruptible(usecs_to_jiffies(1000));
		scan_metadata_complete_to_inactive(super, scan_manager);
		//printk(" complete count = %d \n", atomic_read(&scan_manager->complete_count));
		//printk(" inactive count = %d \n", atomic_read(&scan_manager->inactive_count));
	}

bad_super:;

	return r;
}

void _construct_metadata_in_ram(struct dmsrc_super *super, u32 seg_id){
	struct segment_header *cur_seg, *old_seg;
	u32 ssd_id, offset;
	u32 cur_idx;
	int cur_is_new = 0;
	struct metablock *old_mb, *cur_mb;
	sector_t key;

	cur_seg = get_segment_header_by_id(super, seg_id);

	for(ssd_id = 0;ssd_id < NUM_SSD;ssd_id++){
		for(offset = 0;offset < CHUNK_SZ;offset++){

			cur_idx = ssd_id * CHUNK_SZ + offset;
			cur_mb = get_mb(super, seg_id, cur_idx);

#if 0 
			if(USE_ERASURE_CODE(&super->param)){
				if(ssd_id!=get_parity_ssd(super, seg_id) && offset==CHUNK_SZ-1)
						set_bit(MB_SUMMARY, &cur_mb->mb_flags);
			}else{
				if(offset==CHUNK_SZ-1)
						set_bit(MB_SUMMARY, &cur_mb->mb_flags);
			}
#endif

			key = cur_mb->sector;
			if(cur_mb->sector==~0 || cur_mb->sector>=super->dev_info.origin_sectors){
				//clear_bit(MB_DIRTY, &cur_mb->mb_flags);
				if(test_bit(MB_DIRTY, &cur_mb->mb_flags)){
					atomic_inc(&cur_seg->dirty_count);
				}
				clear_bit(MB_VALID, &cur_mb->mb_flags);
				continue;
			}

			old_mb = ht_lookup(super, key);

			//printk(" cur_idx = %d(%d), sector = %d, seq = %d ", (int)cur_mb->idx, 
			//		seg_id*STRIPE_SZ + cur_idx,
			//		(int)key.sector,(int)cur_seg->sequence);


			if(old_mb && old_mb->sector != ~0){
			//	printk(" hit ");
				old_seg = get_segment_header_by_mb_idx(super, old_mb->idx);
				if(cur_seg->sequence > old_seg->sequence){
					cur_is_new = 1;
				}
				if(cur_seg->sequence == old_seg->sequence && cur_idx > old_mb->idx){
					cur_is_new= 1;
				}

				if(cur_is_new){
					invalidate_previous_cache(super, old_seg, old_mb);
			//		printk(" invalidate ");
				}
			}else{
				cur_is_new= 1;
			}

			if(USE_ERASURE_CODE(&super->param)){
				if(ssd_id==get_parity_ssd(super, seg_id)){
					printk(" parity SSD id = %d segid %d  sector = %d \n", ssd_id, seg_id, (int)key); 
					BUG_ON(1);
				}
			}

			if(cur_is_new){
				bool clean;

				// why? 
				//if(old_mb){
				//	clear_bit(MB_DIRTY, &old_mb->mb_flags);
				//	clear_bit(MB_VALID, &old_mb->mb_flags);
				//}

				ht_register(super, key, cur_mb);
				clean = !test_bit(MB_DIRTY, &cur_mb->mb_flags);
				initialize_mb(super, cur_mb, cur_seg->seg_type, clean);
				seg_length_inc(super, cur_seg, cur_mb, false);
				set_bit(MB_SEAL, &cur_mb->mb_flags);
				atomic_inc(&super->cache_stat.num_used_blocks);
			}else{
				if(test_bit(MB_DIRTY, &cur_mb->mb_flags)){
					atomic_inc(&cur_seg->dirty_count);
				}
				clear_bit(MB_VALID, &cur_mb->mb_flags);
			}

#ifdef USE_LAST_SUMMARY // summary information stored in last of each chunk 
			if(offset==CHUNK_SZ-1)
			{
				printk(" invalid offset ... \n");
				BUG_ON(1);
			}
#else
			if(offset < NUM_SUMMARY)
			{
				printk(" invalid offset ... %d\n", (int)offset);
				BUG_ON(1);
			}

#endif
		}
	}
	if(seg_id<10){
		printk(" seg id = %d, valid = %d, dirty = %d \n", seg_id, atomic_read(&cur_seg->valid_count),
				atomic_read(&cur_seg->dirty_count));

	}
}

void segment_group_print_stat(struct dmsrc_super *super){
	u32 group_idx;
	u32 num_groups = super->cache_stat.num_groups;

	printk("\n");
	for(group_idx = 0;group_idx < num_groups;group_idx++){
		struct group_header *group = &super->group_header_array[group_idx];

		if(group_idx<10)
			printk(" gid = %d, free = %d \n", (int)group->group_id, (int)atomic_read(&group->free_seg_count));
	}
	printk("\n");

}

void segment_group_dec_free_segs(struct dmsrc_super *super, struct segment_header *seg){
	u32 group_idx = seg->seg_id/SEGMENT_GROUP_SIZE;
	struct group_header *group = &super->group_header_array[group_idx];

	atomic_dec(&group->free_seg_count);
	BUG_ON((int)atomic_read(&group->free_seg_count)<0);
}

u32 segment_group_inc_free_segs(struct dmsrc_super *super, struct segment_header *seg){
	u32 group_idx = seg->seg_id/SEGMENT_GROUP_SIZE;
	u32 free_seg_count;
	struct group_header *group = &super->group_header_array[group_idx];

	free_seg_count = atomic_inc_return(&group->free_seg_count);
	BUG_ON(atomic_read(&group->free_seg_count)>SEGMENT_GROUP_SIZE);
	return free_seg_count;
}

int construct_metadata_in_ram(struct dmsrc_super *super){
	struct segment_header *cur_seg;
	u64 last_sequence = 0;
	u32 seg_id;
	u32 group_id;
 	u32 num_segments; 
 	u32 num_groups; 
	u32 *rand_table;

 	num_segments = super->cache_stat.num_segments;
 	num_groups = super->cache_stat.num_groups;

	for (seg_id = 0; seg_id < num_segments; seg_id++) {

		cur_seg = get_segment_header_by_id(super, seg_id);

		if(cur_seg->seg_load){

			if(cur_seg->sequence > last_sequence)
				last_sequence = cur_seg->sequence;

			//printk(" seg id = %d, load \n", seg_id);
			_construct_metadata_in_ram(super, seg_id);
		}

		//if(seg_id < 5)
			//printk(" scan segment = %u (%u), valid = %d, %d %d \n", seg_id, 
			//		(u32)cur_seg->seg_id,
			//		atomic_read(&cur_seg->valid_count),
			//		(int)atomic_read(&cur_seg->num_filling),
			//		(int)atomic_read(&cur_seg->num_inflight));
	}

	rand_table = (u32 *)kmalloc(sizeof(u32)*num_segments, GFP_KERNEL);
	if(rand_table==NULL){
		return -1;
	}
	for (seg_id = 0; seg_id < num_segments; seg_id++) {
		rand_table[seg_id] = seg_id;
	}

#if 0
	for (seg_id = 0; seg_id < num_segments; seg_id++) {
		u32 rand_num;
		u32 temp;

		get_random_bytes(&rand_num, sizeof(u32));
		rand_num %= num_segments;

		temp = rand_table[seg_id];
		rand_table[seg_id] = rand_table[rand_num];
		rand_table[rand_num] = temp;
	}
#endif

	for (seg_id = 0; seg_id < num_segments; seg_id++) {
		u32 rand_seg_id = rand_table[seg_id];

		//printk(" rand seg id = %d \n", rand_seg_id);
		cur_seg = get_segment_header_by_id(super, rand_seg_id);

		if(atomic_read(&cur_seg->valid_count)){

			atomic_inc(&super->wstat.seg_count[cur_seg->seg_type]);

			// chunk summary
			if(is_write_stripe(cur_seg->seg_type)){
				atomic_add(NUM_SUMMARY*NUM_DATA_SSD, &cur_seg->valid_count);
				atomic_add(NUM_SUMMARY*NUM_DATA_SSD, &cur_seg->group->valid_count);
				atomic_add(NUM_SUMMARY*NUM_DATA_SSD, &cur_seg->dirty_count);
				atomic_add(NUM_SUMMARY*NUM_DATA_SSD, &super->cache_stat.num_used_blocks);

				if(USE_ERASURE_PARITY(&super->param)){
					atomic_add(CHUNK_SZ, &cur_seg->valid_count);
					atomic_add(CHUNK_SZ, &cur_seg->group->valid_count);
					atomic_add(CHUNK_SZ, &cur_seg->dirty_count);
					atomic_add(CHUNK_SZ, &super->cache_stat.num_used_blocks);
				}
				BUG_ON(USE_ERASURE_RAID6(&super->param));

			}else{
				atomic_add(NUM_SUMMARY*NUM_SSD, &cur_seg->group->valid_count);
				atomic_add(NUM_SUMMARY*NUM_SSD, &cur_seg->dirty_count);
				atomic_add(NUM_SUMMARY*NUM_SSD, &super->cache_stat.num_used_blocks);
			}
			BUG_ON(atomic_read(&cur_seg->valid_count) > STRIPE_SZ);
			BUG_ON(atomic_read(&cur_seg->dirty_count) > STRIPE_SZ);

			insert_seg_to_used_queue(super, cur_seg);

			set_bit(SEG_SEALED, &cur_seg->flags);
			clear_bit(SEG_USED, &cur_seg->flags);
			clear_bit(SEG_PARTIAL, &cur_seg->flags);

			move_seg_used_to_sealed_queue(super, cur_seg);
		}else{
			insert_seg_to_alloc_queue(super, cur_seg);
			set_bit(SEG_CLEAN, &cur_seg->flags);
			clear_bit(SEG_RECOVERY, &cur_seg->flags);
			clear_bit(SEG_HIT, &cur_seg->flags);

			segment_group_inc_free_segs(super, cur_seg);
		}
	}

	for (group_id = 0; group_id < num_groups; group_id++) {
		struct group_header *group = &super->group_header_array[group_id];
		//printk(" group = %d free segs = %d \n", group_id, atomic_read(&group->free_seg_count));
		if(atomic_read(&group->free_seg_count)==SEGMENT_GROUP_SIZE){
			insert_group_to_alloc_queue(super, group);
		}else{
			insert_group_to_used_queue(super, group);
			move_group_used_to_sealed_queue(super, group);
		}
	}

	printk(" last sequence = %llu\n", last_sequence+1);
	atomic64_set(&super->cache_stat.alloc_sequence, last_sequence+1);

	kfree(rand_table);

	return 0;
}


int assign_new_segment(struct dmsrc_super *super){
	int type;

	//for(type = 0;type < NBUF-1;type++){
	for(type = 0;type <= RHBUF;type++){
		//u32 seg_id;
		if(atomic_read(&super->seg_allocator.seg_alloc_count)<1){
			printk(" no more free segments %d \n", atomic_read(&super->seg_allocator.seg_alloc_count));
			return -1;
		}
#if 0
		seg_id = alloc_new_segment(super, type, false);
		printk(" assign new seg = %d \n", (int)seg_id);
#else
		ma_set_count(super, type, STRIPE_SZ);
		if(should_need_refresh_seg(super, type)){
			printk(" assign new seg = %d %d \n", (int)type,
					ma_get_count(super, type) );
		}
#endif
	}

	return 0;
}

int __must_check scan_metadata(struct dmsrc_super *super)
{
	int r = 0;
	unsigned long start_jiffies;
	unsigned long end_jiffies;

	start_jiffies = jiffies;

	r = load_summary_from_ssd(super);
	if(r)
		return r;

	r = construct_metadata_in_ram(super);
	if(r)
		return r;

#if 0 
	{
		u32 seg_id;
		struct segment_header *cur_seg;
		for (seg_id = 0; seg_id < super->cache_stat.num_segments; seg_id++) {
			cur_seg = get_segment_header_by_id(super, seg_id);

			if(seg_id < 200){
				if(test_bit(SEG_SEALED, &cur_seg->flags)){
					printk(" scan sealed segment = %u (type%d), length = %d, valid = %d, dirty = %d, %d %d \n", 
						seg_id, 
						(u32)cur_seg->seg_type,
						atomic_read(&cur_seg->length),
						atomic_read(&cur_seg->valid_count),
						atomic_read(&cur_seg->dirty_count),
						(int)atomic_read(&cur_seg->num_filling),
						(int)atomic_read(&cur_seg->num_read_inflight));
				}else{
					printk(" scan clean segment = %u (type%d), length = %d, valid = %d, dirty = %d, %d %d \n", 
						seg_id, 
						(u32)cur_seg->seg_type,
						atomic_read(&cur_seg->length),
						atomic_read(&cur_seg->valid_count),
						atomic_read(&cur_seg->dirty_count),
						(int)atomic_read(&cur_seg->num_filling),
						(int)atomic_read(&cur_seg->num_read_inflight));

				}
			}
		}
	}
#endif

#if 1
	mb_array_sanity_check(super);
#endif

	printk(" current util = %d \n", get_curr_util(super));

	while(atomic_read(&super->seg_allocator.seg_alloc_count) < 20){
		do_background_gc(super);
		schedule_timeout_interruptible(msecs_to_jiffies(1000));
		printk(" free segment = %d \n", atomic_read(&super->seg_allocator.seg_alloc_count));
	}
	atomic_set(&super->migrate_mgr.migrate_triggered, 0);
	atomic_set(&super->migrate_mgr.background_gc_on, 0);
	super->migrate_mgr.allow_migrate = 0;

	r = assign_new_segment(super);
	if(r)
		return r;

	end_jiffies = jiffies;

	printk(" current util = %d \n", get_curr_util(super));
	printk(" free segment = %d \n", atomic_read(&super->seg_allocator.seg_alloc_count));
	printk(" Scanning Metadata Time  = %d ms \n", jiffies_to_msecs(end_jiffies - start_jiffies));


	return 0;
}

struct rambuf_page *alloc_single_page(struct dmsrc_super *super){
	unsigned long flags;
	struct rambuf_page *page;
	struct segbuf_manager *segbuf_mgr = &super->segbuf_mgr;
	int check = 0;

	spin_lock_irqsave(&segbuf_mgr->lock, flags);
	while(atomic_read(&segbuf_mgr->inactive_page_count)<=STRIPE_SZ){
		spin_unlock_irqrestore(&segbuf_mgr->lock, flags);
		//printk(" no rambuf single plage ... \n");
		schedule_timeout_interruptible(usecs_to_jiffies(50));
		spin_lock_irqsave(&segbuf_mgr->lock, flags);
		check = 1;
	}
	if(check)
		printk(" delayed ram allocated .. \n");

	atomic_inc(&segbuf_mgr->gc_active_page_count);
	page = _alloc_rambuf_page(super);
	page->pl->next = NULL;
	spin_unlock_irqrestore(&segbuf_mgr->lock, flags);
	return page;
}

void free_single_page(struct dmsrc_super *super, struct rambuf_page *page){
	unsigned long flags;
	struct segbuf_manager *segbuf_mgr = &super->segbuf_mgr;

	spin_lock_irqsave(&segbuf_mgr->lock, flags);
	_free_rambuf_page(super, page);
	atomic_dec(&segbuf_mgr->gc_active_page_count);
	spin_unlock_irqrestore(&segbuf_mgr->lock, flags);
}

struct rambuf_page *_alloc_rambuf_page(struct dmsrc_super *super){
	struct rambuf_page *page;
	struct segbuf_manager *segbuf_mgr = &super->segbuf_mgr;

	if(atomic_read(&segbuf_mgr->inactive_page_count)==0){
		printk(" no rambuf ... \n");
	}
	BUG_ON(atomic_read(&segbuf_mgr->inactive_page_count)==0);
	page = list_first_entry(
		&segbuf_mgr->inactive_page_list, struct rambuf_page, list);

	list_move_tail(&page->list, &segbuf_mgr->active_page_list);
	atomic_dec(&segbuf_mgr->inactive_page_count);
	atomic_inc(&segbuf_mgr->active_page_count);

	return page;
}

struct rambuf_page *_free_rambuf_page(struct dmsrc_super *super, struct rambuf_page *page){
	struct segbuf_manager *segbuf_mgr = &super->segbuf_mgr;

	if(!page)
		return NULL;

	list_move_tail(&page->list, &segbuf_mgr->inactive_page_list);
	atomic_dec(&segbuf_mgr->active_page_count);
	atomic_inc(&segbuf_mgr->inactive_page_count);

	return page;
}

void alloc_summary_rambuf(struct dmsrc_super *super, struct rambuffer *rambuf){
	int i;
	if(SUMMARY_SCHEME==SUMMARY_PER_CHUNK){
		for(i=0;i<STRIPE_SZ;i++){
			if(!rambuf->pages[i] && chunk_summary_range(super, i)){
				rambuf->pages[i] = _alloc_rambuf_page(super); 
			}
		}
	}else{
		if(!rambuf->pages[STRIPE_SZ-1])
			rambuf->pages[STRIPE_SZ-1] = _alloc_rambuf_page(super); 
	}
}

void alloc_rambuf_page(struct dmsrc_super *super, struct rambuffer *rambuf, int cache_type){
	int i;
	int summary_only;

	if(rambuf==NULL)
		return;

	rambuf->alloc_count = 0;

	if(is_gc_stripe(cache_type)){
		summary_only = 0;
	}else{
		if(cache_type == RHBUF || cache_type == RCBUF){
			summary_only = 0;
		}else{
			if(super->param.erasure_code!=ERASURE_CODE_NONE){
				summary_only = 0;
			}else{
				summary_only = 0;
			}
		}
	}

	if(summary_only){
		alloc_summary_rambuf(super, rambuf);
	}else{
		for(i=0;i<STRIPE_SZ;i++){
			if(!rambuf->pages[i])
				rambuf->pages[i] = _alloc_rambuf_page(super); 
		}
	}

	for(i=0;i<STRIPE_SZ;i++){
		if(rambuf->pages[i])
			rambuf->alloc_count++;
	}
	BUG_ON(!rambuf->alloc_count);
}

void free_rambuf_page(struct dmsrc_super *super, struct rambuffer *rambuf){
	int i;

	for(i=0;i<STRIPE_SZ;i++){
		if(rambuf->pages[i]){
			_free_rambuf_page(super, rambuf->pages[i]); 
			rambuf->alloc_count--;
		}
		rambuf->pages[i] = NULL;
	}
	BUG_ON(rambuf->alloc_count);
}

struct rambuffer *alloc_rambuffer(struct dmsrc_super *super, int cache_type, int stripe_size){
	struct rambuffer *next_rambuf;
	struct segbuf_manager *segbuf_mgr = &super->segbuf_mgr;
	struct list_head *inactive_head = &segbuf_mgr->inactive_list;
	struct list_head *active_head = &segbuf_mgr->active_list;
	unsigned long flags;
	int i;

	spin_lock_irqsave(&segbuf_mgr->lock, flags);

	inactive_head = &segbuf_mgr->inactive_list;
	active_head = &segbuf_mgr->active_list;

	if(atomic_read(&segbuf_mgr->inactive_count)){

		next_rambuf = (struct rambuffer *)
			list_entry(inactive_head->next, struct rambuffer, list);

		list_del(&next_rambuf->list);
		atomic_dec(&segbuf_mgr->inactive_count);

		list_add_tail(&next_rambuf->list, active_head);
		atomic_inc(&segbuf_mgr->active_count[cache_type]);
		atomic_inc(&segbuf_mgr->active_total_count);
		alloc_rambuf_page(super, next_rambuf, cache_type);
		atomic_set(&next_rambuf->ref_count, stripe_size);

		for(i = 0;i < NUM_SSD;i++){
			atomic_set(&next_rambuf->bios_count[i], 0);
			atomic_set(&next_rambuf->bios_start[i], 0);
		}
		atomic_set(&next_rambuf->bios_total_count, 0);
		atomic_set(&next_rambuf->bios_total_start, 0);
		for(i = 0;i < STRIPE_SZ;i++){
			next_rambuf->bios[i] = NULL;
		}
		spin_lock_init(&next_rambuf->lock);
	//	atomic_set(&next_rambuf->total_length, 0);
	//	for(i = 0;i < NUM_SSD;i++){
	//		INIT_LIST_HEAD(&next_rambuf->queue[i]);
	//		atomic_set(&next_rambuf->queue_length[i], 0);
	//		spin_lock_init(&next_rambuf->lock[i]);
	//	}

#if 0 
		if(is_write_stripe(cache_type)){
			atomic_add(NUM_SUMMARY*NUM_DATA_SSD, &next_rambuf->ref_count);
			if(USE_ERASURE_PARITY(&super->param))
				atomic_add(CHUNK_SZ, &next_rambuf->ref_count);
		}else{
			atomic_add(NUM_SUMMARY*NUM_SSD, &next_rambuf->ref_count);
		}
#endif
		BUG_ON(USE_ERASURE_RAID6(&super->param));
	}else{
		printk (" alloc: active = %d, inactve = %d \n",  
		(int)atomic_read(&segbuf_mgr->active_total_count),
		(int)atomic_read(&segbuf_mgr->inactive_count));
		BUG_ON(1);
	}

	spin_unlock_irqrestore(&segbuf_mgr->lock, flags);

#if 0
	printk (" alloc: active = %d, inactve = %d \n",  
			(int)atomic_read(&segbuf_mgr->active_count),
			(int)atomic_read(&segbuf_mgr->inactive_count));
	printk(" rambuf page inactive count = %d (%d MB) \n", (int)atomic_read(&super->segbuf_mgr.inactive_page_count), 
			(int)atomic_read(&super->segbuf_mgr.inactive_page_count)/256);
#endif 

	//printk(" alloc rambuf = %d, active = %d \n", next_rambuf->rambuf_id, atomic_read(&segbuf_mgr->active_total_count));

	BUG_ON(next_rambuf==NULL);
	return next_rambuf;
}

void release_rambuffer(struct dmsrc_super *super, struct rambuffer *rambuf, int cache_type){
	struct segbuf_manager *segbuf_mgr = &super->segbuf_mgr;
	struct list_head *inactive_head = &segbuf_mgr->inactive_list;
	unsigned long flags;

	//printk(" release rambuf = %d, active = %d  \n", rambuf->rambuf_id,
	//		atomic_read(&segbuf_mgr->active_total_count));

	spin_lock_irqsave(&segbuf_mgr->lock, flags);

	free_rambuf_page(super, rambuf);

	list_del(&rambuf->list);
	atomic_dec(&segbuf_mgr->active_count[cache_type]);
	atomic_dec(&segbuf_mgr->active_total_count);

	list_add_tail(&rambuf->list, inactive_head);
	atomic_inc(&segbuf_mgr->inactive_count);

	spin_unlock_irqrestore(&segbuf_mgr->lock, flags);

	pending_worker_schedule(super);
}

/*----------------------------------------------------------------*/
int check_rambuf_pool(struct dmsrc_super *super){
	int i;
	struct rambuffer *rambuf;
	struct segbuf_manager *segbuf_mgr = &super->segbuf_mgr;

	for (i = 0; i < segbuf_mgr->num_rambuf_pool; i++) {
		rambuf = segbuf_mgr->rambuf_pool + i;
		if(rambuf==NULL)
			continue;

		printk(" rambuf %d, start %d length = %d \n", 
				i, atomic_read(&rambuf->bios_total_start),
			atomic_read(&rambuf->bios_total_count));
	}

	return 0;
}

/*
 * Obtain one page for the use of kcopyd.
 */
static struct page_list *alloc_pl(gfp_t gfp)
{
	struct page_list *pl;

	pl = kmalloc(sizeof(*pl), gfp);
	if (!pl)
		return NULL;

	pl->page = alloc_page(gfp);
	if (!pl->page) {
		kfree(pl);
		return NULL;
	}

	return pl;
}

static void free_pl(struct page_list *pl)
{
	__free_page(pl->page);
	kfree(pl);
}


static int init_each_rambuf_pool(struct dmsrc_super *super){
	int i, j;
	struct rambuffer *rambuf;
	struct segbuf_manager *segbuf_mgr = &super->segbuf_mgr;
	struct list_head *active_head = &segbuf_mgr->active_list;
	struct list_head *inactive_head = &segbuf_mgr->inactive_list;

	for(i=0;i<(int)atomic_read(&segbuf_mgr->inactive_page_count);i++){
		struct rambuf_page *page;
		page = kmalloc(sizeof(struct rambuf_page), GFP_KERNEL);
		if(!page){
			WBERR();
			return -ENOMEM;
		}

		list_add_tail(&page->list, &segbuf_mgr->inactive_page_list);

#if 0
		page->data = (void *)__get_free_pages(GFP_KERNEL, SRC_SIZE_SHIFT);
		if (!page->data) {
			WBERR();
			return -ENOMEM;
		}
#endif
		page->pl = alloc_pl(__GFP_NOWARN | __GFP_NORETRY);
		if (!page->pl) {
			WBERR();
			return -ENOMEM;
		}
#if 0
		page->page = alloc_pages(GFP_KERNEL, SRC_SIZE_SHIFT);
		if (!page->page) {
			WBERR();
			return -ENOMEM;
		}
#endif 
	}

	INIT_LIST_HEAD(active_head);
	INIT_LIST_HEAD(inactive_head);

	segbuf_mgr->pages = vmalloc(segbuf_mgr->num_rambuf_pool * sizeof(void *) * CHUNK_SZ * MAX_CACHE_DEVS);
	printk(" Allocate memory segbuf_mgr->pages = %dbytes \n", 
				(int)(segbuf_mgr->num_rambuf_pool * sizeof(void *) * CHUNK_SZ * MAX_CACHE_DEVS));
	if(segbuf_mgr->pages==NULL){
		printk(" Cannot allocate memory segbuf_mgr->pages = %dbytes \n", 
				(int)(segbuf_mgr->num_rambuf_pool * sizeof(void *) * CHUNK_SZ * MAX_CACHE_DEVS));
		return -ENOMEM;
	}
	segbuf_mgr->bios = vmalloc(segbuf_mgr->num_rambuf_pool * sizeof(void *) * CHUNK_SZ * MAX_CACHE_DEVS);

	printk(" Allocate memory segbuf_mgr->bios = %dbytes \n", 
				(int)(segbuf_mgr->num_rambuf_pool * sizeof(void *) * CHUNK_SZ * MAX_CACHE_DEVS));
	if(segbuf_mgr->bios==NULL){
		printk(" Cannot allocate memory segbuf_mgr->bios = %dbytes \n", 
				(int)(segbuf_mgr->num_rambuf_pool * sizeof(void *) * CHUNK_SZ * MAX_CACHE_DEVS));
		return -ENOMEM;
	}

	for (i = 0; i < segbuf_mgr->num_rambuf_pool; i++) {
		int num_pages = CHUNK_SZ * MAX_CACHE_DEVS;

		rambuf = segbuf_mgr->rambuf_pool + i;
		rambuf->rambuf_id = i;
		rambuf->alloc_count = 0;

		//for(j = 0;j < NUM_SSD;j++){
		//	rambuf->seg_buf[j] = (void *)__get_free_pages(GFP_KERNEL, ilog2(roundup_pow_of_two(CHUNK_SZ)));
		//	printk(" alloc free pages ... \n");
		//	if(rambuf->seg_buf[j]==NULL){
		//		printk(" No buffer available .. %d \n", ilog2(roundup_pow_of_two(CHUNK_SZ)));
		//		return -ENOMEM;
		//	}
		//}

		//rambuf->pages = vmalloc(sizeof(struct rambuf_page *) * num_pages);
		//rambuf->pages = kmalloc(sizeof(struct rambuf_page *) * num_pages , GFP_KERNEL);
		rambuf->pages = (struct rambuf_page **)segbuf_mgr->pages + i * num_pages;
		if (!rambuf->pages) {
			BUG_ON(1);
			return -ENOMEM;
		}

		//rambuf->bios = kmalloc(sizeof(struct bio *) * num_pages , GFP_KERNEL);
		//rambuf->bios = vmalloc(sizeof(struct bio *) * num_pages);
		rambuf->bios = (struct bio **)segbuf_mgr->bios + i * num_pages;
		if (!rambuf->bios) {
			BUG_ON(1);
			return -ENOMEM;
		}

		for(j=0;j<num_pages;j++){
			rambuf->pages[j] = NULL;
		}

		for(j=0;j<num_pages;j++){
			rambuf->bios[j] = NULL;
		}

		for(j = 0;j < NUM_SSD;j++){
			atomic_set(&rambuf->bios_count[j], 0);
			atomic_set(&rambuf->bios_start[j], 0);
		}
		atomic_set(&rambuf->bios_total_count, 0);
		atomic_set(&rambuf->bios_total_start, 0);

		list_add_tail(&rambuf->list, inactive_head);
		atomic_inc(&segbuf_mgr->inactive_count);
	}

	return 0;
}

int __must_check init_rambuf_pool(struct dmsrc_super *super)
{
	int res;
	u32 nr;
	struct segbuf_manager *segbuf_mgr = &super->segbuf_mgr;
	int i;
	
	//if(SUMMARY_SCHEME==SUMMARY_PER_CHUNK)
	//	nr = div_u64(super->param.rambuf_pool_amount, NUM_SSD);
	//else
	//	nr = super->param.rambuf_pool_amount; 
	nr = super->param.rambuf_pool_amount/STRIPE_SZ; 

	if (!nr) {
		WBERR("rambuf must be allocated at least one");
		return -EINVAL;
	}

	//if (nr<NBUF) {
	//	WBERR(" Rambuf is too small \n");
	//	return -EINVAL;
	//}

	segbuf_mgr->num_rambuf_pool = nr;

	segbuf_mgr->rambuf_pool = vmalloc(sizeof(struct rambuffer) * segbuf_mgr->num_rambuf_pool);
	if (!segbuf_mgr->rambuf_pool) {
		WBERR();
		return -ENOMEM;
	}

	atomic_set(&segbuf_mgr->active_total_count, 0);
	for(i = 0;i < NBUF;i++)
		atomic_set(&segbuf_mgr->active_count[i], 0);
	atomic_set(&segbuf_mgr->inactive_count, 0);

	INIT_LIST_HEAD(&segbuf_mgr->active_page_list);
	INIT_LIST_HEAD(&segbuf_mgr->inactive_page_list);

	atomic_set(&segbuf_mgr->active_page_count, 0);
	atomic_set(&segbuf_mgr->gc_active_page_count, 0);
	atomic_set(&segbuf_mgr->inactive_page_count, super->param.rambuf_pool_amount);
	atomic_set(&segbuf_mgr->total_page_count, super->param.rambuf_pool_amount);
	printk(" Rambuf Size = %d MB, num rmabuf head = %d\n", super->param.rambuf_pool_amount/256, nr);

	res = init_each_rambuf_pool(super);
	if(res)
		return res;

	printk (" active = %d, inactve = %d \n",  (int)atomic_read(&segbuf_mgr->active_total_count),
			(int)atomic_read(&segbuf_mgr->inactive_count));

	spin_lock_init(&segbuf_mgr->lock);

	init_waitqueue_head(&segbuf_mgr->wait_queue);

	segbuf_mgr->initialized = 1;

	return 0;
}

void free_rambuf_pool(struct dmsrc_super *super)
{
	//struct rambuffer *rambuf;
	struct rambuf_page *page, *temp;
	struct segbuf_manager *segbuf_mgr = &super->segbuf_mgr;
	//size_t i, j;

	if(!segbuf_mgr->initialized)
		return;

	//for (i = 0; i < segbuf_mgr->num_rambuf_pool; i++) {
	//	rambuf = segbuf_mgr->rambuf_pool + i;
		//for(j = 0;j <  NUM_SSD;j++){
		//	free_pages((unsigned long)rambuf->seg_buf[j], ilog2(roundup_pow_of_two(CHUNK_SZ)));
		//}
	//}

	vfree(segbuf_mgr->pages);
	vfree(segbuf_mgr->bios);
	vfree(segbuf_mgr->rambuf_pool);

	list_for_each_entry_safe(page, temp, &segbuf_mgr->active_page_list, list){
		list_del(&page->list);

		//free_pages((unsigned long)page->data, SRC_SIZE_SHIFT);
		//__free_pages(page->page, SRC_SIZE_SHIFT);
		free_pl(page->pl);
		kfree(page);
		atomic_dec(&segbuf_mgr->active_page_count);
	}
	BUG_ON(atomic_read(&segbuf_mgr->active_page_count));

	list_for_each_entry_safe(page, temp, &segbuf_mgr->inactive_page_list, list){
		list_del(&page->list);

		//free_pages((unsigned long)page->data, SRC_SIZE_SHIFT);
		//__free_pages(page->page, SRC_SIZE_SHIFT);
		free_pl(page->pl);
		kfree(page);
		atomic_dec(&segbuf_mgr->inactive_page_count);
	}
	BUG_ON(atomic_read(&segbuf_mgr->inactive_page_count));
}

int create_daemon(struct dmsrc_super *super, 
		struct task_struct **taskp, 
		int (*threadfn)(void *data), 
		char *name){
	struct task_struct *task;
	int r = 0;

	task = kthread_create(threadfn, super, name);
	if (IS_ERR(name)) { 
		r = PTR_ERR(task); 
		task = NULL; 
		//WBERR("couldn't spawn" #name "daemon"); 
		printk(" %s daemon cannot be created \n", name);
	} 
	wake_up_process(task); 

	*taskp = task;

	return r;
}

/*----------------------------------------------------------------*/

#define CREATE_DAEMON(name) \
	do { \
		super->name##_daemon = kthread_create(name##_proc, super, \
						      #name "_daemon"); \
		if (IS_ERR(super->name##_daemon)) { \
			r = PTR_ERR(super->name##_daemon); \
			super->name##_daemon = NULL; \
			WBERR("couldn't spawn" #name "daemon"); \
			goto bad_##name##_daemon; \
		} \
		wake_up_process(super->name##_daemon); \
	} while (0)



#if 0
void free_cache(struct dmsrc_super *super)
{
	int i;

	read_miss_mgr_deinit(super);

	recovery_mgr_deinit(super);

	sync_mgr_deinit(super);

	flush_mgr_deinit(super);

	free_ht(super);
	free_segment_header_array(super);

	free_rambuf_pool(super);

	for(i = 0;i < MAX_CACHE_DEVS;i++){
		if(super->metablock_array[i]){
			large_array_free(super->metablock_array[i]);
		}
	}

	plugger_deinit(super);
	degraded_mgr_deinit(super);
}
#endif
