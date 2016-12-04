/****************************************************************************
 * SRC (SSD RAID Cache): Device mapper target for block-level disk caching
 * Yongseok Oh (ysoh@uos.ac.kr) 2013 - 2014
 * filename: alloc.c
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

#include <linux/buffer_head.h>
#include <linux/dmaengine.h>
#include <linux/raid/xor.h>
#include <linux/raid/pq.h>
#include <linux/dm-kcopyd.h>
#include <linux/blkdev.h>
#include <linux/sched.h>
#include <linux/delay.h>
#include <linux/crc32.h>
#include <linux/gfp.h>
#include <linux/random.h>
#include "target.h"
#include "alloc.h"
#include "metadata.h"
#include "daemon.h"

#if 0 
int dev_start(struct dmsrc_super *super, u64 seg_id){

	sector_t sector = seg_id * STRIPE_SZ_SECTOR;
	int req_dev;

	if(NO_USE_ERASURE_CODE(&super->param)){
		return 0;
	}else if(USE_ERASURE_PARITY(&super->param)){
		raid5_calc_sector(&super->raid_conf, sector, 0, &req_dev, NULL, NULL);
	}else if(USE_ERASURE_RAID6(&super->param)){
		raid5_calc_sector(&super->raid_conf, sector, 0, &req_dev, NULL, NULL);
	}
	return req_dev;
}


int cursor_start(struct dmsrc_super *super, u64 seg_id){
	int start = dev_start(super, seg_id);
	return start * CHUNK_SZ;
}
#endif

int multi_allocator_init(struct dmsrc_super *super){
	int i, j;

	for(i = 0;i < NBUF;i++){
		for(j = 0;j < MAX_CACHE_DEVS;j++)
			spin_lock_init(&super->ma[i].lock[j]);

		super->ma[i].row_count = kmalloc(sizeof(atomic_t) * CHUNK_SZ, GFP_KERNEL | __GFP_ZERO);
		if(super->ma[i].row_count==NULL){
			return -1;
		}
	}

	return 0;
}

void multi_allocator_deinit(struct dmsrc_super *super){
	int i;

	for(i = 0;i < NBUF;i++){
		kfree(super->ma[i].row_count);	
	}
}

int get_num_empty_chunks(struct dmsrc_super *super, int cache_type){
	struct multi_allocator *ma = &super->ma[cache_type];
	int count = 0;
	int i;

	for(i = 0;i < NUM_SSD;i++){
		if(ma->seg_empty_chunk_map[cache_type][i])
			count++;
	}
	return count;
}

void group_reserve_empty_chunk(struct dmsrc_super *super, u32 group_id, int cache_type){
	struct multi_allocator *ma = &super->ma[cache_type];
	int i;
	int reserved_chunks;
	struct group_header *group = &super->group_header_array[group_id];

	for(i = 0;i < NUM_SSD;i++){
		ma->group_empty_chunk_map[cache_type][i] = 0;
	}

	// reserve parity blocks 
	if(is_write_stripe(cache_type) && USE_ERASURE_CODE(&super->param)){
		ma->group_empty_chunk_map[cache_type][get_parity_ssd(super, group_id)] = 1;
		//printk(" group = %d parity ssd = %d ", group_id, get_parity_ssd(super, group_id));
	}

	if(super->param.hot_identification){
		// reserve empty blocks 
		if(//cache_type == WHBUF && 
			(super->param.data_allocation==DATA_ALLOC_FLEX_VERT || 
			 super->param.data_allocation==DATA_ALLOC_FLEX_HORI)){
			reserved_chunks = NUM_SSD - calc_need_num_ssds(super);
			if(reserved_chunks==NUM_DATA_SSD){
			//	printk(" group reserve no bandwidth ....\n");
				reserved_chunks = NUM_DATA_SSD-1;
			}

		}else{
			reserved_chunks = 0;
		}
	}else{
		if(//(cache_type == WHBUF||cache_type==WCBUF||cache_type==GWBUF) && 
			(super->param.data_allocation==DATA_ALLOC_FLEX_VERT || 
			 super->param.data_allocation==DATA_ALLOC_FLEX_HORI))
		{
			reserved_chunks = NUM_SSD - calc_need_num_ssds(super);
			if(reserved_chunks==NUM_DATA_SSD){
			//	printk(" group reserve no bandwidth ....\n");
				reserved_chunks = NUM_DATA_SSD-1;
			}
		}else{
			reserved_chunks = 0;
		}
	}

	//printk(" need ssd = %d \n", NUM_SSD - reserved_chunks + 1);
	//if(reserved_chunks==NUM_DATA_SSD){
	//	reserved_chunks = NUM_DATA_SSD-1;
	//}
	//reserved_chunks = 1;
	//{struct migration_manager *migrate_mgr = &super->migrate_mgr;
	//if(atomic_read(&migrate_mgr->copy_job_count)){
	//	printk(" Copy job = %d MB/s\n", atomic_read(&migrate_mgr->copy_job_count)/256);
	//}}

	if(super->param.data_allocation==DATA_ALLOC_FLEX_VERT || 
			 super->param.data_allocation==DATA_ALLOC_FLEX_HORI){
		atomic_set(&group->num_used_ssd,  NUM_SSD - reserved_chunks);
		atomic_set(&group->skewed_segment, 1);
	}else{
		BUG_ON(1);
		atomic_set(&group->num_used_ssd,  NUM_SSD);
		atomic_set(&group->skewed_segment, 1);
	}

	for(i = 0;i < reserved_chunks;i++){
		u32 ssdno;
		get_random_bytes((void *)&ssdno, sizeof(u32));
		ssdno = ssdno % NUM_SSD;

		if(ssdno == get_parity_ssd(super, group_id) ||
			ma->group_empty_chunk_map[cache_type][ssdno] ){
			i--;
			continue;
		}
		ma->group_empty_chunk_map[cache_type][ssdno] = 1;
		//printk(" reserved empty ssd = %d ", ssdno);
	}
	//printk("\n");
}

void reserve_empty_chunk(struct dmsrc_super *super, u64 seg_id, int cache_type){
	struct multi_allocator *ma = &super->ma[cache_type];
	int i;
	int reserved_chunks;

	for(i = 0;i < NUM_SSD;i++){
		ma->seg_empty_chunk_map[cache_type][i] = 0;
	}

//	if(cache_type == RHBUF && cache_type != RCBUF && cache_type != GRBUF)
//		return;

	// reserve parity blocks 
	if(is_write_stripe(cache_type) && USE_ERASURE_CODE(&super->param)){
		ma->seg_empty_chunk_map[cache_type][get_parity_ssd(super, seg_id)] = 1;
		//printk(" parity ssd = %d ", get_parity_ssd(super, seg_id));
	}

	if(super->param.hot_identification){
		// reserve empty blocks 
		if(cache_type == WHBUF && 
			(super->param.data_allocation==DATA_ALLOC_FLEX_VERT || 
			 super->param.data_allocation==DATA_ALLOC_FLEX_HORI)){
			BUG_ON(1);
			reserved_chunks = NUM_SSD - calc_need_num_ssds(super);
		}else{
			reserved_chunks = 0;
		}
	}else{
		if((cache_type == WHBUF||cache_type==WCBUF||cache_type==GWBUF) && 
			(super->param.data_allocation==DATA_ALLOC_FLEX_VERT || 
			 super->param.data_allocation==DATA_ALLOC_FLEX_HORI)){
			BUG_ON(1);
			reserved_chunks = NUM_SSD - calc_need_num_ssds(super);
		}else{
			reserved_chunks = 0;
		}
	}

	for(i = 0;i < reserved_chunks;i++){
		u32 ssdno;
		get_random_bytes((void *)&ssdno, sizeof(u32));
		ssdno = ssdno % NUM_SSD;

		if(ssdno == get_parity_ssd(super, seg_id) ||
			ma->seg_empty_chunk_map[cache_type][ssdno] ){
			i--;
			continue;
		}
		ma->seg_empty_chunk_map[cache_type][ssdno] = 1;

		//printk(" empty ssd = %d ", ssdno);
	}
	//printk("\n");
}

int ma_reset(struct dmsrc_super *super, u64 seg_id, int cache_type){
	struct multi_allocator *ma = &super->ma[cache_type];
	int cursor;
	int i;
	int chunk_offset;
	unsigned long flags;
	int parity_ssd;
	int stripe_size = 0;

	//printk(" ma reset ... \n");
	atomic_set(&ma->total_count, 0);

	if(super->param.data_allocation==DATA_ALLOC_FLEX_VERT || 
	 super->param.data_allocation==DATA_ALLOC_FLEX_HORI){
		//group_reserve_empty_chunk(super, group->group_id, cache_type);
		for(i = 0;i < NUM_SSD;i++){
			ma->seg_empty_chunk_map[cache_type][i] = 
				ma->group_empty_chunk_map[cache_type][i];
		}
		parity_ssd = get_parity_ssd(super, seg_id/SEGMENT_GROUP_SIZE);
	}else{
		reserve_empty_chunk(super, seg_id, cache_type);
		parity_ssd = get_parity_ssd(super, seg_id);
	}

	if(parity_ssd>=0)
		atomic_set(&ma->cur_dev, parity_ssd);
	else
		atomic_set(&ma->cur_dev, 0);

	for(chunk_offset = 0;chunk_offset < CHUNK_SZ;chunk_offset++)
		atomic_set(&ma->row_count[chunk_offset], 0);

	for(i = 0;i < NUM_SSD;i++){
		if(ma->seg_empty_chunk_map[cache_type][i]){
			atomic_set(&ma->count[i], CHUNK_SZ);
			atomic_add(CHUNK_SZ, &ma->total_count);

			for(chunk_offset = 0;chunk_offset < CHUNK_SZ;chunk_offset++)
				atomic_inc(&ma->row_count[chunk_offset]);

			continue;
		}

		stripe_size += CHUNK_SZ;
		spin_lock_irqsave(&ma->lock[i], flags);
		cursor = i * CHUNK_SZ - 1;
		ma->cursor[i] = cursor;
		atomic_set(&ma->count[i], 0);
		spin_unlock_irqrestore(&ma->lock[i], flags);
	}

	if(is_write_stripe(cache_type) && USE_ERASURE_CODE(&super->param)){
		stripe_size += CHUNK_SZ;
	}

	//printk(" seg = %d, total = %d, type = %d \n", (int)seg_id, (int)atomic_read(&ma->total_count), cache_type);

	return stripe_size;
}

u32 ma_select_dev(struct dmsrc_super *super, sector_t sector, int cache_type){
	int debug = 0;
	struct multi_allocator *ma = &super->ma[cache_type];
	int cur_dev = atomic_read(&ma->cur_dev);
	int allocation_policy = super->param.data_allocation;

	if(allocation_policy==DATA_ALLOC_HORI ||
		allocation_policy==DATA_ALLOC_FLEX_HORI){

	}else if(allocation_policy==DATA_ALLOC_VERT || 
			allocation_policy==DATA_ALLOC_FLEX_VERT){
		if(atomic_read(&ma->count[cur_dev])<CHUNK_SZ)
			return cur_dev;
	}else{
		BUG_ON(1);
	}

Rescan:;

	cur_dev = (atomic_read(&ma->cur_dev) + 1) % NUM_SSD;
	atomic_set(&ma->cur_dev, cur_dev);

	debug++;
	BUG_ON(debug>NUM_SSD);

	if(atomic_read(&ma->count[cur_dev])>=CHUNK_SZ){
		//printk(" rescan ... %d \n", current->pid);
		goto Rescan;
	}

	return cur_dev;
}

u32 ma_alloc(struct dmsrc_super *super, struct segment_header *seg, u64 seg_id, int cache_type, 
		int devno, u32 *cur_count){
	struct multi_allocator *ma = &super->ma[cache_type];
	unsigned long flags;
	u32 cursor;
	u32 count;

	BUG_ON(devno>=NUM_SSD);

	spin_lock_irqsave(&ma->lock[devno], flags);
	cursor = ++(ma->cursor[devno]);

	atomic_inc(&ma->count[devno]);
	atomic_inc(&ma->total_count);
	BUG_ON(atomic_read(&ma->count[devno]) > CHUNK_SZ);

	atomic_inc(&ma->row_count[cursor % CHUNK_SZ]);
	count = atomic_read(&ma->total_count);
	spin_unlock_irqrestore(&ma->lock[devno], flags);

	if(cur_count)
		*cur_count = count;

	if(devno != atomic_read(&ma->cur_dev))
		atomic_set(&ma->cur_dev, devno);

	if(atomic_read(&ma->row_count[cursor % CHUNK_SZ])> NUM_SSD){
		printk(" row count ... \n");
	}
	BUG_ON(atomic_read(&ma->row_count[cursor % CHUNK_SZ])> NUM_SSD);
	if(atomic_read(&ma->total_count) > STRIPE_SZ)
		printk(" total count .. \n");

	BUG_ON(atomic_read(&ma->total_count) > STRIPE_SZ);

	//printk(" pid = %d devno = %d cursor = %d count = %d \n", 
	//		(int)current->pid,
	//		(int)devno,
	//		(int)ma->cursor[devno],
	//		(int)atomic_read(&ma->total_count));

	return SEG_START_IDX(seg) + cursor;
}

inline u32 ma_get_count_per_dev(struct dmsrc_super *super, int cache_type, int devno){
	return  atomic_read(&super->ma[cache_type].count[devno]);
}

inline u32 ma_get_row_count(struct dmsrc_super *super, int cache_type, int row){
	return  atomic_read(&super->ma[cache_type].row_count[row]);
}

inline u32 ma_get_free(struct dmsrc_super *super, int cache_type){
	int i;
	u32 free_blocks = 0;
	u32 row_count = 0;

	for(i = 0;i < CHUNK_SZ-NUM_SUMMARY;i++){
		row_count = ma_get_row_count(super, cache_type, i);
		free_blocks += (NUM_SSD - row_count);
	}
	return free_blocks;
}

inline u32 ma_get_count(struct dmsrc_super *super, int cache_type){
	return  atomic_read(&super->ma[cache_type].total_count);
}

inline void ma_set_count(struct dmsrc_super *super, int cache_type, int count){
	atomic_set(&super->ma[cache_type].total_count, count);
}

/* ported from linux-3.13.6/drivers/md/raid5.c */
/*
 * Input: a 'big' sector number,
 * Output: index of the data and parity disk, and the sector # in them.
 */
sector_t raid5_calc_sector(struct r5conf *conf, sector_t r_sector,
				     int previous, int *dd_idx, int *p_disk, int *q_disk)
{
	sector_t stripe, stripe2;
	sector_t chunk_number;
	unsigned int chunk_offset;
	int pd_idx, qd_idx;
	int ddf_layout = 0;
	sector_t new_sector;
	int algorithm = previous ? conf->prev_algo
				 : conf->algorithm;
	int sectors_per_chunk = previous ? conf->prev_chunk_sectors
					 : conf->chunk_sectors;
	int raid_disks = previous ? conf->previous_raid_disks
				  : conf->raid_disks;
	int data_disks = raid_disks - conf->max_degraded;

	/* First compute the information on this sector */

	/*
	 * Compute the chunk number and the sector offset inside the chunk
	 */
	chunk_offset = sector_div(r_sector, sectors_per_chunk);
	chunk_number = r_sector;

	/*
	 * Compute the stripe number
	 */
	stripe = chunk_number;
	*dd_idx = sector_div(stripe, data_disks);
	stripe2 = stripe;
	/*
	 * Select the parity disk based on the user selected algorithm.
	 */
	pd_idx = qd_idx = -1;
	switch(conf->level) {
	case 4:
		pd_idx = data_disks;
		break;
	case 5:
		switch (algorithm) {
		case ALGORITHM_LEFT_ASYMMETRIC:
			pd_idx = data_disks - sector_div(stripe2, raid_disks);
			if (*dd_idx >= pd_idx)
				(*dd_idx)++;
			break;
		case ALGORITHM_RIGHT_ASYMMETRIC:
			pd_idx = sector_div(stripe2, raid_disks);
			if (*dd_idx >= pd_idx)
				(*dd_idx)++;
			break;
		case ALGORITHM_LEFT_SYMMETRIC:
			pd_idx = data_disks - sector_div(stripe2, raid_disks);
			*dd_idx = (pd_idx + 1 + *dd_idx) % raid_disks;
			break;
		case ALGORITHM_RIGHT_SYMMETRIC:
			pd_idx = sector_div(stripe2, raid_disks);
			*dd_idx = (pd_idx + 1 + *dd_idx) % raid_disks;
			break;
		case ALGORITHM_PARITY_0:
			pd_idx = 0;
			(*dd_idx)++;
			break;
		case ALGORITHM_PARITY_N:
			pd_idx = data_disks;
			break;
		default:
			BUG();
		}
		break;
	case 6:

		switch (algorithm) {
		case ALGORITHM_LEFT_ASYMMETRIC:
			pd_idx = raid_disks - 1 - sector_div(stripe2, raid_disks);
			qd_idx = pd_idx + 1;
			if (pd_idx == raid_disks-1) {
				(*dd_idx)++;	/* Q D D D P */
				qd_idx = 0;
			} else if (*dd_idx >= pd_idx)
				(*dd_idx) += 2; /* D D P Q D */
			break;
		case ALGORITHM_RIGHT_ASYMMETRIC:
			pd_idx = sector_div(stripe2, raid_disks);
			qd_idx = pd_idx + 1;
			if (pd_idx == raid_disks-1) {
				(*dd_idx)++;	/* Q D D D P */
				qd_idx = 0;
			} else if (*dd_idx >= pd_idx)
				(*dd_idx) += 2; /* D D P Q D */
			break;
		case ALGORITHM_LEFT_SYMMETRIC:
			pd_idx = raid_disks - 1 - sector_div(stripe2, raid_disks);
			qd_idx = (pd_idx + 1) % raid_disks;
			*dd_idx = (pd_idx + 2 + *dd_idx) % raid_disks;
			break;
		case ALGORITHM_RIGHT_SYMMETRIC:
			pd_idx = sector_div(stripe2, raid_disks);
			qd_idx = (pd_idx + 1) % raid_disks;
			*dd_idx = (pd_idx + 2 + *dd_idx) % raid_disks;
			break;

		case ALGORITHM_PARITY_0:
			pd_idx = 0;
			qd_idx = 1;
			(*dd_idx) += 2;
			break;
		case ALGORITHM_PARITY_N:
			pd_idx = data_disks;
			qd_idx = data_disks + 1;
			break;

		case ALGORITHM_ROTATING_ZERO_RESTART:
			/* Exactly the same as RIGHT_ASYMMETRIC, but or
			 * of blocks for computing Q is different.
			 */
			pd_idx = sector_div(stripe2, raid_disks);
			qd_idx = pd_idx + 1;
			if (pd_idx == raid_disks-1) {
				(*dd_idx)++;	/* Q D D D P */
				qd_idx = 0;
			} else if (*dd_idx >= pd_idx)
				(*dd_idx) += 2; /* D D P Q D */
			ddf_layout = 1;
			break;

		case ALGORITHM_ROTATING_N_RESTART:
			/* Same a left_asymmetric, by first stripe is
			 * D D D P Q  rather than
			 * Q D D D P
			 */
			stripe2 += 1;
			pd_idx = raid_disks - 1 - sector_div(stripe2, raid_disks);
			qd_idx = pd_idx + 1;
			if (pd_idx == raid_disks-1) {
				(*dd_idx)++;	/* Q D D D P */
				qd_idx = 0;
			} else if (*dd_idx >= pd_idx)
				(*dd_idx) += 2; /* D D P Q D */
			ddf_layout = 1;
			break;

		case ALGORITHM_ROTATING_N_CONTINUE:
			/* Same as left_symmetric but Q is before P */
			pd_idx = raid_disks - 1 - sector_div(stripe2, raid_disks);
			qd_idx = (pd_idx + raid_disks - 1) % raid_disks;
			*dd_idx = (pd_idx + 1 + *dd_idx) % raid_disks;
			ddf_layout = 1;
			break;

		case ALGORITHM_LEFT_ASYMMETRIC_6:
			/* RAID5 left_asymmetric, with Q on last device */
			pd_idx = data_disks - sector_div(stripe2, raid_disks-1);
			if (*dd_idx >= pd_idx)
				(*dd_idx)++;
			qd_idx = raid_disks - 1;
			break;

		case ALGORITHM_RIGHT_ASYMMETRIC_6:
			pd_idx = sector_div(stripe2, raid_disks-1);
			if (*dd_idx >= pd_idx)
				(*dd_idx)++;
			qd_idx = raid_disks - 1;
			break;

		case ALGORITHM_LEFT_SYMMETRIC_6:
			pd_idx = data_disks - sector_div(stripe2, raid_disks-1);
			*dd_idx = (pd_idx + 1 + *dd_idx) % (raid_disks-1);
			qd_idx = raid_disks - 1;
			break;

		case ALGORITHM_RIGHT_SYMMETRIC_6:
			pd_idx = sector_div(stripe2, raid_disks-1);
			*dd_idx = (pd_idx + 1 + *dd_idx) % (raid_disks-1);
			qd_idx = raid_disks - 1;
			break;

		case ALGORITHM_PARITY_0_6:
			pd_idx = 0;
			(*dd_idx)++;
			qd_idx = raid_disks - 1;
			break;

		default:
			BUG();
		}
		break;
	}

	//if (sh) {
	//	sh->pd_idx = pd_idx;
	//	sh->qd_idx = qd_idx;
	//	sh->ddf_layout = ddf_layout;
	//}
	/*
	 * Finally, compute the new sector number
	 */
	if(p_disk)
		*p_disk = pd_idx;

	if(q_disk)
		*q_disk = qd_idx;

	new_sector = (sector_t)stripe * sectors_per_chunk + chunk_offset;
	return new_sector;
}

#if 0
int sa_init(struct dmsrc_super *super, u64 seg_id, int cache_type){
	struct single_allocator *sa = &super->sa[cache_type];
	int cursor;
	unsigned long flags;

	spin_lock_irqsave(&sa->lock, flags);

	if(super->param->data_allocation==DATA_ALLOC_VERT){
		cursor = cursor_start(super, seg_id) - 1;
	}else{

		if(super->param->parity_allocation==PARITY_ALLOC_FIXED)
			sa->col = NR_SSD-1;
		else
			sa->col = ((seg_id%NR_SSD) + (NR_SSD-1)) % NR_SSD;

		sa->row = -1;

		cursor = cursor_start(super, seg_id) - 1;
	}

	sa->cursor = cursor;
	atomic_set(&sa->count, 0);
	spin_unlock_irqrestore(&sa->lock, flags);

	return 0;
}

u32 sa_alloc_horizontal(struct dmsrc_super *super, u64 seg_id, int cache_type){
	u32 col, row;
	u32 start_ssd;
	u32 parity_ssd;
	u32 next;

	start_ssd = get_start_ssd(super, seg_id);

	col = super->sa[cache_type].col;
	row = super->sa[cache_type].row; 
	col = (col + 1) % NR_SSD;

	if(USE_ERASURE_CODE(super->param)){

		parity_ssd = get_parity_ssd(super, seg_id);

		if(col==parity_ssd ||
				(super->param->erasure_code==ERASURE_CODE_RAID6 && 
				 col == (parity_ssd+1)%NR_SSD)){
			while(col!=start_ssd){
				col = (col + 1) % NR_SSD;
			}
		}
	}

	if(col==start_ssd)
		row++;

	next = col * CHUNK_SZ + row;
	next %= STRIPE_SZ;

	super->sa[cache_type].col = col;
	super->sa[cache_type].row = row;
	return next;
}


u32 sa_alloc(struct dmsrc_super *super, struct segment_header *seg, u64 seg_id, int cache_type, u32 *cur_count){
	struct single_allocator *sa = &super->sa[cache_type];
	unsigned long flags;
	u32 next;
	u32 idx;
	u32 count;

	spin_lock_irqsave(&sa->lock, flags);

	if(super->param->data_allocation==DATA_ALLOC_VERT)
		div_u64_rem(super->sa[cache_type].cursor + 1, NR_CACHES_INSEG, &next);
	else 
		next = sa_alloc_horizontal(super, seg_id, cache_type);

	super->sa[cache_type].cursor = next;

	atomic_inc(&super->sa[cache_type].count);
	count = atomic_read(&super->sa[cache_type].count);
	if(cur_count)
		*cur_count = count;
	BUG_ON(count > NR_CACHES_INSEG);

	idx = SEG_START_IDX(seg) + super->sa[cache_type].cursor;
	spin_unlock_irqrestore(&sa->lock, flags);

	//printk(" pid = %d cursor = %d count = %d \n", 
	//		(int)current->pid,
	//		(int)idx,
	//		(int)count);

	return idx;
}

inline u32 sa_get_count(struct dmsrc_super *super, int cache_type){
	return  atomic_read(&super->sa[cache_type].count);
}
#endif 
