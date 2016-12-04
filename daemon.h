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

#ifndef DM_SRC_DAEMON_H
#define DM_SRC_DAEMON_H

//#define NO_CLEAN_COPY
#define HOT_DATA_COPY

//#define FORCE_UMAX

struct merge_req_t{
	struct dm_io_region o_region;
	struct dm_io_region c_region;
	struct list_head list;
};

/*----------------------------------------------------------------*/

int flush_meta_proc(void *);

/*----------------------------------------------------------------*/

void queue_barrier_io(struct dmsrc_super *, struct bio *);
void barrier_deadline_proc(unsigned long data);
void flush_barrier_ios(struct work_struct *);
void do_read_caching_worker(struct work_struct *ws);

/*----------------------------------------------------------------*/

int migrate_proc(void *);
void wait_for_migration(struct dmsrc_super *, u64 id);

/*----------------------------------------------------------------*/

int modulator_proc(void *);

/*----------------------------------------------------------------*/

void schedule_sync_proc(unsigned long data);
void sync_proc(struct work_struct *work);

/*----------------------------------------------------------------*/

int recorder_proc(void *);

/*----------------------------------------------------------------*/

int checker_proc(void *);

void pending_worker(struct work_struct *work);
void do_mig_worker(struct work_struct *work);
void issue_deferred_bio(struct dmsrc_super *super, struct bio_list *);
void read_caching_make_job(struct dmsrc_super *super, struct segment_header *seg, struct metablock *mb, struct bio *bio, struct rambuffer *rambuf);
void read_callback(unsigned long error, void *context);
void start_recovery(struct dmsrc_super *super);
int recovery_proc(void *data);
void do_recovery_worker(struct work_struct *work);
void gen_summary_io(struct dmsrc_super *super, struct segment_header *seg, 
		struct rambuffer *rambuf,
		u32 idx,
		u32 mem_idx);

void gen_partial_summary_io(struct dmsrc_super *super, struct segment_header *seg, 
		struct rambuffer *rambuf);

void plug_deadline_proc(unsigned long data);
void update_plug_deadline(struct dmsrc_super *super);
void plug_proc(struct work_struct *work);
int flush_plug_proc(struct dmsrc_super *super, 
		struct segment_header *seg, 
		struct rambuffer *rambuf, 
		atomic_t *bios_start,
		atomic_t *bios_count,
		int force, 
		int devno, 
		int group_sealed);
void flush_kcopy_job(struct dmsrc_super *super, struct copy_job_group *cp_job_group);
void flush_segmd_endio(unsigned long error, void *context);
struct segment_header *select_victim_greedy_cold(struct dmsrc_super *super, int use_gc);
struct group_header *select_victim_greedy(struct dmsrc_super *super, int use_gc);
void finalize_clean_seg(struct dmsrc_super *super, struct segment_header *seg, int cleanup);
int get_metadata_count(struct dmsrc_super *super, int seg_type);
void check_plug_proc(struct dmsrc_super *super, 
		struct segment_header *seg, 
		struct rambuffer *rambuf, 
		int force, 
		int devno);
void clean_empty_seg(struct dmsrc_super *super, int use_gc);
int get_data_max_count(struct dmsrc_super *super, int seg_type);
int get_data_valid_count(struct dmsrc_super *super, struct segment_header *seg);
int calc_meta_count(struct dmsrc_super *super, struct segment_header *seg);
int calc_valid_count(struct dmsrc_super *super, struct segment_header *seg, int use_gc);
void seg_write_worker(struct work_struct *work);
/*----------------------------------------------------------------*/

/* Stopping Daemons */

/*
 * Daemons should not be terminated in blockup situation.
 * They should be actually terminated in calling .dtr routine
 * since there generally should be no more than two path
 * for terminating sole thing.
 */

/*
 * flush daemon and migrate daemon stopped in blockup
 * could cause lockup in calling .dtr since it demands
 * .postsuspend to flush transient data called beforehand
 * and these daemons related to I/O execution should
 * not be stopped therefor.
 */


/*----------------------------------------------------------------*/

#endif
