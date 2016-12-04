/****************************************************************************
 * SRC (SSD RAID Cache): Device mapper target for block-level disk caching
 * Yongseok Oh (ysoh@uos.ac.kr) 2013 - 2014
 * filename: alloc.h
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

#ifndef DM_ALLOC_H
#define DM_ALLOC_H


/* ported from linux-3.13.6/drivers/md/raid5.c */

/*
 * Our supported algorithms
 */
#define ALGORITHM_LEFT_ASYMMETRIC	0 /* Rotating Parity N with Data Restart */
#define ALGORITHM_RIGHT_ASYMMETRIC	1 /* Rotating Parity 0 with Data Restart */
#define ALGORITHM_LEFT_SYMMETRIC	2 /* Rotating Parity N with Data Continuation */
#define ALGORITHM_RIGHT_SYMMETRIC	3 /* Rotating Parity 0 with Data Continuation */

/* Define non-rotating (raid4) algorithms.  These allow
 * conversion of raid4 to raid5.
 */
#define ALGORITHM_PARITY_0		4 /* P or P,Q are initial devices */
#define ALGORITHM_PARITY_N		5 /* P or P,Q are final devices. */

/* DDF RAID6 layouts differ from md/raid6 layouts in two ways.
 * Firstly, the exact positioning of the parity block is slightly
 * different between the 'LEFT_*' modes of md and the "_N_*" modes
 * of DDF.
 * Secondly, or order of datablocks over which the Q syndrome is computed
 * is different.
 * Consequently we have different layouts for DDF/raid6 than md/raid6.
 * These layouts are from the DDFv1.2 spec.
 * Interestingly DDFv1.2-Errata-A does not specify N_CONTINUE but
 * leaves RLQ=3 as 'Vendor Specific'
 */

#define ALGORITHM_ROTATING_ZERO_RESTART	8 /* DDF PRL=6 RLQ=1 */
#define ALGORITHM_ROTATING_N_RESTART	9 /* DDF PRL=6 RLQ=2 */
#define ALGORITHM_ROTATING_N_CONTINUE	10 /*DDF PRL=6 RLQ=3 */


/* For every RAID5 algorithm we define a RAID6 algorithm
 * with exactly the same layout for data and parity, and
 * with the Q block always on the last device (N-1).
 * This allows trivial conversion from RAID5 to RAID6
 */
#define ALGORITHM_LEFT_ASYMMETRIC_6	16
#define ALGORITHM_RIGHT_ASYMMETRIC_6	17
#define ALGORITHM_LEFT_SYMMETRIC_6	18
#define ALGORITHM_RIGHT_SYMMETRIC_6	19
#define ALGORITHM_PARITY_0_6		20
#define ALGORITHM_PARITY_N_6		ALGORITHM_PARITY_N



int multi_allocator_init(struct dmsrc_super *super);
int ma_reset(struct dmsrc_super *wb, u64 seg_id, int cache_type);
u32 ma_alloc(struct dmsrc_super *wb, struct segment_header *seg, u64 seg_id, int cache_type, 
																		int devno, u32 *cur_count);
u32 ma_select_dev(struct dmsrc_super *wb, sector_t sector, int cache_type);
u32 ma_get_count(struct dmsrc_super *wb, int cache_type);
void ma_set_count(struct dmsrc_super *wb, int cache_type, int count);

int cursor_start(struct dmsrc_super *wb, u64 seg_id);
sector_t raid5_calc_sector(struct r5conf *conf, sector_t r_sector,
				     int previous, int *dd_idx, int *p_disk, int *q_disk);
inline u32 ma_get_per_log_count(struct dmsrc_super *wb, sector_t sector, int cache_type);
int dev_start(struct dmsrc_super *super, u64 seg_id);
int get_num_empty_chunks(struct dmsrc_super *super, int cache_type);
inline u32 ma_get_count_per_dev(struct dmsrc_super *super, int cache_type, int devno);
void multi_allocator_deinit(struct dmsrc_super *super);
inline u32 ma_get_row_count(struct dmsrc_super *super, int cache_type, int row);
void group_reserve_empty_chunk(struct dmsrc_super *super, u32 group_id, int cache_type);
inline u32 ma_get_free(struct dmsrc_super *super, int cache_type);

#endif
