/****************************************************************************
 * SRC (SSD RAID Cache): Device mapper target for block-level disk caching
 * Yongseok Oh (ysoh@uos.ac.kr) 2013 - 2014
 * filename: lru.h 
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

#include <linux/list.h>
#include "metadata.h"

#ifndef _CACHE_H
#define _CACHE_H  

struct lru_node{
	struct list_head cn_list;
	struct list_head cn_write_list;
	struct hlist_node cn_hash;
	struct page *cn_page;

	sector_t cn_blkno;
	u32 crc32;
	int cn_read_hit;
	int cn_write_hit;
	int cn_read_ref;
	int cn_write_ref;
	int cn_alloc_by_gc;
	atomic_t sealed;
	atomic_t locked;
};

struct cache_manager{
 spinlock_t lock;
 struct list_head cm_head;
 struct list_head cm_free_head;
 struct large_array *cm_hash;
 struct large_array *cm_cache;

 unsigned int cm_hit;
 unsigned int cm_miss;
 unsigned int cm_ref;
 unsigned int cm_read_hit;
 unsigned int cm_read_ref;

atomic_t cm_sealed_count;

 int cm_size; 
 int cm_free;
 int cm_count;
 int cm_min;
 char *cm_name;

 int cm_lowwater;
 int cm_highwater;

 void (*cache_open)(struct cache_manager *cache,int cache_size);
 void (*cache_close)(struct cache_manager *cache);
 struct lru_node *(*cache_presearch)(struct cache_manager *cache, sector_t blkno);
 struct lru_node *(*cache_search)(struct cache_manager *cache, sector_t blkno);
 void *(*cache_replace)(struct cache_manager *cache, int w); 
 void *(*cache_remove)(struct cache_manager *cache, struct lru_node *ln); 
 void (*cache_move_mru)(struct cache_manager *cache, struct lru_node *ln); 
 void (*cache_insert)(struct cache_manager *cache, struct lru_node *node);
 void *(*cache_alloc)(struct cache_manager *cache, struct lru_node *node, sector_t blkno);
 int (*cache_inc)(struct cache_manager *cache, int i);
 int (*cache_dec)(struct cache_manager *cache, int i);
};

#define CACHE_OPEN(c, sz) c->cache_open((struct cache_manager *)c, sz)
#define CACHE_CLOSE(c ) c->cache_close((struct cache_manager *)c)
#define CACHE_PRESEARCH(c, p) c->cache_presearch((struct cache_manager *)c, p)
#define CACHE_SEARCH(c, p) c->cache_search((struct cache_manager *)c, p)
#define CACHE_REPLACE(c, w) c->cache_replace((struct cache_manager *)c, w)
#define CACHE_MOVEMRU(c, w) c->cache_move_mru((struct cache_manager *)c, w)
#define CACHE_REMOVE(c, p) c->cache_remove((struct cache_manager *)c, p)
#define CACHE_INSERT(c, p) c->cache_insert((struct cache_manager *)c, p)
#define CACHE_ALLOC(c, n, p) c->cache_alloc(c, n, p)
#define CACHE_PRINT(c, p) c->cache_print((struct cache_manager *)c, p)


void lru_open(struct cache_manager *c,int cache_size);
void lru_close(struct cache_manager *c);
struct lru_node *lru_presearch(struct cache_manager *c, sector_t blkno);
struct lru_node *lru_search(struct cache_manager *c, sector_t blkno);
void *lru_remove(struct cache_manager *c, struct lru_node *ln);
void *lru_alloc(struct cache_manager *c, struct lru_node *ln, sector_t blkno);
void lru_insert(struct cache_manager *c,struct lru_node *ln);
void *lru_replace(struct cache_manager *c, int watermark);	
void lru_init(struct cache_manager **c,char *name, int size,int high,int low);
void lru_deinit(struct cache_manager *lru_manager);
void lru_move_clean_list ( struct cache_manager *c, struct lru_node *ln );

#if 0
struct lru_node *mlru_search(struct cache_manager **lru_manager,int lru_num, int blkno, int insert,int hit, int *hit_position);
void mlru_remove(struct cache_manager **lru_manager,int lru_num, int blkno);
struct cache_manager **mlru_init(char *name,int lru_num, int total_size);
void mlru_exit(struct cache_manager **lru_manager,int lru_num);
#endif 

#endif 
