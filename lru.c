/****************************************************************************
 * SRC (SSD RAID Cache): Device mapper target for block-level disk caching
 * Yongseok Oh (ysoh@uos.ac.kr) 2013 - 2014
 * filename: lru.c
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

#include "target.h"
#include "metadata.h"
#include "lru.h"
#include <linux/string.h>
#include <linux/list.h>

#define ASSERT assert

void lru_open(struct cache_manager *c,int cache_size){
	int i;

	INIT_LIST_HEAD ( &c->cm_head );
	INIT_LIST_HEAD ( &c->cm_free_head );

	c->cm_ref = 0;
	c->cm_hit = 0;
	c->cm_miss = 0;
	c->cm_size = cache_size;
	c->cm_free = cache_size;
	c->cm_count = 0;
	atomic_set(&c->cm_sealed_count, 0);

	c->cm_hash = large_array_alloc(sizeof(struct hlist_head), cache_size);
	if(c->cm_hash == NULL){
		printk(" Malloc Error %s %d \n",__FUNCTION__,__LINE__);
		BUG_ON(1);
	}

	for(i = 0;i < cache_size;i++){
		struct hlist_head *hash;
		hash = (struct hlist_head *)large_array_at(c->cm_hash, (u64)i);
		INIT_HLIST_HEAD ( hash );
	}

	c->cm_cache = large_array_alloc(sizeof(struct lru_node), cache_size);
	if(c->cm_cache == NULL){
		printk(" Malloc Error %s %d \n",__FUNCTION__,__LINE__);
		BUG_ON(1);
	}

	for(i=0;i<cache_size;i++){
		struct lru_node *ln;
		ln = large_array_at(c->cm_cache, i);
		if(!ln)
			continue;

		memset((void *)ln, 0x00, sizeof(struct lru_node));
		list_add( &ln->cn_list, &c->cm_free_head );

		ln->cn_page = alloc_page(__GFP_NOWARN | __GFP_NORETRY);
		if(!ln->cn_page){
			printk(" alloc page Error %s %d \n",__FUNCTION__,__LINE__);
			BUG_ON(1);
		}
	}
}



void lru_close(struct cache_manager *c){
	struct lru_node *ln, *temp;

	list_for_each_entry_safe(ln, temp, &c->cm_head, cn_list){
		__free_page(ln->cn_page);
		list_del ( & ln->cn_list );
		hlist_del ( & ln->cn_hash );
	}

	list_for_each_entry_safe(ln, temp, &c->cm_free_head, cn_list){
		__free_page(ln->cn_page);
		list_del ( & ln->cn_list );
	}

	BUG_ON ( !list_empty ( &c->cm_head ) );
	BUG_ON ( !list_empty ( &c->cm_free_head ) );

	large_array_free(c->cm_hash);
	large_array_free(c->cm_cache);
}

struct lru_node *lru_presearch(struct cache_manager *c, sector_t blkno){
	struct hlist_node *node;
	struct hlist_head *head;
	struct lru_node *ln;
	
	head = (struct hlist_head *)large_array_at(c->cm_hash, blkno%c->cm_size);
	hlist_for_each ( node, head ) {
		ln = hlist_entry( node,  struct lru_node, cn_hash );
		if ( ln->cn_blkno == blkno ) 
			return ln;
	}

	return NULL;
}


struct lru_node *lru_search(struct cache_manager *c, sector_t blkno){
	struct lru_node *ln;
		
	c->cm_ref++;
	ln = lru_presearch ( c, blkno );
	if(ln){
		c->cm_hit++;
		return ln;
	}else{
		c->cm_miss++;
	}	

	return NULL;
}


void lru_movemru(struct cache_manager *c, struct lru_node *ln ) {
	list_del ( &ln->cn_list );
	list_add( &ln->cn_list, &c->cm_head );
}

void *lru_remove(struct cache_manager *c, struct lru_node *ln ) {
	list_del ( &ln->cn_list );
	hlist_del ( &ln->cn_hash );

	c->cm_free++;
	c->cm_count--;
	return (void *)ln;
}


void *lru_alloc(struct cache_manager *c, struct lru_node *ln, sector_t blkno){
	void *ptr;
	if(ln == NULL){
		ln = list_first_entry( &c->cm_free_head, struct lru_node, cn_list);
		list_del(&ln->cn_list);
	}

	ptr = ln->cn_page;
	memset((void *)ln, 0x00, sizeof(struct lru_node));
	ln->cn_page = ptr;
	
	ln->cn_blkno = blkno;	
	return ln;
}

void lru_insert(struct cache_manager *c,struct lru_node *ln){
	struct hlist_head *hash;

	list_add( &ln->cn_list, &c->cm_head );

	hash = large_array_at(c->cm_hash, (ln->cn_blkno) % c->cm_size);
	hlist_add_head( &ln->cn_hash, hash ) ; 

	c->cm_free--;
	c->cm_count++;
}


void *lru_replace(struct cache_manager *c, int watermark){	
	struct list_head *remove_ptr;
	struct lru_node *victim = NULL;

	if ( c->cm_free < watermark + 1 ) {
		remove_ptr = (struct list_head *)(&c->cm_head)->prev;
		victim = list_entry ( remove_ptr, struct lru_node, cn_list );
		victim = CACHE_REMOVE(c, victim);
	}

	return victim;
}

void lru_init(struct cache_manager **c,char *name, int size,int high,int low){
	*c = (struct cache_manager *)kmalloc(sizeof(struct cache_manager), GFP_KERNEL);
	if(*c == NULL){
		printk(" Malloc Error %s %d \n",__FUNCTION__,__LINE__);
		BUG_ON(1);
		//fprintf(stderr, " Malloc Error %s %d \n",__FUNCTION__,__LINE__);
		//exit(1);
	}
	memset(*c, 0x00, sizeof(struct cache_manager));

	spin_lock_init(&((*c)->lock));

	(*c)->cache_open = lru_open;
	(*c)->cache_close = lru_close;
	(*c)->cache_presearch = lru_presearch;
	(*c)->cache_search = lru_search;
	(*c)->cache_replace = lru_replace;
	(*c)->cache_remove = lru_remove;
	(*c)->cache_move_mru = lru_movemru;
	(*c)->cache_insert = lru_insert;
	(*c)->cache_alloc = lru_alloc;

	CACHE_OPEN((*c), size);

	(*c)->cm_lowwater = low;
	(*c)->cm_highwater = high;
}

void lru_deinit(struct cache_manager *lru_manager){
	CACHE_CLOSE(lru_manager);
	kfree(lru_manager);
}

#if 0
struct lru_node *m_lru_insert(struct cache_manager **lru_manager, int k, int blkno){
	struct lru_node *ln;
	int j;

	for(j = k;j > 0;j--){
		struct lru_node *victim_ln;
		victim_ln = CACHE_REPLACE(lru_manager[j], 0);
		if(victim_ln){		
			kfree(victim_ln);
		}

		victim_ln = CACHE_REPLACE(lru_manager[j-1], 0);
		if(victim_ln){			
			CACHE_INSERT(lru_manager[j], victim_ln);
		}
	}

	ln = CACHE_ALLOC(lru_manager[0], NULL, blkno);
	
	CACHE_INSERT(lru_manager[0], ln);

	return ln;
}


struct cache_manager **mlru_init(char *name,int lru_num, int total_size){
	struct cache_manager **lru_manager;
	char str[128];	
	int i;
	//int j;

	lru_manager = (struct cache_manager **)kmalloc(sizeof(struct cache_manager *) * lru_num, GFP_KERNEL);
	if(lru_manager == NULL){
		printk(" Malloc Error %s %d \n",__FUNCTION__,__LINE__);
		BUG_ON(1);
		//exit(1);
	}
	memset(lru_manager, 0x00, sizeof(struct cache_manager *) * lru_num); 


	if(total_size%lru_num){
		//fprintf(stderr, " remainder of total %d / lrunum %d exists\n", total_size, lru_num);
	}
	for(i = 0;i < lru_num;i++){
		//sprintf(str,"%s%d", name, i);
		lru_init(&lru_manager[i],str, total_size/lru_num,  1, 0);
	}

	return lru_manager;
}

void mlru_exit(struct cache_manager **lru_manager,int lru_num){
	int i;

	int mlru_hit = 0;

	for(i = 0;i < lru_num;i++){		

		mlru_hit += lru_manager[i]->cm_hit;
		CACHE_CLOSE(lru_manager[i]);

		//printf(" %d Multi LRU Hit Ratio = %f \n", i, (float)mlru_hit/lru_manager[0]->cm_ref);
	}

}



void mlru_remove(struct cache_manager **lru_manager,int lru_num, int blkno){
//	listnode *node = NULL;
	struct lru_node *ln=NULL;	
	int j;

	for(j = 0;j < lru_num;j++){
		ln = CACHE_SEARCH(lru_manager[j], blkno);
		if(ln){			
			break;
		}
	}

	if(ln){ 	
		ln = CACHE_REMOVE(lru_manager[j], ln);
		kfree(ln);
	}
	
}

struct lru_node *mlru_search(struct cache_manager **lru_manager,int lru_num, int blkno, int insert,int hit, int *hit_position){
	struct lru_node *ln=NULL;	
	int j;

	for(j = 0;j < lru_num;j++){
		ln = CACHE_SEARCH(lru_manager[j], blkno);

		if ( hit_position )
			*hit_position = j;

		if(ln){
			break;
		}
	}

	//if(ln){		
		//ln =(struct lru_node *) node->data;
		//if(ln->cn_frequency > 1)
		//	ln = ln;
	//}

	//if ( j > 0 && j < lru_num ) {
	//	printf (" hit position = %d \n");
	//}
	if(!hit){
		lru_manager[0]->cm_ref--;
		if(ln){			
			lru_manager[j]->cm_hit--;
		}
	}

	if(!insert){		
		return ln;
	}

	if(!ln){ // miss
		ln = m_lru_insert(lru_manager, lru_num - 1, blkno);
	}else{ // hit 
		ln = CACHE_REMOVE(lru_manager[j], ln);
		kfree(ln);
		ln = m_lru_insert(lru_manager, j, blkno);
	}

	return ln;
}

#endif 
