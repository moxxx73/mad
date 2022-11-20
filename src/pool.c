#include "pool.h"

#include <stdio.h>
#include <errno.h>

POOL *mempool = NULL;

void free_pool(void){
	MEMOBJ *mem_ptr = NULL, *save = NULL;
	fprintf(stderr, "Cleaning up...\n");
	if(mempool){
		if(mempool->alloc_hd){
			mem_ptr = mempool->alloc_hd;
			while(mem_ptr){
				if(mem_ptr->ptr && mem_ptr->cleaner){
					//printf("free_pool(): Freeing %p\n", mem_ptr->ptr);
					mem_ptr->cleaner(mem_ptr->ptr);
				}
				save = mem_ptr->fw;
				memset(mem_ptr, 0, sizeof(MEMOBJ));
				free(mem_ptr);
				mem_ptr = save;
			}
		}
		memset(mempool, 0, sizeof(POOL));
		free(mempool);
		mempool = NULL;
	}
	return;
}

void init_pool(void){
	mempool = (POOL *)malloc(sizeof(POOL));
	if(!mempool) return;
	memset(mempool, 0, sizeof(POOL));
	if(!(mempool->alloc_hd = (MEMOBJ *)malloc(sizeof(MEMOBJ)))){
		free(mempool);
		return;
	}
	memset(mempool->alloc_hd, 0, sizeof(MEMOBJ));
	atexit(&free_pool);
	return;
}

void *import_ptr(void *ptr, void (*cleaner)(void *)){
	MEMOBJ *mem_ptr = NULL;
	if(!mempool || !ptr || !cleaner) return NULL;
	if(mempool->alloc_hd){
		mem_ptr = mempool->alloc_hd;
		for(; mem_ptr->fw; mem_ptr = mem_ptr->fw);
		
		mem_ptr->fw = (MEMOBJ *)malloc(sizeof(MEMOBJ));
		if(mem_ptr->fw){
			memset(mem_ptr->fw, 0, sizeof(MEMOBJ));

			mem_ptr->fw->cleaner = cleaner;
			mem_ptr->fw->ptr = ptr;
			mem_ptr->fw->bk = mem_ptr;
			return ptr;
		}else fprintf(stderr, "malloc(): %s\n", strerror(errno));
	}
	return NULL;
}

void rmptr(void *ptr){
	MEMOBJ *mem_ptr = NULL;
	if(!ptr || !mempool) return;
	mem_ptr = mempool->alloc_hd;
	while(mem_ptr){
		if(mem_ptr->ptr == ptr && mem_ptr->cleaner){
			//printf("free_obj(): Freeing %p\n", ptr);
			mem_ptr->cleaner(mem_ptr->ptr);
			if(mem_ptr->fw) mem_ptr->fw->bk = mem_ptr->bk;
			if(mem_ptr->bk) mem_ptr->bk->fw = mem_ptr->fw;
			memset(mem_ptr, 0, sizeof(MEMOBJ));
			free(mem_ptr);
			return;
		}
		mem_ptr = mem_ptr->fw;
	}
	return;
}