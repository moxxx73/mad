#ifndef MEMPOOL_H
#define MEMPOOL_H

#include <stdlib.h>
#include <string.h>

typedef struct mem_obj{
	struct mem_obj *bk;
	void *ptr;
	void (*cleaner)(void *);
	long size;
	struct mem_obj *fw;
} MEMOBJ;

typedef struct{
	long allocated;
	long freed;
	MEMOBJ *alloc_hd;
} POOL;

extern POOL *mempool;

void free_pool(void);

void init_pool(void);

void *import_ptr(void *ptr, void (*cleaner)(void *));

void rmptr(void *ptr);

#endif