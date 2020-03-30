#include "util.h"
#include "buffer.h"
#include <stdlib.h>

#define BUF_SIZE 64000
#define DUMMY_BUF_SIZE 8000
#define bufbase(ptr) ((bufbase_t *)((char *)(ptr) - sizeof(bufbase_t)))
#define buflen(ptr) (bufbase(ptr)->len)

void * bufpool_alloc(bufpool_t * pool, int len)
{

	bufbase_t *base = malloc(sizeof(bufbase_t) + len);
	if (base == NULL) {
		return NULL;
	}
	base->pool = pool;
	base->len = len;
	return (char *)base + sizeof(bufbase_t);
}

void bufpool_free_internal(void * ptr)
{
	if (ptr == NULL) {
		return;
	}
	free(bufbase(ptr));
}

void *bufpool_grow(bufpool_t *pool) {
	int idx = pool->size;
	void *buf;
	if (idx == BUFPOOL_CAPACITY) return 0;
	buf = bufpool_alloc(pool, BUF_SIZE);
	if (buf == NULL) {
		return NULL;
	}
	pool->bufs[idx] = 0;
	pool->size = idx + 1;
	return buf;
}

void bufpool_enqueue(bufpool_t *pool, void *ptr) {
	int idx;
	for (idx = 0; idx < pool->size; ++idx) {
		if (!pool->bufs[idx]) break;
	}
//	assert(idx < pool->size);
	pool->bufs[idx] = ptr;
}

void *bufpool_dequeue(bufpool_t *pool) {
	int idx;
	void *ptr;
	for (idx = 0; idx < pool->size; ++idx) {
		ptr = pool->bufs[idx];
		if (ptr != NULL) {
			pool->bufs[idx] = 0;
			return ptr;
		}
	}
	return bufpool_grow(pool);
}

void * bufpool_dummy()
{
	return bufpool_alloc(0, DUMMY_BUF_SIZE);
}

void * bufpool_acquire(bufpool_t * pool, int * len)
{
	void *buf;
	int size = *len;
	if (size > DUMMY_BUF_SIZE) {
		buf = bufpool_dequeue(pool);
		if (buf != NULL) {
			if (size > BUF_SIZE) *len = BUF_SIZE;
			return buf;
		}
		size = DUMMY_BUF_SIZE;
	}
	buf = bufpool_alloc(NULL, size);
	if (buf != NULL) {
		*len = size;
	} else {
		*len = 0;
	}
	return buf;
}

void bufpool_release(void * ptr)
{
	bufbase_t *base;
	if (ptr == NULL) {
		return;
	}
	base = bufbase(ptr);
	if (base->pool) {
		bufpool_enqueue(base->pool, ptr);
	} else {
		free(base);
	}
}

void bufpool_init(bufpool_t * pool)
{
	pool->size = 0;
}

void bufpool_free(bufpool_t * pool)
{
	int idx;
	for (idx = 0; idx < pool->size; ++idx) {
		bufpool_free_internal(pool->bufs[idx]);
	}
}
