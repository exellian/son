#ifndef BUFFER_H_
#define BUFFER_H_

#define BUFPOOL_CAPACITY 100

typedef struct bufpool_s bufpool_t;

struct bufpool_s {
	void *bufs[BUFPOOL_CAPACITY];
	int size;
};

typedef struct bufbase_s bufbase_t;

struct bufbase_s {
	bufpool_t *pool;
	int len;
};
void *bufpool_acquire(bufpool_t *pool, int *len);
void bufpool_release(void *ptr);
void bufpool_init(bufpool_t *pool);
void bufpool_free(bufpool_t *pool);

#endif // !BUFFER_H_

