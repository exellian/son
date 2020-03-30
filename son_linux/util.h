#ifndef UTIL_H_
#define UTIL_H_

#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>

#define ASSERT_MALLOC(res) if ((res) == NULL) { \
	fprintf(stderr, "FATAL memory allocation failure!"); \
	abort(); \
}

#endif