#ifndef UTIL_H_
#define UTIL_H_

#include <stdio.h>
#include <stdlib.h>

#define ASSERT_MALLOC(res) if ((res) == NULL) { \
	fprintf(stderr, "FATAL memory allocation failure!"); \
	abort(); \
}

#endif