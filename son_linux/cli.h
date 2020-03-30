#ifndef CLI_H_
#define CLI_H_

#define PARSE_ERROR 1

#include "proxy.h"

int parse_endpoints(int argc, char *argv[], endpoint_t * local, endpoint_t * remote);

#endif