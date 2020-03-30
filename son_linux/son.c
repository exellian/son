#include "util.h"
#include <uv.h>
#include "buffer.h"
#include "cli.h"
#include "proxy.h"

int main(int argc, char *argv[])
{
	endpoint_t local;
	endpoint_t remote;
	proxy_t proxy;

	if (parse_endpoints(argc, argv, &local, &remote) == PARSE_ERROR) {
		return PARSE_ERROR;
	}
	init_proxy(local, remote, &proxy);
	int res = start_proxy(&proxy);
	free_proxy(&proxy);
	free_endpoint(&local);
	free_endpoint(&remote);
	return res;
}