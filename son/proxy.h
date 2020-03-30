#ifndef TCP_PROXY_H_
#define TCP_PROXY_H_

#include "buffer.h"
#include <uv.h>

#define DEFAULT_BACKLOG 1024
#define DEFAULT_MIN_PEER_TABLE_SIZE 50
#define DEFAULT_MAX_PEER_TABLE_SIZE 10000
#define DEFAULT_MAX_PEER_TABLE_COLLISIONS 4
#define DEFAULT_MAX_PEER_TABLE_RESIZES 7

typedef struct peer_information_s peer_information_t;
typedef struct endpoint_s endpoint_t;
typedef struct peer_s peer_t;
typedef struct tunnel_s tunnel_t;
typedef struct proxy_s proxy_t;
typedef struct pending_s pending_t;
typedef struct write_data_s write_data_t;
typedef struct peer_list_s peer_list_t;
typedef struct peer_table_s peer_table_t;

struct peer_information_s {
	char ip[45];
	int port;
};
struct endpoint_s {
	struct sockaddr * addr;
	int ipv6;
	int tcp;
};

struct peer_s {
	size_t key;
	peer_information_t information;
	tunnel_t* tunnel;
	peer_t* next;
};

struct peer_list_s {
	size_t size;
	peer_t* start;
	peer_t* last;
};

struct peer_table_s {
	size_t size;
	size_t resize_count;
	peer_list_t* list;
};

struct proxy_s {
	uv_loop_t loop;
	bufpool_t local_pool;
	bufpool_t remote_pool;
	endpoint_t local;
	endpoint_t remote;
	uv_stream_t* server;
	peer_table_t table;
	const struct sockaddr* ipv4_wildcard;
	const struct sockaddr* ipv6_wildcard;
};

struct pending_s {
	pending_t * next;
	uv_buf_t buf;
};

struct tunnel_s {
	uv_stream_t* remote;
	uv_stream_t* local;
	struct sockaddr* remote_addr;
	struct sockaddr* local_addr;
	int connected;
	int remote_closed;
	int local_closed;
	pending_t * pending_queue;
	pending_t * pending_queue_last;
	proxy_t * proxy;
};

struct write_data_s {
	tunnel_t* tunnel;
	uv_buf_t buf;
};

int init_endpoint_ipv6(struct sockaddr_in6 * addr, int tcp, endpoint_t * endpoint);
int init_endpoint_ipv4(struct sockaddr_in * addr, int tcp, endpoint_t * endpoint);
void free_endpoint(endpoint_t * endpoint);
void init_proxy(endpoint_t local, endpoint_t remote, proxy_t * proxy);
int start_proxy(proxy_t * proxy);
void free_proxy(proxy_t * proxy);
void init_pending(uv_buf_t buf, pending_t * pending);
void push_pending(pending_t * pending, tunnel_t * tunnel);
pending_t * pop_pending(tunnel_t * tunnel);
void init_tunnel(proxy_t * proxy, tunnel_t * tunnel);
void init_write_data(uv_buf_t buf, tunnel_t * tunnel, write_data_t * write_data);
void init_peer(size_t key, peer_information_t* information, tunnel_t* tunnel, peer_t * peer);
void init_peer_list(peer_list_t* list);
void add_peer_list(size_t key, peer_information_t* information, tunnel_t* tunnel, peer_list_t* list);
peer_t * get_peer_list(size_t key, peer_information_t* information, peer_list_t* list);
void free_peer_list(peer_list_t* list);
void print_peer_list(peer_list_t * list);
void init_peer_table(peer_table_t * table);
void free_peer_table(peer_table_t * table);
void set_peer_table(peer_information_t* information, tunnel_t * tunnel, peer_table_t * table);
tunnel_t * get_peer_table(peer_information_t* information, peer_table_t * table);
void print_peer_table(peer_table_t * table);
#endif