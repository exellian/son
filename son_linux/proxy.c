#include "util.h"
#include "proxy.h"
#include "buffer.h"
#include "util.h"
#include <netinet/in.h>

void add_peer_list_raw(peer_t* peer, peer_list_t* list);

void alloc_buffer(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf);
void alloc_buffer_server(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf);
void alloc_buffer_remote(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf);

void init_tcp_server(proxy_t * proxy);
void init_udp_server(proxy_t * proxy);
peer_information_t get_peer_information(const struct sockaddr * addr);
size_t hash_peer_information(peer_information_t * information, size_t m);

void on_connection_tcp_local_tcp_remote(uv_stream_t *server, int status);
void on_connection_tcp_local_udp_remote(uv_stream_t *server, int status);
void on_read_tcp_local_tcp_remote(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf);
void on_read_tcp_local_udp_remote(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf);
void on_read_udp_local_tcp_remote(uv_udp_t* handle, ssize_t nread, const uv_buf_t* buf, const struct sockaddr* addr, unsigned flags);
void on_read_udp_local_udp_remote(uv_udp_t* handle, ssize_t nread, const uv_buf_t* buf, const struct sockaddr* addr, unsigned flags);
void on_written_tcp_local_tcp_remote(uv_write_t * write, int status);
void on_written_tcp_local_udp_remote(uv_write_t * req, int status);
void on_written_udp_local_tcp_remote(uv_udp_send_t * req, int status);
void on_written_udp_local_udp_remote(uv_udp_send_t * req, int status);
void on_close_tcp_local(uv_handle_t* handle);

void on_connect_tcp_remote_tcp_local(uv_connect_t* connection, int status);
void on_connect_tcp_remote_udp_local(uv_connect_t* connection, int status);
void on_read_tcp_remote_tcp_local(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf);
void on_read_tcp_remote_udp_local(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf);
void on_read_udp_remote_tcp_local(uv_udp_t* handle, ssize_t nread, const uv_buf_t* buf, const struct sockaddr* addr, unsigned flags);
void on_read_udp_remote_udp_local(uv_udp_t* handle, ssize_t nread, const uv_buf_t* buf, const struct sockaddr* addr, unsigned flags);
void on_written_tcp_remote_tcp_local(uv_write_t* write, int status);
void on_written_tcp_remote_udp_local(uv_write_t* write, int status);
void on_written_udp_remote_tcp_local(uv_udp_send_t * req, int status);
void on_written_udp_remote_udp_local(uv_udp_send_t * req, int status);
void on_close_tcp_remote(uv_handle_t* handle);

/**
* Init ipv6 address endpoint
*/
int init_endpoint_ipv6(struct sockaddr_in6 * addr, int tcp, endpoint_t * endpoint)
{
	struct sockaddr_in6 * addr6 = (struct sockaddr_in6*)malloc(sizeof(struct sockaddr_in6));
	ASSERT_MALLOC(addr6);
	*addr6 = *addr;
	endpoint->addr = (struct sockaddr*)addr6;
	endpoint->ipv6 = 1;
	endpoint->tcp = tcp;
	return 0;
}
/**
* Init ipv4 address endpoint
*/
int init_endpoint_ipv4(struct sockaddr_in * addr, int tcp, endpoint_t * endpoint)
{
	struct sockaddr_in * addr4 = (struct sockaddr_in*)malloc(sizeof(struct sockaddr_in));
	ASSERT_MALLOC(addr4);
	*addr4 = *addr;
	endpoint->addr = (struct sockaddr*)addr4;
	endpoint->ipv6 = 0;
	endpoint->tcp = tcp;
	return 0;
}
/**
* Free of endpoint address
*/
void free_endpoint(endpoint_t * endpoint)
{
	free(endpoint->addr);
}
/**
* Init proxy
*/
void init_proxy(endpoint_t local, endpoint_t remote, proxy_t * proxy)
{
	struct sockaddr_in* ipv4 = (struct sockaddr_in*)malloc(sizeof(struct sockaddr_in));
	ASSERT_MALLOC(ipv4);
	uv_ip4_addr("0.0.0.0", 0, ipv4);
	struct sockaddr_in6* ipv6 = (struct sockaddr_in6*)malloc(sizeof(struct sockaddr_in6));
	ASSERT_MALLOC(ipv6);
	uv_ip6_addr("::0", 0, ipv6);

	proxy->server = NULL;
	uv_loop_init(&proxy->loop);
	proxy->local = local;
	proxy->remote = remote;
	proxy->ipv4_wildcard = (struct sockaddr*)ipv4;
	proxy->ipv6_wildcard = (struct sockaddr*)ipv6;
	bufpool_init(&proxy->local_pool);
	bufpool_init(&proxy->remote_pool);
}
/**
* Starts the proxy
*/
int start_proxy(proxy_t * proxy)
{
	if (proxy->local.tcp) {
		init_tcp_server(proxy);
	} else {
		init_udp_server(proxy);
	}

	peer_information_t info = get_peer_information(proxy->local.addr);
	if (proxy->local.ipv6) {
		printf("Proxy listening on [%s]:%i\n", info.ip, info.port);
	} else {
		printf("Proxy listening on %s:%i\n", info.ip, info.port);
	}
	
	return uv_run(&proxy->loop, UV_RUN_DEFAULT);
}
/**
* Should be called after start_proxy() terminates
*/
void free_proxy(proxy_t * proxy)
{
	free(proxy->server);
	free(proxy->ipv4_wildcard);
	free(proxy->ipv6_wildcard);
	uv_loop_close(&proxy->loop);
	bufpool_free(&proxy->local_pool);
	bufpool_free(&proxy->remote_pool);
}
/**
* Inits pending linked list
*/
void init_pending(uv_buf_t buf, pending_t * pending)
{
	pending->buf = buf;
	pending->next = NULL;
}
/**
* Push pending buf
*/
void push_pending(pending_t * pending, tunnel_t * tunnel)
{
	if (tunnel->pending_queue_last == NULL) {
		tunnel->pending_queue = pending;
		tunnel->pending_queue_last = pending;
	}
	else {
		tunnel->pending_queue_last->next = pending;
		tunnel->pending_queue_last = pending;
	}
}
/**
* Pop pending buf
*/
pending_t * pop_pending(tunnel_t * tunnel)
{
	pending_t * pending = tunnel->pending_queue;
	if (pending == NULL) {
		return NULL;
	}
	tunnel->pending_queue = pending->next;
	if (tunnel->pending_queue == NULL) {
		tunnel->pending_queue_last = NULL;
	}
	return pending;
}
/**
* Init tcp_tunnel_t
*/
void init_tunnel(proxy_t * proxy, tunnel_t * tunnel)
{
	tunnel->local = NULL;
	tunnel->remote = NULL;
	tunnel->proxy = proxy;
	tunnel->local_addr = NULL;
	tunnel->remote_addr = NULL;
	tunnel->connected = 0;
	tunnel->remote_closed = 1;
	tunnel->local_closed = 1;
	tunnel->pending_queue = NULL;
	tunnel->pending_queue_last = NULL;
}
/**
* Allocation of local buffers
*/
void alloc_buffer(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf)
{
	tunnel_t * tunnel = (tunnel_t*)handle->data;
	int len = (int)suggested_size;
	void *ptr = bufpool_acquire(&tunnel->proxy->local_pool, &len);
	ASSERT_MALLOC(ptr);
	*buf = uv_buf_init(ptr, (unsigned int)len);
}
/**
* Allocation of local buffers
*/
void alloc_buffer_server(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf)
{
	proxy_t* proxy = (proxy_t*)handle->data;
	int len = (int)suggested_size;
	void *ptr = bufpool_acquire(&proxy->local_pool, &len);
	ASSERT_MALLOC(ptr);
	*buf = uv_buf_init(ptr, (unsigned int)len);
}
/**
* Allocation of remote buffers
*/
void alloc_buffer_remote(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf)
{
	tunnel_t * tunnel = (tunnel_t*)handle->data;
	int len = (int)suggested_size;
	void *ptr = bufpool_acquire(&tunnel->proxy->remote_pool, &len);
	ASSERT_MALLOC(ptr);
	*buf = uv_buf_init(ptr, (unsigned int)len);
}
/**
* Init write_data_t
*/
void init_write_data(uv_buf_t buf, tunnel_t * tunnel, write_data_t * write_data)
{
	write_data->buf = buf;
	write_data->tunnel = tunnel;
}
/**
* Inits peer
*/
void init_peer(size_t key, peer_information_t* information, tunnel_t* tunnel, peer_t * peer)
{
	peer->key = key;
	peer->information = *information;
	peer->tunnel = tunnel;
	peer->next = NULL;
}
/**
* Inits peer list
*/
void init_peer_list(peer_list_t* list)
{
	list->last = NULL;
	list->start = NULL;
	list->size = 0;
}
/**
* Adds Peer to list
*/
void add_peer_list(size_t key, peer_information_t* information, tunnel_t* tunnel, peer_list_t* list)
{
	peer_t * peer = (peer_t*)malloc(sizeof(peer_t));
	ASSERT_MALLOC(peer);
	init_peer(key, information, tunnel, peer);
	if (list->start == NULL) {
		list->start = peer;	
	} else {
		list->last->next = peer;
	}
	list->size++;
	list->last = peer;
}
/**
* 
*/
void add_peer_list_raw(peer_t* peer, peer_list_t* list)
{
	peer->next = NULL;
	if (list->last == NULL) {
		list->start = peer;
	} else {
		list->last->next = peer;
	}
	list->size++;
	list->last = peer;
}
/**
* Gets peer from list or NULL
*/
peer_t * get_peer_list(size_t key, peer_information_t* information, peer_list_t* list)
{
	peer_t *peer = list->start;
	while (peer != NULL) {
		if ((information->port == peer->information.port) && (strcmp(information->ip, peer->information.ip) == 0)) {
			return peer;
		}
		peer = peer->next;
	}
	return NULL;
}
/**
* Frees peer list
*/
void free_peer_list(peer_list_t* list)
{
	peer_t *peer = list->start;
	while (peer != NULL) {
		peer_t * next = peer->next;
		free(peer);
		peer = next;
	}
}
/**
* Inits hash table for peers
*/
void init_peer_table(peer_table_t * table)
{
	table->size = DEFAULT_MIN_PEER_TABLE_SIZE;
	table->resize_count = 0;
	table->list = (peer_list_t*)calloc(DEFAULT_MIN_PEER_TABLE_SIZE, sizeof(peer_list_t));
	ASSERT_MALLOC(table->list);
}
/**
* Frees hash table for peers
*/
void free_peer_table(peer_table_t * table)
{
	free_peer_list(table->list);
	free(table->list);
}
/**
* Prints peer list
*/
void print_peer_list(peer_list_t * list)
{

	peer_t* peer = list->start;

	while (peer != NULL) {
		printf(" %i", (int)peer->tunnel);
		peer = peer->next;
	}
	printf("\n");
	
}
/**
* Sets peer in hash table
*/
void set_peer_table(peer_information_t* information, tunnel_t * tunnel, peer_table_t * table)
{
	size_t hash_code = hash_peer_information(information, table->size);
	peer_list_t * list = table->list + hash_code;
	size_t i;
	size_t new_size;
	if (list->size == DEFAULT_MAX_PEER_TABLE_COLLISIONS && table->resize_count <= DEFAULT_MAX_PEER_TABLE_RESIZES) {
		new_size = table->size * 2;
		table->list = (peer_list_t*)realloc(table->list, new_size * sizeof(peer_list_t));
		ASSERT_MALLOC(table->list);
		
		for (i = table->size;i < new_size;i++) {
			init_peer_list(table->list + i);
		}
		table->size = new_size;
		table->resize_count++;
		hash_code = hash_peer_information(information, new_size);
	}
	add_peer_list(hash_code, information, tunnel, list);
}
/**
* Gets peer in hash table
*/
tunnel_t * get_peer_table(peer_information_t* information, peer_table_t * table)
{
	size_t current_size = table->size;
	size_t i;
	size_t first_hash_code;
	size_t hash_code;
	peer_list_t* list;
	peer_t* prev;
	peer_t* peer;
	for (i = 0; i <= table->resize_count; i++) {
		hash_code = hash_peer_information(information, current_size);
		if (i == 0) {
			first_hash_code = hash_code;
		}
		list = table->list + hash_code;
		peer = list->start;
		prev = NULL;
		while (peer != NULL) {
			if ((peer->information.port == information->port) && (strcmp(peer->information.ip, information->ip) == 0)) {
				if (i != 0) {
					if (prev == NULL) {
						list->start = peer->next;
					} else {
						prev->next = peer->next;
					}
					if (peer->next == NULL) {
						list->last = prev;
					}
					add_peer_list_raw(peer, (table->list + first_hash_code));
				}
				return peer->tunnel;
			}
			prev = peer;
			peer = peer->next;
		}
		current_size = current_size / 2;
	}
	return NULL;
}
/**
*
*/
void print_peer_table(peer_table_t * table)
{
	size_t i;
	for (i = 0;i < table->size;i++) {
		printf("%i: ", i);
		//printf("%p", peer);
		print_peer_list((table->list + i));
	}
}

/**
* Local creation
*/

/**
* Tcp server setup
*/
void init_tcp_server(proxy_t * proxy)
{
	uv_tcp_t * server = (uv_tcp_t*)malloc(sizeof(uv_tcp_t));
	ASSERT_MALLOC(server);
	server->data = proxy;
	uv_tcp_init(&proxy->loop, server);
	uv_tcp_bind(server, proxy->local.addr, 0);

	int res;
	if (proxy->remote.tcp) {
		res = uv_listen((uv_stream_t*)server, DEFAULT_BACKLOG, on_connection_tcp_local_tcp_remote);
	} else {
		res = uv_listen((uv_stream_t*)server, DEFAULT_BACKLOG, on_connection_tcp_local_udp_remote);
	}
	if (res) {
		fprintf(stderr, "Server read error %s\n", uv_err_name(res));
	}
}
/**
* Udp server setup
*/
void init_udp_server(proxy_t * proxy)
{
	uv_udp_t * server = (uv_udp_t*)malloc(sizeof(uv_udp_t));
	ASSERT_MALLOC(server);
	init_peer_table(&proxy->table);
	server->data = proxy;
	uv_udp_init(&proxy->loop, server);
	uv_udp_bind(server, proxy->local.addr, 0);
	if (proxy->remote.tcp) {
		uv_udp_recv_start(server, alloc_buffer_server, on_read_udp_local_tcp_remote);
	} else {
		uv_udp_recv_start(server, alloc_buffer_server, on_read_udp_local_udp_remote);
	}
}
/**
* Get tcp peer information
*/
peer_information_t get_peer_information(const struct sockaddr * addr)
{
	peer_information_t info;
	if (addr->sa_family == AF_INET) {
		const struct sockaddr_in *addr_i4 = (const struct sockaddr_in *)addr;
		uv_ip4_name(addr_i4, info.ip, sizeof(info.ip));
		info.port = htons(addr_i4->sin_port);
	}
	else if (addr->sa_family == AF_INET6) {
		const struct sockaddr_in6 *addr_i6 = (const struct sockaddr_in6 *)addr;
		uv_ip6_name(addr_i6, info.ip, sizeof(info.ip));
		info.port = htons(addr_i6->sin6_port);
	}
	return info;
}
/**
* Hash function for sockaddr
*/
#define HASH_P 23
size_t hash_peer_information(peer_information_t * information, size_t m)
{
	size_t hash = 0;
	size_t len = strlen(information->ip);
	size_t i;
	size_t p_pow = 1;
	size_t q = 0;
	size_t n = information->port;
	char c;
	for (i = 0;i < len;i++) {
		c = information->ip[i];
		size_t res = ((size_t)c - ((size_t)'a') + 1) * p_pow;
		hash = (hash + res) % m;
		p_pow = (p_pow * HASH_P) % m;
	}
	while (n != 0) {
		hash = (hash + ((n % 10 + 1) * p_pow)) % m;
		p_pow = (p_pow * HASH_P) % m;
		n = n / 10;
	}
	return hash;
}

/**
* Local events
*/

/**
* Tcp connection callback
*/
void on_connection_tcp_local_tcp_remote(uv_stream_t * server, int status)
{
	if (status < 0) {
		fprintf(stderr, "New connection error %s\n", uv_strerror(status));
		return;
	}
	/**
	* Allocation objects
	*/
	proxy_t * proxy = server->data;
	tunnel_t * tunnel = (tunnel_t*)malloc(sizeof(tunnel_t));
	ASSERT_MALLOC(tunnel);
	uv_tcp_t * local = (uv_tcp_t*)malloc(sizeof(uv_tcp_t));
	ASSERT_MALLOC(local);

	init_tunnel(proxy, tunnel);
	uv_tcp_init(&proxy->loop, local);
	tunnel->local = (uv_stream_t*)local;
	local->data = tunnel;

	if (uv_accept((uv_stream_t*)server, (uv_stream_t*)local) == 0) {
		
		tunnel->local_closed = 0;
		uv_connect_t * connect = (uv_connect_t*)malloc(sizeof(uv_connect_t));
		ASSERT_MALLOC(connect);
		uv_tcp_t * remote = (uv_tcp_t*)malloc(sizeof(uv_tcp_t));
		ASSERT_MALLOC(remote);

		uv_tcp_init(&tunnel->proxy->loop, remote);
		tunnel->remote = (uv_stream_t*)remote;
		remote->data = tunnel;
		uv_tcp_connect(connect, remote, tunnel->proxy->remote.addr, on_connect_tcp_remote_tcp_local);
		uv_read_start(tunnel->local, alloc_buffer, on_read_tcp_local_tcp_remote);
	} else {
		uv_close((uv_handle_t*)local, on_close_tcp_local);
	}
}
/**
* Tcp connection callback
*/
void on_connection_tcp_local_udp_remote(uv_stream_t *server, int status)
{
	if (status < 0) {
		fprintf(stderr, "New connection error %s\n", uv_strerror(status));
		return;
	}
	/**
	* Allocation objects
	*/
	proxy_t * proxy = server->data;
	tunnel_t * tunnel = (tunnel_t*)malloc(sizeof(tunnel_t));
	ASSERT_MALLOC(tunnel);
	uv_tcp_t * local = (uv_tcp_t*)malloc(sizeof(uv_tcp_t));
	ASSERT_MALLOC(local);

	init_tunnel(proxy, tunnel);
	uv_tcp_init(&proxy->loop, local);
	tunnel->local = (uv_stream_t*)local;
	local->data = tunnel;

	if (uv_accept((uv_stream_t*)server, (uv_stream_t*)local) == 0) {

		tunnel->local_closed = 0;
		uv_udp_t * remote = (uv_udp_t*)malloc(sizeof(uv_udp_t));
		ASSERT_MALLOC(remote);
		uv_udp_init(&tunnel->proxy->loop, remote);
		tunnel->remote = (uv_stream_t*)remote;
		tunnel->connected = 1;
		remote->data = tunnel;
		uv_udp_recv_start(remote, alloc_buffer_remote, on_read_udp_remote_tcp_local);
		uv_read_start(tunnel->local, alloc_buffer, on_read_tcp_local_udp_remote);
	}
	else {
		uv_close((uv_handle_t*)local, on_close_tcp_local);
	}
}
/**
* On external client incoming data
*/
void on_read_tcp_local_tcp_remote(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf)
{
	tunnel_t * tunnel = (tunnel_t*)stream->data;
	if (nread < 0) {
		if (nread != UV_EOF) {
			fprintf(stderr, "Server read error %s\n", uv_err_name(nread));
		}
		uv_close((uv_handle_t*)tunnel->local, on_close_tcp_local);
		uv_close((uv_handle_t*)tunnel->remote, on_close_tcp_remote);
		bufpool_release(buf->base);
		return;
	}

	printf("[TCP][LOCAL][READ] size: %u\n", nread);

	if (!tunnel->connected) {
		pending_t * pending = (pending_t*)malloc(sizeof(pending_t));
		ASSERT_MALLOC(pending);
		init_pending(uv_buf_init(buf->base, nread), pending);
		push_pending(pending, tunnel);
	} else {
		write_data_t * write_data = (write_data_t*)malloc(sizeof(write_data_t));
		ASSERT_MALLOC(write_data);
		init_write_data(uv_buf_init(buf->base, nread), tunnel, write_data);

		uv_write_t *req = (uv_write_t*)malloc(sizeof(uv_write_t));
		ASSERT_MALLOC(req);
		req->data = write_data;
		uv_write(req, tunnel->remote, &write_data->buf, 1, on_written_tcp_remote_tcp_local);
	}
}
/**
* On external client incoming data
*/
void on_read_tcp_local_udp_remote(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf)
{
	tunnel_t * tunnel = (tunnel_t*)stream->data;
	if (nread < 0) {
		if (nread != UV_EOF) {
			fprintf(stderr, "Server read error %s\n", uv_err_name(nread));
		}
		uv_close((uv_handle_t*)tunnel->local, on_close_tcp_local);
		bufpool_release(buf->base);
		return;
	}

	printf("[TCP][LOCAL][READ] size: %u\n", nread);

	write_data_t * write_data = (write_data_t*)malloc(sizeof(write_data_t));
	ASSERT_MALLOC(write_data);
	init_write_data(uv_buf_init(buf->base, nread), tunnel, write_data);

	uv_udp_send_t * req = (uv_udp_send_t*)malloc(sizeof(uv_udp_send_t));
	ASSERT_MALLOC(req);
	req->data = write_data;
	uv_udp_send(req, (uv_udp_t*)tunnel->remote, &write_data->buf, 1, tunnel->proxy->remote.addr, on_written_udp_remote_tcp_local);
}
/**
* On external client incoming data
*/
void on_read_udp_local_tcp_remote(uv_udp_t* handle, ssize_t nread, const uv_buf_t* buf, const struct sockaddr* addr, unsigned flags)
{
	proxy_t * proxy = (proxy_t*)handle->data;
	
	peer_information_t info = get_peer_information(addr);
	tunnel_t* tunnel = get_peer_table(&info, &proxy->table);

	if (tunnel == NULL) {
		tunnel = (tunnel_t*)malloc(sizeof(tunnel_t));
		ASSERT_MALLOC(tunnel);
		init_tunnel(proxy, tunnel);
		if (addr->sa_family == AF_INET) {
			tunnel->local_addr = (struct sockaddr*)malloc(sizeof(struct sockaddr_in));
			ASSERT_MALLOC(tunnel->local_addr);
			*((struct sockaddr_in*)tunnel->local_addr) = *((struct sockaddr_in*)addr);
		}
		else {
			tunnel->local_addr = (struct sockaddr*)malloc(sizeof(struct sockaddr_in6));
			ASSERT_MALLOC(tunnel->local_addr);
			*((struct sockaddr_in6*)tunnel->local_addr) = *((struct sockaddr_in6*)addr);
		}
		tunnel->local = (uv_stream_t*)handle;
		uv_connect_t* connect = (uv_connect_t*)malloc(sizeof(uv_connect_t));
		ASSERT_MALLOC(connect);
		uv_tcp_t* remote = (uv_tcp_t*)malloc(sizeof(uv_tcp_t));
		ASSERT_MALLOC(remote);

		uv_tcp_init(&proxy->loop, remote);
		tunnel->remote = (uv_stream_t*)remote;
		remote->data = tunnel;
		uv_tcp_connect(connect, remote, proxy->remote.addr, on_connect_tcp_remote_udp_local);
	}

	if (nread < 0) {
		if (nread != UV_EOF) {
			fprintf(stderr, "Server read error %s\n", uv_err_name(nread));
		}
		uv_close((uv_handle_t*)tunnel->remote, on_close_tcp_remote);
		bufpool_release(buf->base);
		return;
	}

	printf("[UDP][LOCAL][READ] size: %u\n", nread);

	
	if (!tunnel->connected) {
		pending_t* pending = (pending_t*)malloc(sizeof(pending_t));
		ASSERT_MALLOC(pending);
		init_pending(uv_buf_init(buf->base, nread), pending);
		push_pending(pending, tunnel);
	}
	else {
		write_data_t * write_data = (write_data_t*)malloc(sizeof(write_data_t));
		ASSERT_MALLOC(write_data);
		init_write_data(uv_buf_init(buf->base, nread), tunnel, write_data);

		uv_write_t *req = (uv_write_t*)malloc(sizeof(uv_write_t));
		ASSERT_MALLOC(req);
		req->data = write_data;
		uv_write(req, tunnel->remote, &write_data->buf, 1, on_written_tcp_local_tcp_remote);
	}
}
/**
* On external client incoming data
*/
void on_read_udp_local_udp_remote(uv_udp_t* handle, ssize_t nread, const uv_buf_t* buf, const struct sockaddr* addr, unsigned flags)
{
	proxy_t * proxy = (proxy_t*)handle->data;

	if (nread < 0 || addr == NULL) {
		if (nread != UV_EOF) {
			fprintf(stderr, "Server read error %s\n", uv_err_name(nread));
		}
		bufpool_release(buf->base);
		return;
	}

	peer_information_t info = get_peer_information(addr);
	//printf("[UDP][Read] %s:%i hash: %u\n", info.ip, info.port, hash_peer_information(&info, proxy->table.size));

	tunnel_t* tunnel = get_peer_table(&info, &proxy->table);

	if (tunnel == NULL) {
		tunnel = (tunnel_t*)malloc(sizeof(tunnel_t));
		ASSERT_MALLOC(tunnel);
		init_tunnel(proxy, tunnel);
		if (addr->sa_family == AF_INET) {
			tunnel->local_addr = (struct sockaddr*)malloc(sizeof(struct sockaddr_in));
			ASSERT_MALLOC(tunnel->local_addr);
			*((struct sockaddr_in*)tunnel->local_addr) = *((struct sockaddr_in*)addr);
		} else {
			tunnel->local_addr = (struct sockaddr*)malloc(sizeof(struct sockaddr_in6));
			ASSERT_MALLOC(tunnel->local_addr);
			*((struct sockaddr_in6*)tunnel->local_addr) = *((struct sockaddr_in6*)addr);
		}

		tunnel->local = (uv_stream_t*)handle;

		uv_udp_t* remote = (uv_udp_t*)malloc(sizeof(uv_udp_t));
		ASSERT_MALLOC(remote);
		uv_udp_init(&proxy->loop, remote);

		remote->data = tunnel;
		tunnel->remote = (uv_stream_t*)remote;
		tunnel->remote_addr = proxy->remote.addr;
		set_peer_table(&info, tunnel, &proxy->table);
		
		if (proxy->remote.ipv6) {
			uv_udp_bind(remote, proxy->ipv6_wildcard, 0);
		} else {
			uv_udp_bind(remote, proxy->ipv4_wildcard, 0);
		}
		uv_udp_set_broadcast(remote, 1);
		uv_udp_recv_start(remote, alloc_buffer_remote, on_read_udp_remote_udp_local);
	}

	write_data_t * write_data = (write_data_t*)malloc(sizeof(write_data_t));
	ASSERT_MALLOC(write_data);
	init_write_data(uv_buf_init(buf->base, nread), tunnel, write_data);

	uv_udp_send_t * req = (uv_udp_send_t*)malloc(sizeof(uv_udp_send_t));
	ASSERT_MALLOC(req);
	req->data = write_data;
	info = get_peer_information(tunnel->remote_addr);
	//printf("[UDP][INFO] %s:%i\n", info.ip, info.port);
	uv_udp_send(req, (uv_udp_t*)tunnel->remote, &write_data->buf, 1, proxy->remote.addr, on_written_udp_remote_udp_local);
}
/**
* On external client data write finished
*/
void on_written_tcp_local_tcp_remote(uv_write_t* req, int status)
{
	write_data_t * write_data = (write_data_t*)req->data;
	
	if (status >= 0) {
		printf("[TCP][LOCAL][WRITE] size: %u\n", write_data->buf.len);
	}

	bufpool_release(write_data->buf.base);
	free(req);
	free(write_data);
}
/**
* On external client data write finished
*/
void on_written_tcp_local_udp_remote(uv_write_t * req, int status)
{
	write_data_t * write_data = (write_data_t*)req->data;

	if (status >= 0) {
		printf("[UDP][LOCAL][WRITE] size: %u\n", write_data->buf.len);
	}

	bufpool_release(write_data->buf.base);
	free(req);
	free(write_data);
}
/**
* On external client data write finished
*/
void on_written_udp_local_tcp_remote(uv_udp_send_t * req, int status)
{
	write_data_t * write_data = (write_data_t*)req->data;

	if (status >= 0) {
		printf("[UDP][LOCAL][WRITE] size: %u\n", write_data->buf.len);
	}

	bufpool_release(write_data->buf.base);
	free(req);
	free(write_data);
}
/**
* On external client data write finished
*/
void on_written_udp_local_udp_remote(uv_udp_send_t * req, int status)
{
	write_data_t * write_data = (write_data_t*)req->data;

	if (status >= 0) {
		//printf("[UDP][LOCAL][WRITE] size: %u\n", write_data->buf.len);
	}

	bufpool_release(write_data->buf.base);
	free(req);
	free(write_data);
}
/**
* On external client closed from local event
*/
void on_close_tcp_local(uv_handle_t* handle)
{
	tunnel_t * tunnel = handle->data;
	pending_t * pending = pop_pending(tunnel);
	while (pending != NULL) {
		bufpool_release(pending->buf.base);
		free(pending);
		pending = pop_pending(tunnel);
	}
	tunnel->local_closed = 1;
	free(tunnel->local);
	if (tunnel->remote_closed) {
		free(tunnel);
	}
}

/**
* remote events
*/

/**
* On remote connect
*/
void on_connect_tcp_remote_tcp_local(uv_connect_t* connect, int status)
{
	pending_t * pending;
	uv_write_t * req = NULL;
	write_data_t * write_data = NULL;
	uv_stream_t * stream = connect->handle;
	tunnel_t * tunnel = (tunnel_t*)stream->data;
	
	tunnel->remote_closed = 0;
	free(connect);

	if (status < 0) {
		fprintf(stderr, "New connection error %s\n", uv_strerror(status));
		pending = pop_pending(tunnel);
		while (pending != NULL) {
			free(pending);
			pending = pop_pending(tunnel);
		}
		uv_close((uv_handle_t*)tunnel->remote, on_close_tcp_remote);
		uv_close((uv_handle_t*)tunnel->local, on_close_tcp_local);
		return;
	}
	
	tunnel->connected = 1;
	uv_read_start(tunnel->remote, alloc_buffer_remote, on_read_tcp_remote_tcp_local);

	pending = pop_pending(tunnel);
	while (pending != NULL) {
		req = (uv_write_t*)malloc(sizeof(uv_write_t));
		ASSERT_MALLOC(req);
		write_data = (write_data_t*)malloc(sizeof(write_data_t));
		ASSERT_MALLOC(write_data);
		init_write_data(pending->buf, tunnel, write_data);
		req->data = write_data;
		uv_write(req, tunnel->remote, &write_data->buf, 1, on_written_tcp_remote_tcp_local);
		free(pending);
		pending = pop_pending(tunnel);
	}
}
/**
* 
*/
void on_connect_tcp_remote_udp_local(uv_connect_t* connect, int status)
{
	pending_t * pending;
	uv_write_t * req = NULL;
	write_data_t * write_data = NULL;
	uv_stream_t * stream = connect->handle;
	tunnel_t * tunnel = (tunnel_t*)stream->data;

	tunnel->remote_closed = 0;
	free(connect);

	if (status < 0) {
		fprintf(stderr, "New connection error %s\n", uv_strerror(status));
		pending = pop_pending(tunnel);
		while (pending != NULL) {
			free(pending);
			pending = pop_pending(tunnel);
		}
		uv_close((uv_handle_t*)tunnel->remote, on_close_tcp_remote);
		return;
	}

	tunnel->connected = 1;
	uv_read_start(tunnel->remote, alloc_buffer_remote, on_read_tcp_remote_udp_local);

	pending = pop_pending(tunnel);
	while (pending != NULL) {
		req = (uv_write_t*)malloc(sizeof(uv_write_t));
		ASSERT_MALLOC(req);
		write_data = (write_data_t*)malloc(sizeof(write_data_t));
		ASSERT_MALLOC(write_data);
		init_write_data(pending->buf, tunnel, write_data);
		req->data = write_data;
		uv_write(req, tunnel->remote, &write_data->buf, 1, on_written_tcp_remote_udp_local);
		free(pending);
		pending = pop_pending(tunnel);
	}
}
/**
* On remote incoming data
*/
void on_read_tcp_remote_tcp_local(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf)
{
	tunnel_t * tunnel = (tunnel_t*)stream->data;
	if (nread < 0) {
		if (nread != UV_EOF) {
			fprintf(stderr, "Server read error %s\n", uv_err_name(nread));
		}
		uv_close((uv_handle_t*)tunnel->remote, on_close_tcp_remote);
		uv_close((uv_handle_t*)tunnel->local, on_close_tcp_local);
		bufpool_release(buf->base);
		return;
	}

	printf("[TCP][REMOTE][READ] size: %u\n", nread);

	write_data_t * write_data = (write_data_t*)malloc(sizeof(write_data_t));
	ASSERT_MALLOC(write_data);
	init_write_data(uv_buf_init(buf->base, nread), tunnel, write_data);

	uv_write_t *req = (uv_write_t*)malloc(sizeof(uv_write_t));
	ASSERT_MALLOC(req);
	req->data = write_data;
	uv_write(req, tunnel->local, &write_data->buf, 1, on_written_tcp_local_tcp_remote);
}
/**
* On remote incoming data
*/
void on_read_tcp_remote_udp_local(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf)
{
	tunnel_t * tunnel = (tunnel_t*)stream->data;
	if (nread < 0) {
		if (nread != UV_EOF) {
			fprintf(stderr, "Server read error %s\n", uv_err_name(nread));
		}
		uv_close((uv_handle_t*)tunnel->remote, on_close_tcp_remote);
		bufpool_release(buf->base);
		return;
	}

	printf("[TCP][REMOTE][READ] size: %u\n", nread);

	write_data_t * write_data = (write_data_t*)malloc(sizeof(write_data_t));
	ASSERT_MALLOC(write_data);
	init_write_data(uv_buf_init(buf->base, nread), tunnel, write_data);

	uv_udp_send_t * req = (uv_udp_send_t*)malloc(sizeof(uv_udp_send_t));
	ASSERT_MALLOC(req);
	req->data = write_data;
	uv_udp_send(req, (uv_udp_t*)tunnel->local, &write_data->buf, 1, tunnel->local_addr, on_written_udp_local_tcp_remote);
}
/**
* On remote incoming data
*/
void on_read_udp_remote_tcp_local(uv_udp_t* handle, ssize_t nread, const uv_buf_t* buf, const struct sockaddr* addr, unsigned flags)
{
	tunnel_t * tunnel = (tunnel_t*)handle->data;
	if (nread < 0) {
		if (nread != UV_EOF) {
			fprintf(stderr, "Server read error %s\n", uv_err_name(nread));
		}
		uv_close((uv_handle_t*)tunnel->local, on_close_tcp_local);
		bufpool_release(buf->base);
		return;
	}

	printf("[UDP][REMOTE][READ] size: %u\n", nread);

	write_data_t * write_data = (write_data_t*)malloc(sizeof(write_data_t));
	ASSERT_MALLOC(write_data);
	init_write_data(uv_buf_init(buf->base, nread), tunnel, write_data);

	uv_write_t *req = (uv_write_t*)malloc(sizeof(uv_write_t));
	ASSERT_MALLOC(req);
	req->data = write_data;
	uv_write(req, tunnel->local, &write_data->buf, 1, on_written_tcp_local_udp_remote);
}
/**
* On remote incoming data
*/
void on_read_udp_remote_udp_local(uv_udp_t* handle, ssize_t nread, const uv_buf_t* buf, const struct sockaddr* addr, unsigned flags)
{
	tunnel_t * tunnel = (tunnel_t*)handle->data;

	if (nread < 0 || addr == NULL) {
		if (nread != UV_EOF) {
			fprintf(stderr, "Server read error %s\n", uv_err_name(nread));
		}
		bufpool_release(buf->base);
		return;
	}

	//printf("[UDP][REMOTE][READ] size: %u\n", nread);

	write_data_t * write_data = (write_data_t*)malloc(sizeof(write_data_t));
	ASSERT_MALLOC(write_data);
	init_write_data(uv_buf_init(buf->base, nread), tunnel, write_data);

	uv_udp_send_t * req = (uv_udp_send_t*)malloc(sizeof(uv_udp_send_t));
	ASSERT_MALLOC(req);
	req->data = write_data;

	peer_information_t info = get_peer_information(tunnel->local_addr);
	
	//printf("[UDP][REMOTE][INFO]  [%s]:%i\n", info.ip, info.port);

	uv_udp_send(req, (uv_udp_t*)tunnel->local, &write_data->buf, 1, tunnel->local_addr, on_written_udp_local_udp_remote);

}
/**
* On remote data write finished
*/
void on_written_tcp_remote_tcp_local(uv_write_t * req, int status)
{
	write_data_t * write_data = (write_data_t*)req->data;

	if (status >= 0) {
		printf("[TCP][REMOTE][WRITE] size: %u\n", write_data->buf.len);
	}

	bufpool_release(write_data->buf.base);
	free(req);
	free(write_data);
}
/**
* On remote data write finished
*/
void on_written_tcp_remote_udp_local(uv_write_t * req, int status)
{
	write_data_t * write_data = (write_data_t*)req->data;

	if (status >= 0) {
		printf("[TCP][REMOTE][WRITE] size: %u\n", write_data->buf.len);
	}

	bufpool_release(write_data->buf.base);
	free(req);
	free(write_data);
}
/**
* On remote data write finished
*/
void on_written_udp_remote_tcp_local(uv_udp_send_t * req, int status)
{
	write_data_t * write_data = (write_data_t*)req->data;

	if (status >= 0) {
		printf("[UDP][REMOTE][WRITE] size: %u\n", write_data->buf.len);
	}

	bufpool_release(write_data->buf.base);
	free(req);
	free(write_data);
}
/**
* On remote data write finished
*/
void on_written_udp_remote_udp_local(uv_udp_send_t * req, int status)
{
	write_data_t * write_data = (write_data_t*)req->data;

	if (status >= 0) {
		//printf("[UDP][REMOTE][WRITE] size: %u\n", write_data->buf.len);
	}

	bufpool_release(write_data->buf.base);
	free(req);
	free(write_data);
}
/**
* On remote client closed from remote event
*/
void on_close_tcp_remote(uv_handle_t* handle)
{
	tunnel_t * tunnel = handle->data;
	tunnel->remote_closed = 1;
	free(tunnel->remote);
	if (tunnel->local_closed) {
		free(tunnel);
	}
}
