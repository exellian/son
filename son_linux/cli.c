#include "util.h"
#include "cli.h"
#include <uv.h>

int parse_endpoint(char * arg, endpoint_t * endpoint);
void print_help();

int parse_endpoints(int argc, char * argv[], endpoint_t * local, endpoint_t * remote)
{
	if (argc == 2) {
		if (strcmp(argv[1], "-help") == 0) {
			print_help();
		}
	} else if (argc == 3) {
		if (parse_endpoint(argv[1], local) != 0) {
			return PARSE_ERROR;
		}
		if (parse_endpoint(argv[2], remote) != 0) {
			return PARSE_ERROR;
		}
	} else {
		fprintf(stderr, "Missing command line parameters! Type -help\n");
		return PARSE_ERROR;
	}
	return 0;
}

int is_tcp_protocol(char * protocol)
{
	if (strcmp(protocol, "tcp6") == 0 || strcmp(protocol, "tcp4") == 0 || strcmp(protocol, "tcp") == 0) {
		return 1;
	}
	return 0;
}

int is_normal(char c, int ipv6)
{
	if (c != '\0' && c != '[' && c != ']') {
		return 1;
	}
	if (ipv6 = 0 && c != ':') {
		return 1;
	}
	return 0;
}

int parse_endpoint(char * arg, endpoint_t * endpoint)
{
	char *protocol = NULL;
	char *address = NULL;
	char *port = NULL;
	char c;
	int port_parsed;
	int ipv6_address = 0;
	int i;
	int knoten = 0;
	int len = strlen(arg);

	int tcp = 0;

	for (i = 0; i < len + 1; i++) {
		c = arg[i];
		if (knoten == 0) {
			if (is_normal(c, 0)) {
				knoten = 1;
			}
			else {
				fprintf(stderr, "Endpoint invalid protocol definition!\n");
				return PARSE_ERROR;
			}
		}
		else if (knoten == 1) {
			if (c == ':') {
				arg[i] = '\0';
				protocol = arg;
				knoten = 2;
			}
			else if (is_normal(c, 0)) {
				continue;
			}
			else {
				fprintf(stderr, "Endpoint invalid protocol definition!\n");
				return PARSE_ERROR;
			}
		}
		else if (knoten == 2) {
			if (c == '[') {
				ipv6_address = 1;
				address = arg + i;
				knoten = 4;
			}
			else if (is_normal(c, 0)) {
				address = arg + i;
				knoten = 3;
			}
			else {
				fprintf(stderr, "Endpoint invalid address definition!\n");
				return PARSE_ERROR;
			}
		}
		else if (knoten == 3) {
			if (c == '\0') {
				port = address;
				address = NULL;
				knoten = 8;
			}
			else if (c == ':') {
				arg[i] = '\0';
				knoten = 6;
			}
			else if (is_normal(c, 0)) {
				continue;
			}
			else {
				fprintf(stderr, "Endpoint invalid address definition!\n");
				return PARSE_ERROR;
			}
		}
		else if (knoten == 4) {
			if (c == ']') {
				knoten = 5;
			}
			else if (is_normal(c, 1)) {
				continue;
			}
			else {
				fprintf(stderr, "Endpoint invalid address definition!\n");
				return PARSE_ERROR;
			}
		}
		else if (knoten == 5) {
			if (c == ':') {
				arg[i] = '\0';
				knoten = 6;
			}
			else {
				fprintf(stderr, "Endpoint invalid address definition!\n");
				return PARSE_ERROR;
			}
		}
		else if (knoten == 6) {
			if (is_normal(c, 0)) {
				port = arg + i;
				knoten = 8;
			}
			else {
				fprintf(stderr, "Endpoint invalid port definition!\n");
				return PARSE_ERROR;
			}
		}
	}
	if (knoten != 8) {
		fprintf(stderr, "Unknown format!%i\n", knoten);
		return PARSE_ERROR;
	}
	port_parsed = atoi(port);
	if (port_parsed <= 0) {
		fprintf(stderr, "Endpoint invalid port!\n");
		return PARSE_ERROR;
	}

	if (is_tcp_protocol(protocol)) {
		if (strcmp(protocol, "tcp4") == 0 && (ipv6_address && address != NULL)) {
			fprintf(stderr, "Can't use ipv6 address as bind address for tcp4 protocol!\n");
			return PARSE_ERROR;
		}
		if (strcmp(protocol, "tcp6") == 0 && (!ipv6_address && address != NULL)) {
			fprintf(stderr, "Can't use ipv4 address as bind address for tcp6 protocol!\n");
			return PARSE_ERROR;
		}
		tcp = 1;
	}
	else {
		if (strcmp(protocol, "udp4") == 0 && (ipv6_address && address != NULL)) {
			fprintf(stderr, "Can't use ipv6 address as bind address for udp4 protocol!\n");
			return PARSE_ERROR;
		}
		if (strcmp(protocol, "udp6") == 0 && (!ipv6_address && address != NULL)) {
			fprintf(stderr, "Can't use ipv4 address as bind address for udp6 protocol!\n");
			return PARSE_ERROR;
		}
		tcp = 0;
	}

	if (address == NULL) {
		if (strcmp(protocol, "udp4") == 0 || strcmp(protocol, "tcp4") == 0) {
			address = "0.0.0.0";
		} else if (strcmp(protocol, "udp6") == 0 || strcmp(protocol, "tcp6") == 0) {
			address = "[::0]";
			ipv6_address = 1;
		} else {
			address = "0.0.0.0";
		}
	}
	if (ipv6_address) {
		size_t len = strlen(address);
		address = address + 1;
		address[len - 2] = '\0';
		struct sockaddr_in6 addr;
		uv_ip6_addr(address, port_parsed, &addr);
		if (init_endpoint_ipv6(&addr, tcp, endpoint)) {
			return PARSE_ERROR;
		}
	} else {
		struct sockaddr_in addr;
		uv_ip4_addr(address, port_parsed, &addr);
		if (init_endpoint_ipv4(&addr, tcp, endpoint)) {
			return PARSE_ERROR;
		}
	}
	return 0;
}

void print_help()
{
	printf("Use the following commands to rewrite packets: \n\n");
	printf("A rewrite command has the following format:\n\n");
	printf("    protocol:address:port protocol:address:port\n\n");
	printf("protocol:\n\n");
	printf("    tcp          Uses tcp on both ipv6 and ipv4\n");
	printf("    udp          Uses udp on both ipv6 and ipv4\n");
	printf("    tcp4         Uses tcp on ipv4\n");
	printf("    tcp6         Uses tcp on ipv6\n");
	printf("    udp4         Uses udp on ipv4\n");
	printf("    udp6         Uses udp on ipv6\n");
	printf("\naddress (optional) (default value: 0.0.0.0 and [::0]):\n\n");
	printf("    127.0.0.1    Ipv4 format example\n");
	printf("    [::1]        Ipv6 format example\n");
	printf("\nport:\n\n");
	printf("    8080         Port example\n");
}