#ifndef _NET_H
#define _NET_H

#include <mongoose.h>
#include <arpa/inet.h>


#define IPV4_ADDR_SIZE 4 // size of byte array for holding ipv4 address (4 byte == 32bit)
#define IPV6_ADDR_SIZE 16 // size of byte array for holding ipv6 address (16 byte == 128 bit)
#define MAC_ADDR_SIZE 6 // size of byte array for holding mac address (6 byte == 48bit )

/* BELOW MACRO SIZE INCLUDES NULL POINTER SENTINEL! */
#define MAC_ADDR_STR_LEN 18
#define IPV4_ADDR_STR_LEN INET_ADDRSTRLEN
#define IPV6_ADDR_STR_LEN INET6_ADDRSTRLEN
#define IP_CMD "ip neigh show"
/* end of IP,MAC size */


#define MAX_LINE_LEN 256



/* Functions */
int get_client_mac_by_ipv4(uint8_t mac[MAC_ADDR_SIZE], struct mg_addr *addr);
int mac_to_str(const uint8_t mac[MAC_ADDR_SIZE], char mac_str[MAC_ADDR_STR_LEN]);
int ipv4_to_str(struct mg_addr *addr, char buf[IPV4_ADDR_STR_LEN]);
int ipv6_to_str(struct mg_addr *addr, char buf[IPV6_ADDR_STR_LEN]);
int str_to_mac(const char mac_str[MAC_ADDR_STR_LEN], uint8_t mac_array[MAC_ADDR_SIZE]);
int str_to_ipv4(const char *ip_str, uint8_t ip_array[IPV4_ADDR_SIZE]);
#endif
