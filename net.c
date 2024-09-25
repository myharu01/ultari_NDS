#include "net.h"
#include "include/net.h"
#include "mongoose.h"
#include <stdio.h>
#include <string.h>
#include <errno.h>


/**
 * @brief This function retrieves the client's MAC address given their IP address.
 *
 * This function uses the system's neighbor cache to find the MAC address associated
 * with a given IP address. It executes the "ip neigh show" command and parses the output
 * to find the corresponding MAC address.
 *
 * @param mac A buffer to store the retrieved MAC address.
 * @param addr The IP address (mg_addr) to look up.
 * @return 0 on success, -1 on failure.
 */
int 
get_client_mac_by_ipv4(uint8_t mac[MAC_ADDR_SIZE], struct mg_addr *addr) {
    char line[MAX_LINE_LEN] = {0};
    char req_ip[IPV6_ADDR_STR_LEN + 1];  // Large enough for both IPv4 and IPv6
    FILE *stream;
    const char *conversion_result;
    size_t len;
    int result;
    char mac_str[MAC_ADDR_STR_LEN + 1];
    unsigned int values[MAC_ADDR_SIZE];


    // Convert IP address from mg_addr to string
    if (addr->is_ip6) {
        conversion_result = inet_ntop(AF_INET6, addr->ip, req_ip, INET6_ADDRSTRLEN);
    } else {
        conversion_result = inet_ntop(AF_INET, addr->ip, req_ip, INET_ADDRSTRLEN);
    }
    
    if (conversion_result == NULL) {
        MG_ERROR(("Error: Failed to convert IP address: %s\n", strerror(errno)));
        return -1;
    }
    
    // Safely add a space at the end of the IP string
    len = strlen(req_ip);
    if (len >= INET6_ADDRSTRLEN) {
        MG_ERROR(("Error: IP address is too long!\n"));
        return -1;
    }
    req_ip[len] = ' ';
    req_ip[len + 1] = '\0';
    // Open a pipe to the "ip neigh show" command
    stream = popen(IP_CMD, "r");
    if (!stream) {
        MG_ERROR(("Error: Failed to initiate command '%s': %s\n", IP_CMD, strerror(errno)));
        return -1;
    }
    result = -1;

    // Read the output line by line
    while (fgets(line, sizeof(line), stream) != NULL) {
        if (strncmp(line, req_ip, len + 1) == 0) {
            if (sscanf(line, "%*s %*s %*s %*s %17[A-Fa-f0-9:]", mac_str) == 1) {
                // Convert MAC address from string to uint8_t array
                if (sscanf(mac_str, "%x:%x:%x:%x:%x:%x", &values[0], &values[1], &values[2],
                           &values[3], &values[4], &values[5]) == MAC_ADDR_SIZE) {
                    for (int i = 0; i < MAC_ADDR_SIZE; ++i) {
                        mac[i] = (uint8_t)values[i];
                    }
                    result = 0;
                    break;  // MAC address found, exit the loop
                }
            }
        }
    }

    MG_DEBUG(("FOUND : Client MAC address :[%s] and ip address : [%s]\n", mac_str, req_ip));
    
    pclose(stream);
    if (result != 0) {
        MG_ERROR(("Error: MAC address not found for IP [%s]!\n", req_ip));
    }
    return result;
}


/* Function to convert uint8_t MAC address to string */
int mac_to_str(const uint8_t mac[MAC_ADDR_SIZE], char mac_str[MAC_ADDR_STR_LEN]) {
    if (mac == NULL || mac_str == NULL){
        MG_ERROR(("NULL check: mac or mac_str address is NULL!"));
        return -1;
    }
    mg_snprintf(mac_str, MAC_ADDR_STR_LEN, "%M", mg_print_mac, mac);

    return 0;
}

/* Function to convert uint8_t IP address (IPv4) to string */
int ipv4_to_str(struct mg_addr *addr, char buf[IPV4_ADDR_STR_LEN]) {
    if (buf == NULL || addr == NULL){
        MG_ERROR(("NULL check: addr or buf address is NULL!"));
        return -1;
    }
    mg_snprintf(buf, IPV4_ADDR_STR_LEN, "%M", mg_print_ip4, addr);

    return 0;
}

/* Function to convert uint8_t IP address (IPv6) to string */
int ipv6_to_str(struct mg_addr *addr, char buf[IPV6_ADDR_STR_LEN]) {
    if (buf == NULL || addr == NULL){
        MG_ERROR(("NULL check: addr or buf address is NULL!"));
        return -1;
    }
    mg_snprintf(buf, IPV6_ADDR_STR_LEN, "%M", mg_print_ip6, addr);

    return 0;
}

/* Function to convert IPv4 string to uint8_t array */
int str_to_ipv4(const char *ip_str, uint8_t ip_array[IPV4_ADDR_SIZE]) {
    char *token;
    char ip_copy[IPV4_ADDR_STR_LEN]; 
    int i = 0;

    // Create a copy of the input string to avoid modifying the original
    strncpy(ip_copy, ip_str, sizeof(ip_copy));
    ip_copy[15] = '\0';  // Ensure null termination for safety

    // Tokenize the string by "."
    token = strtok(ip_copy, ".");
    while (token != NULL) {
        if (i >= 4) {
            // IPv4 address must have exactly 4 parts
            MG_ERROR(("str to ipv4 tokenize failed: ipv4 address format wrong!"));
            return -1;
        }

        int num = atoi(token);
        if (num < 0 || num > 255) {
            MG_ERROR(("str to ipv4 tokenize failed: ipv4 address format wrong! \
            (exceeds 255 or less than 0)"));
            // Each part must be between 0 and 255
            return -1;
        }

        // Store the converted number into the array
        ip_array[i++] = (uint8_t)num;

        token = strtok(NULL, ".");
    }

    // Ensure that exactly 4 parts were processed
    if (i != 4) {
        MG_ERROR(("str to ipv4 tokenize failed: ipv4 address format wrong!"));
        return -1;
    }

    return 0; // Success
}

/* Function to convert MAC address string to uint8_t array */
int str_to_mac(const char mac_str[MAC_ADDR_STR_LEN], uint8_t mac_array[MAC_ADDR_SIZE]) {
    char *token;
    char mac_copy[MAC_ADDR_STR_LEN]; 
    int i = 0;
    int num;

    // Create a copy of the input string to avoid modifying the original
    strncpy(mac_copy, mac_str, sizeof(mac_copy));
    mac_copy[MAC_ADDR_STR_LEN - 1] = '\0';  // Ensure null termination for safety

    // Tokenize the string by ":"
    token = strtok(mac_copy, ":");
    while (token != NULL) {
        if (i >= 6) {
            // MAC address must have exactly 6 parts
            MG_ERROR(("str to mac tokenize failed: mac address format wrong!"));
            return -1;
        }

        // Convert the hex string to an integer
        num = strtol(token, NULL, 16);
        if (num < 0 || num > 255) {
            // Each part must be between 00 and FF
            return -1;
        }

        // Store the converted number into the array
        mac_array[i++] = (uint8_t)num;

        token = strtok(NULL, ":");
    }

    // Ensure that exactly 6 parts were processed
    if (i != 6) {
        MG_ERROR(("str to mac tokenize failed: mac address format wrong!"));
        return -1;
    }

    return 0; // Success
}
