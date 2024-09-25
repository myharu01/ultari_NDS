#include <stdlib.h>
#include <string.h>
#include "client_list.h"
#include "authserver.h"
#include "mongoose.h"
#include "net.h"
#include <pthread.h>

// Head of the client list
LIST_HEAD(client_list);

/* Number of clients in Router */
static int client_count = 0;

/** Global mutex to protect access to the client list */
pthread_mutex_t client_list_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Init the client list */
void client_list_init(void) {
    INIT_LIST_HEAD(&client_list);
    client_count = 0;
    MG_INFO(("Client list init succeded!"));
}

/* Returns number of clients currently on client list */
int get_client_list_length(void) {
    return client_count;
}

/* Adds a new client to the client list */
t_client *add_client_to_list(struct mg_connection *client_c, char* token){
    t_client *new_client = (t_client *)malloc(sizeof(t_client));
    uint8_t client_mac[MAC_ADDR_SIZE];

    get_client_mac_by_ipv4(client_mac, &client_c->rem);
    
    if (!new_client) {
        MG_ERROR(("Failed to allocate new_client memory!"));
        return NULL;
    }
    memset(new_client, 0, sizeof(t_client));

    /* Set client struct value */
    new_client->session_start = time(NULL);
    new_client->session_end = new_client->session_start + JWT_EXPIRATION_TIME;
    new_client->token = token;
    new_client->client_ip = client_c -> rem;
    new_client->client_mac = client_mac;
    new_client->connection = client_c;
    
    /* Add the new client to the list */
    list_add_tail(&new_client->list, &client_list);
    client_count++;

    return new_client;
}

/** @brief Finds a client by its MAC, IP or token. IP nor MAC is not string type.*/
t_client *client_list_find_by_any(const char target_mac[MAC_ADDR_SIZE], 
const char target_ip[IPV4_ADDR_SIZE], const char* target_token) {
    t_client *client;
    uint8_t each_client_mac[MAC_ADDR_SIZE];
    uint8_t each_client_ip[IPV4_ADDR_SIZE];

    list_for_each_entry(client, &client_list, list) {
        if (client->connection->rem.is_ip6 == true){
            MG_ERROR(("Client has ipv6 address! Something get wrong?"));
            break;
        }
        get_client_mac_by_ipv4(each_client_mac, (struct mg_addr *)client->connection);
        memcpy(each_client_ip, client->connection->rem.ip, IPV4_ADDR_SIZE);
        
        if ((target_mac && memcmp(target_mac, each_client_mac, MAC_ADDR_SIZE) == 0) ||
            (target_ip && memcmp(target_ip, each_client_ip, IPV4_ADDR_SIZE) == 0) ||
            (target_token && strcmp(client->token, target_token) == 0)) {
            return client;
        }
    }

    MG_INFO(("Requested Client has not found by given information"));
    return NULL;
}


/** @brief Finds a client only by its local IP */
t_client *client_list_find_by_ip(const char local_ip[IPV4_ADDR_SIZE]) {
    return client_list_find_by_any(NULL, local_ip, NULL);
}

/** @brief Finds a client only by its MAC */
t_client *client_list_find_by_mac(const char mac[MAC_ADDR_SIZE]) {
    return client_list_find_by_any(mac, NULL, NULL);
}

/** @brief Finds a client by its token */
t_client *client_list_find_by_token(const char* token) {
    return client_list_find_by_any(NULL, NULL, token);
}


/** @brief Deletes a client from the client list */
void delete_client_from_list(t_client *client) {
    if (client) {
        list_del(&client->list);
        client_count--;

        free(client->token);
        free(client);
    }
}

/** @brief Prints all client from the client list. For debugging. */
void print_all_clients(void) {
    t_client *client;
    char mac_str[MAC_ADDR_STR_LEN]; // MAC address format (e.g., "AA:BB:CC:DD:EE:FF")
    time_t now = time(NULL);
    char ipv4_str[IPV4_ADDR_STR_LEN];

    if (list_empty(&client_list)) {
        MG_DEBUG(("The client list is empty.\n"));
    } 
    else {
        MG_DEBUG(("There are currently %d clients in the list:\n", client_count));

        /* traversal the client list */
        list_for_each_entry(client, &client_list, list) {
            // Retrieve the IP address
            ipv4_to_str(&client->client_ip, ipv4_str);
            mac_to_str(client->client_mac, mac_str);

            if (client->connection->rem.is_ip6) {
                MG_ERROR(("Client has ipv6 address! Something get wrong?"));
                return ;
            }

            // Print the client information
            printf("Client:\n");
            printf("  IP Address: %s\n", ipv4_str);
            printf("  MAC Address: %s\n", mac_str);
            printf("  Token: %s\n", client->token);
            printf("  Session Start Time: %s", ctime(&client->session_start));
            printf("  Session End Time: %s", ctime(&client->session_end));
            printf("  Time Remaining: %ld seconds\n", client->session_end - now);
        }
    }
}