
/** @file client_list.h
    @brief Client List functions
    @author Copyright (C) 2004 Alexandre Carmel-Veilleux <acv@acv.ca>
    @author Copyright (C) 2007 Paul Kube <nodogsplash@kokoro.ucsd.edu>
*/

#ifndef _CLIENT_LIST_H_
#define _CLIENT_LIST_H_

#include <time.h>
#include "mongoose.h"
#include "generic_list.h"
#include "net.h"

// Client node for the connected client linked list.

typedef struct _t_client {
	struct mg_connection *connection; /**< @brief represent this client connection info */ 
	char* token;		/**< @brief Client token */
	time_t session_start;	/**< @brief Time the client was authenticated */
	time_t session_end;		/**< @brief Time until client will be deauthenticated */
	struct mg_addr client_ip;
	uint8_t* client_mac; /* client mac */
	struct list_head list; /**< @brief list struct kb/s */
} t_client;


/** @brief Initializes the client list */
void client_list_init(void);

/** @brief Returns number of clients currently on client list */
int get_client_list_length(void);

/** @brief Adds a new client to the client list */
t_client *add_client_to_list(struct mg_connection *client_c, char* token);

/** @brief Finds a client by its MAC, IP or token */
t_client *client_list_find_by_any(const char target_mac[MAC_ADDR_SIZE], 
const char target_ip[IPV4_ADDR_SIZE], const char* target_token);

/** @brief Finds a client by its MAC and IP */
t_client * client_list_find(const char mac[MAC_ADDR_SIZE], const char ip[IPV4_ADDR_SIZE]);

/** @brief Finds a client only by its IP */
t_client *client_list_find_by_ip(const char ip[IPV4_ADDR_SIZE]); /* needed by fw_iptables.c, auth.c * and ndsctl_thread.c */

/** @brief Finds a client only by its MAC */
t_client *client_list_find_by_mac(const char mac[MAC_ADDR_SIZE]); /* needed by ndsctl_thread.c */

/** @brief Finds a client by its token */
t_client *client_list_find_by_token(const char* token);

/** @brief Deletes a client from the client list */
void delete_client_from_list(t_client *client);

/** @brief Prints all client from the client list. For debugging. */
void print_all_clients(void);


#define LOCK_CLIENT_LIST() do { \
	MG_DEBUG(("Locking client list")); \
	pthread_mutex_lock(&client_list_mutex); \
	MG_DEBUG(("Locked client list"));  \
} while (0)

#define UNLOCK_CLIENT_LIST() do { \
	MG_DEBUG(("Unlocking client list")); \
	pthread_mutex_unlock(&client_list_mutex); \
	MG_DEBUG(("Locked client list"));  \
} while (0)

extern pthread_mutex_t client_list_mutex;



#endif /* _CLIENT_LIST_H_ */