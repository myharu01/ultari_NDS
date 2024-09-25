#include "copy.h"
#include <stdlib.h>  // For malloc, free

// Deep copy function for mg_http_message
// This function duplicates the entire mg_http_message structure using mg_strdup for mg_str fields.
struct mg_http_message *copy_http_message(const struct mg_http_message *src) {
    if (src == NULL) {
        return NULL;  // Return NULL if source is NULL
    }

    // Allocate memory for the new mg_http_message
    struct mg_http_message *dest = (struct mg_http_message *)malloc(sizeof(struct mg_http_message));
    if (dest == NULL) {
        return NULL;  // Memory allocation failed
    }

    // Deep copy for method, uri, query, proto using mg_strdup
    dest->method = mg_strdup(src->method);
    dest->uri = mg_strdup(src->uri);
    dest->query = mg_strdup(src->query);
    dest->proto = mg_strdup(src->proto);

    // Deep copy for each header's name and value using mg_strdup
    for (int i = 0; i < MG_MAX_HTTP_HEADERS; i++) {
        dest->headers[i].name = mg_strdup(src->headers[i].name);
        dest->headers[i].value = mg_strdup(src->headers[i].value);
    }

    // Deep copy for body, head, and message using mg_strdup
    dest->body = mg_strdup(src->body);
    dest->head = mg_strdup(src->head);
    dest->message = mg_strdup(src->message);

    return dest;
}

// Free memory allocated for mg_http_message
// Frees all dynamically allocated fields and the main mg_http_message structure.
void free_http_message(struct mg_http_message *msg) {
    if (msg != NULL) {
        // Free all dynamic fields within the structure using free
        free((char *)msg->method.buf);
        free((char *)msg->uri.buf);
        free((char *)msg->query.buf);
        free((char *)msg->proto.buf);

        // Free each header's name and value
        for (int i = 0; i < MG_MAX_HTTP_HEADERS; i++) {
            free((char *)msg->headers[i].name.buf);
            free((char *)msg->headers[i].value.buf);
        }

        // Free the body, head, and message fields
        free((char *)msg->body.buf);
        free((char *)msg->head.buf);
        free((char *)msg->message.buf);

        // Free the main structure
        free(msg);
        
        //debugging message
        MG_DEBUG(("mg_http_message successfully free'ed!"));
    }
}