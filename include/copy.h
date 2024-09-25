#ifndef COPY_H
#define COPY_H

#include "mongoose.h"  // Including the mongoose library for mg_str and mg_http_message

// Function prototypes for copying and freeing mg_http_message
struct mg_http_message *copy_http_message(const struct mg_http_message *src);
void free_http_message(struct mg_http_message *msg);

#endif // COPY_H