#include "include/authserver.h"
#include "client_list.h"
#include "include/mongoose.h"
#include "mongoose.h"
#include "authserver.h"
#include <net.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <jwt.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <pthread.h>
#include <unistd.h>
#include "get_info.h"
#include "copy.h"
#include "input_validation.h"
#include "firewall.h"

static void ev_handler(struct mg_connection *c, int ev, void *ev_data);
static void handle_login(struct mg_connection *c, struct mg_http_message *hm);
static void handle_logout(struct mg_connection *c);
static char* create_jwt();
static char* create_relpath(struct mg_http_serve_opts* opts, const char* path);
static void* do_login(void *arg);


typedef struct {
    struct mg_connection *c;
    struct mg_http_message *hm;
} login_thread_args_t;



static char* create_relpath(struct mg_http_serve_opts* opts, const char* path) {
    size_t len = strlen(opts->root_dir) + strlen(path) + 2;
    char *relpath = (char*) malloc(len);

    strcpy(relpath, opts->root_dir);
    if (opts->root_dir[strlen(opts->root_dir) - 1] != '/') 
        strcat(relpath, "/");

    strcat(relpath, path);
    return relpath;
}


static char* create_jwt(void) {
    jwt_t *jwt;
    char *encoded = NULL;
    time_t now = time(NULL);

    // span JWT object
    if (jwt_new(&jwt)) {
        return NULL;
    }

    // Add field to JWT payload
    jwt_add_grant_int(jwt, "iat", now);            // Issued date (issued at)
    jwt_add_grant_int(jwt, "exp", now + JWT_EXPIRATION_TIME);  // Expiration time

    if (jwt_set_alg(jwt, JWT_ALG_HS256, (unsigned char *)JWT_SECRET_KEY, strlen(JWT_SECRET_KEY))) {
        jwt_free(jwt);
        return NULL;
    }

    // JWT encoding
    encoded = jwt_encode_str(jwt);

    // free JWT
    jwt_free(jwt);

    return encoded;
}

/* Extract the access_token from the HTTP message and return it as a char* */
static char* extract_token_from_http(struct mg_http_message *hm) {
    struct mg_str *cookie = mg_http_get_header(hm, "Cookie");
    struct mg_str val;
    char *token = NULL;
    size_t token_len = 0;

    /* Retrieve the cookie */
    if (cookie == NULL) {
        MG_DEBUG(("Cannot find cookie!"));
        return NULL;
    } else {
        MG_DEBUG(("[Cookie: %.*s]", (int)cookie->len, cookie->buf));
        val = mg_http_get_header_var(*cookie, mg_str("access_token"));
    }

    /* If access_token cannot be found */
    if (val.len <= 0) {
        MG_DEBUG(("Cannot find access token!"));
        return NULL;
    }

    /* Allocate memory for the token, with an extra byte for null termination */
    token = (char *)malloc(val.len + 1);
    if (token == NULL) {
        MG_ERROR(("Failed to allocate memory for token!"));
        return NULL;
    }

    /* Copy the token value from val.buf up to the first occurrence of '\r' or '\n' */
    for (size_t i = 0; i < val.len; i++) {
        if (val.buf[i] == '\r' || val.buf[i] == '\n') {
            break;
        }
        token[token_len++] = val.buf[i];
    }
    token[token_len] = '\0';  // Null-terminate the token

    MG_DEBUG(("Extracted Token: %s", token));

    return token;  // Return the extracted token
}

/* Find token from http message and verify it */
static int verify_jwt(struct mg_http_message *hm) {
    struct mg_str *cookie = mg_http_get_header(hm, "Cookie");
    struct mg_str val;
    jwt_t *jwt;
    time_t now;
    int decode_result;
    char token[1024];  // Buffer to temporarily store the token (size should be adjusted as needed)
    size_t token_len = 0;

    /* Retrieve the cookie */
    if (cookie == NULL) {
        MG_DEBUG(("Cannot find cookie!"));
        return -1;
    } else {
        MG_DEBUG(("[Cookie:%.*s]", (int)cookie->len, cookie->buf));
        val = mg_http_get_header_var(*cookie, mg_str("access_token"));
    }

    /* If access_token cannot be found */
    if (val.len <= 0) {
        MG_DEBUG(("Cannot find access token!"));
        return -1;
    }

    // Process the token: copy from val.buf up to the first occurrence of '\r' or '\n'
    for (size_t i = 0; i < val.len; i++) {
        if (val.buf[i] == '\r' || val.buf[i] == '\n') {
            break;
        }
        token[token_len++] = val.buf[i];
    }
    token[token_len] = '\0';  // Add '\0' to mark the end of the new token

    MG_DEBUG(("Processed Token: %s", token));

    // Decode the token
    decode_result = jwt_decode(&jwt, token, (unsigned char *)JWT_SECRET_KEY, strlen(JWT_SECRET_KEY));

    if (decode_result != 0) {
        MG_ERROR(("Failed to verify token! ERROR : %d", decode_result));
        return -1;  // Failed to verify the token
    }

    // Check the expiration time
    now = time(NULL);
    if (jwt_get_grant_int(jwt, "exp") < now) {
        jwt_free(jwt);
        return -1;  // Token has expired
    }

    MG_INFO(("Succeeded to verify token!"));
    jwt_free(jwt);
    return 0;
}



int authserv_init(struct mg_mgr *mgr) {
  void *res_http;
  void *res_https;

  res_http = mg_http_listen(mgr, HTTP_URL, ev_handler, NULL);
  res_https = mg_http_listen(mgr, HTTPS_URL, ev_handler, (void *) 1);

  if (res_http == NULL){
    MG_ERROR(("Failed to start http listener!"));
    return -1;
  }
  if (res_https == NULL){
    MG_ERROR(("Failed to start https listener!"));
    return -1;
  }
  return 0;
}

// HTTP request handler function
static void ev_handler(struct mg_connection *c, int ev, void *ev_data) {

    if (ev == MG_EV_ACCEPT) {
        if (c->fn_data != NULL) { /* TLS CONNECT */
            struct mg_str cert = mg_file_read(&mg_fs_posix, "cert.pem");
            struct mg_str key = mg_file_read(&mg_fs_posix, "key.pem");
            struct mg_tls_opts opts = {.cert = cert,
                                        .key = key};
            mg_tls_init(c, &opts);
        }
    }

    else if (ev == MG_EV_HTTP_MSG) {
        struct mg_http_message *hm = (struct mg_http_message *) ev_data;

        if (mg_match(hm->uri, mg_str("/login"), NULL)){
            handle_login(c, hm);
        } 

        else if (mg_match(hm->uri, mg_str("/logout"), NULL)){
            handle_logout(c);
        } 

        else if (mg_match(hm->uri, mg_str("/status"), NULL)){
            /* TODO: Some get current client's status*/
        }

        else {
            struct mg_http_serve_opts opts = {
                .root_dir = WEB_ROOT_DIR  // set to web_root dir to WEB_ROOT_DIR
            };
            //mg_http_serve_file(c, hm, "web_root/login.html",&opts);
            mg_http_serve_dir(c, hm, &opts);
        }

    }
}

/* handle function */


static void handle_login(struct mg_connection *c, struct mg_http_message *hm) {
    // Allocate memory for arguments to pass to the thread
    pthread_t thread_id;
    login_thread_args_t *args = malloc(sizeof(login_thread_args_t));
    char student_id[100], password[100];
    mg_http_get_var(&hm->body, "studentId", student_id, sizeof(student_id));
    mg_http_get_var(&hm->body, "password", password, sizeof(password));
    
    if (args == NULL) {
        mg_http_reply(c, 500, "", "Internal server error!"); 
        MG_ERROR(("Failed to allocate memory."));
        return;
    }
    // Initialize and copy the arguments 
    args->c = c;
    args->hm = copy_http_message(hm);

    // Create a thread to handle the login
    if (pthread_create(&thread_id, NULL, do_login, (void *)args) != 0) {
        mg_http_reply(c, 500, "", "Internal server error!"); 
        MG_ERROR(("Failed to create thread!"));
        free(args);  // Clean up on failure
        return;
    }
    // Detach the thread to allow it to clean up after itself
    pthread_detach(thread_id);
}

// Function to handle login
static void *do_login(void *arg) {
    login_thread_args_t *args = (login_thread_args_t *) arg;
    struct mg_connection *c = args->c;
    struct mg_http_message* hm = args->hm;
    struct mg_http_serve_opts opts;
    opts.root_dir = WEB_ROOT_DIR;
    char student_id[100], password[100];
    char cookie[512];
    char *jwt_token;
    char *existed_token;
    char *path = malloc(sizeof(char) * 200);
    char *file;
    t_client* client;
    bool id_flag, pw_flag = false;

    /* First, verifying user if has access token */
    if (verify_jwt(hm) == 0){
        existed_token = extract_token_from_http(hm);
        client = client_list_find_by_token(existed_token);

        printf("token : %s", existed_token);

        if (client != NULL){
            LOCK_CLIENT_LIST();
            delete_client_from_list(client);
            add_client_to_list(c, existed_token);
            /* For debugging purpose, use print_all_clients() */
            print_all_clients();
            UNLOCK_CLIENT_LIST();
        }
        else {
            LOCK_CLIENT_LIST();
            add_client_to_list(c, existed_token);
            print_all_clients();
            /* For debugging purpose, use print_all_clients() */
            UNLOCK_CLIENT_LIST();
        }
        mg_http_reply(c, 200, "", "You already logged in!");
        /* TODO : redirect client to another website (Like sangmyung univ homepage) */


        return NULL;
    }

    // Extract studentId and password from the POST request body
    // We already checked validality of student id and password 
    mg_http_get_var(&hm->body, "studentId", student_id, sizeof(student_id));
    mg_http_get_var(&hm->body, "password", password, sizeof(password));

        // Check if input data is invalid
    id_flag = validate_student_id(student_id);
    pw_flag = validate_password(password);

    if ((!id_flag) && (!pw_flag)){
        file = "error/fail_invalid_input.html";
	    path = create_relpath(&opts,file);
	    mg_http_serve_file(c, hm, path, &opts);
        return NULL;
    }


    // Verify user credentials
    int auth_result = is_valid_user(student_id, password, c);
    // If authentication is successful
    if (auth_result == LOGIN_SUCCESS) {
        // Create a JWT token
        jwt_token = create_jwt();
        if (jwt_token == NULL) {
	        file = "error/fail_jwt.html";
	        path = create_relpath(&opts,file);
	        mg_http_serve_file(c, hm, path, &opts);
        }
        // Set the JWT in the cookie
        mg_snprintf(cookie, sizeof(cookie),
                    "Set-Cookie: access_token=%s; Path=/; HttpOnly; Max-Age=%d; %s\r\n",
                    jwt_token, JWT_EXPIRATION_TIME, c->is_tls ? "Secure;" : "");
        // Respond to the client with the cookie
        mg_http_reply(c, 200, cookie, "Login successful!");

        LOCK_CLIENT_LIST();
        add_client_to_list(c, jwt_token);
        //allow_mac_ip_rule(mac_str, ipv4_str);

        /* For debugging purpose, use print_all_clients() */
        print_all_clients();
        UNLOCK_CLIENT_LIST();

        // Free the JWT string memory
        free(jwt_token);
    }
    // If student ID is invalid
    else if (auth_result == WRONG_ID_FORMAT) {
	    file = "error/fail_invalid_input.html";
	    path = create_relpath(&opts,file);
	    mg_http_serve_file(c, hm, path, &opts);
    }
    // If password is incorrect
    else if (auth_result == WRONG_CREDENTIAL) {
	    file = "error/fail_invalid_input.html";
	    path = create_relpath(&opts,file);
	    mg_http_serve_file(c, hm, path, &opts);
    }
    // For any other unexpected errors
    else {
	    file = "error/fail_unexpect.html";
	    path = create_relpath(&opts,file);
	    mg_http_serve_file(c, hm, path, &opts);
    }

    free_http_message(hm);
    return NULL;
}


static void handle_logout(struct mg_connection *c) {
  char cookie[256];
  mg_snprintf(cookie, sizeof(cookie),
              "Set-Cookie: access_token=; Path=/; "
              "Expires=Thu, 01 Jan 1970 00:00:00 UTC; "
              "%sHttpOnly; Max-Age=0; \r\n",
              c->is_tls ? "Secure; " : "");
  mg_http_reply(c, 200, cookie, "true\n");
}

