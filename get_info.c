#include "get_info.h"
#include "mongoose.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include "net.h"

#ifdef USE_PARSE_USER_INFO
#include <libxml/HTMLparser.h>
#include <libxml/xpath.h>
#endif

 struct memory_struct{
    char *memory;
    size_t size;
};

static const char *smul_error_messages[] = {
    "Unknown error.",
    "Cookie is not working properly.",
    "Wrong ID format.",
    "Wrong credentials.",
    "Session terminated."
};


static size_t write_memory(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct memory_struct *mem = (struct memory_struct *)userp;
    char *ptr = realloc(mem->memory, mem->size + realsize + 1);
    if (ptr == NULL) {
        MG_INFO(("write_memory function failed! (realloc returned NULL)"));
        return 0;
    }
    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;
    return realsize;
}

static enum smul_error_code get_error_code(const char *memory) {
    if (strstr(memory, "errorcode=1") != NULL) return COOKIE_NOT_WORKING;
    if (strstr(memory, "errorcode=2") != NULL) return WRONG_ID_FORMAT;
    if (strstr(memory, "errorcode=3") != NULL) return WRONG_CREDENTIAL;
    if (strstr(memory, "errorcode=4") != NULL) return SESSION_TERMINATED;
    return UNKNOWN_ERROR;
}


static struct curl_res *authenticate(const char *username, const char *password, struct mg_connection *c) {
    CURL *curl;
    CURLcode res;
    struct memory_struct chunk;
    chunk.memory = malloc(1);
    chunk.size = 0;
    uint8_t client_mac[MAC_ADDR_SIZE];
    char postdata[256];
    enum smul_error_code error_code;
    struct curl_res* result;


    result = malloc(sizeof(struct curl_res));
    /* Get client mac address */

    if (get_client_mac_by_ipv4(client_mac, &c->rem) == -1){
        result->curl = NULL;
        result->errorcode = CANNOT_FIND_MAC;
        return result;
    }

    curl = curl_easy_init();

    if (curl == NULL){
        MG_INFO(("Curl easy init failed!"));
        result->curl = curl;
        result->errorcode = INTERNAL_ERROR;
        return result;
    }

    curl_easy_setopt(curl, CURLOPT_URL, LOGIN_SERVER_URL);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    snprintf(postdata, sizeof(postdata), "username=%s&password=%s", username, password);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postdata);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_memory);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    curl_easy_setopt(curl, CURLOPT_COOKIEFILE, "");
    curl_easy_setopt(curl, CURLOPT_COOKIEJAR, "");
    res = curl_easy_perform(curl);

    if (res != CURLE_OK) {
        fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        curl_easy_cleanup(curl);
        free(chunk.memory);

        result->curl = curl;
        result->errorcode = INTERNAL_ERROR;
        return result;
    }

    if (strstr(chunk.memory, "errorcode") == NULL) {
        free(chunk.memory);
        MG_INFO(("Client : %M (mac address) succeed to login", mg_print_mac, client_mac));

        result->curl = curl;
        result->errorcode = LOGIN_SUCCESS;
        return result;
    } 

    else {
        error_code = get_error_code(chunk.memory);
        MG_INFO(("Client : %M (mac address) failed to login to smul server. Error: %s", 
                mg_print_mac, client_mac, smul_error_messages[error_code]));
        curl_easy_cleanup(curl);
        free(chunk.memory);
        result->curl = NULL;
        result->errorcode = error_code;
        return result;
    }
}


/* Parse user info function works well. But not to recommend using it.
 * because We don't want to store any students' information on our router.
 */

#ifdef USE_PARSED_USER_INFO

static char* fetch_user_info(CURL *curl) {
    CURLcode res;
    struct MemoryStruct chunk;
    chunk.memory = malloc(1);
    chunk.size = 0;

    curl_easy_setopt(curl, CURLOPT_URL, USER_INFO_URL);
    curl_easy_setopt(curl, CURLOPT_COOKIEFILE, "cookies.txt");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        free(chunk.memory);
        return NULL;
    }

    return chunk.memory;
}


static void parse_user_info(const char *html_content) {
    htmlDocPtr doc = htmlReadMemory(html_content, strlen(html_content), NULL, NULL, 0);
    if (doc == NULL) {
        fprintf(stderr, "Failed to parse HTML\n");
        return;
    }

    xmlXPathContextPtr context = xmlXPathNewContext(doc);
    if (context == NULL) {
        fprintf(stderr, "Failed to create XPath context\n");
        xmlFreeDoc(doc);
        return;
    }

    const char *xpaths[] = {
        "//input[@id='id_firstname']/@value",
        "//input[@id='id_department']/@value",
        "//input[@id='id_email']/@value",
        "//input[@id='id_idnumber']/@value"
    };
    const char *labels[] = {"이름", "학과", "이메일 주소","학번"};

    for (int i = 0; i < 4; i++) {
        xmlXPathObjectPtr result = xmlXPathEvalExpression((const xmlChar *)xpaths[i], context);
        if (result == NULL) {
            fprintf(stderr, "Failed to evaluate XPath expression\n");
            continue;
        }

        if (xmlXPathNodeSetIsEmpty(result->nodesetval)) {
            fprintf(stderr, "No result for XPath expression: %s\n", xpaths[i]);
        } else {
            xmlNodePtr node = result->nodesetval->nodeTab[0];
            xmlChar *value = xmlNodeGetContent(node);
            printf("%s: %s\n", labels[i], (char *)value);
            xmlFree(value);
        }

        xmlXPathFreeObject(result);
    }

    xmlXPathFreeContext(context);
    xmlFreeDoc(doc);
}
#endif

int is_valid_user(char *username, char *password, struct mg_connection *c){
    struct curl_res *res = authenticate(username, password, c);
    enum smul_error_code code;


    code = res->errorcode;
    curl_easy_cleanup(res->curl);
    free(res);

    return (int) code;
}
