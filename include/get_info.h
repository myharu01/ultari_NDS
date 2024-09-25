#ifndef GET_INFO_H
#define GET_INFO_H

#include "mongoose.h"
#include <curl/curl.h>

#define LOGIN_SERVER_URL "https://ecampus.smu.ac.kr/login/index.php"
#define USER_INFO_URL "https://ecampus.smu.ac.kr/user/user_edit.php"


enum smul_error_code{
    UNKNOWN_ERROR,
    COOKIE_NOT_WORKING,
    WRONG_ID_FORMAT,
    WRONG_CREDENTIAL,
    SESSION_TERMINATED,
    LOGIN_SUCCESS,
    CANNOT_FIND_MAC,
    INTERNAL_ERROR
};

struct curl_res{
    CURL *curl;
    enum smul_error_code errorcode;
};


int is_valid_user(char *username, char *password, struct mg_connection *c);


#endif