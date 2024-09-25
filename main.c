#include "mongoose.h"
#include "firewall.h"
#include "authserver.h"
#include <curl/curl.h>
#include "client_list.h"


static void run_mongoose(void) {
  struct mg_mgr mgr;        // Mongoose event manager
  mg_mgr_init(&mgr);        // Initialize event manager
  mg_log_set(MG_LL_DEBUG);  // Set log level to debug

  if (authserv_init(&mgr) != 0){ // Auth server Init
    MG_ERROR(("Failed to Start Ultari"));
  }

  /* Infinite Event loop */
  for (;;){              
    mg_mgr_poll(&mgr, 0);  // Process network events
  }
}

int main(){
    /* Init curl for check user information to school server */
    if (curl_global_init(CURL_GLOBAL_ALL) != 0){
      MG_ERROR(("Failed to Init CURL!"));
      curl_global_cleanup();
      return -1;
    }

    /* TODO: initialization of nftables rule */
    /* TODO: apply_nftables_rules() */
    // apply_nftables_rules();
    
    client_list_init();
    /* start running mongoose server */
    run_mongoose();


    /* TODO: de-allocate curl curl_global_cleanup(); */
    return 0;
}
