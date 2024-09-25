
#ifndef _AUTHSERVER_H
#define _AUTHSERVER_H

#include <mongoose.h>

#define WEB_ROOT_DIR "./web_root"
#if defined(HTTP_URL) && defined(HTTPS_URL)
// Allow to override via the build flags
#elif MG_ENABLE_TCPIP
#define HTTP_URL "http://0.0.0.0"     // Embedded build:
#define HTTPS_URL "https://0.0.0.0"  // Use standard privileged ports
#else
#define HTTP_URL "http://0.0.0.0"    // Workstation build:
#define HTTPS_URL "https://0.0.0.0"  // Use non-privileged ports
#endif



/* Not safe, this is a just test. (Temporary implementation!) */
#define JWT_SECRET_KEY "632f95e3a3a3f253162bf0d05e5f96c198ed80b8f6aef693f186d9fce0ca2fe0"
#define JWT_EXPIRATION_TIME 7200




// Event log entry
struct ui_event {
  uint8_t type, prio;
  unsigned long timestamp;
  char text[10];
};

// Function declarations
int authserv_init(struct mg_mgr *mgr);

#endif
