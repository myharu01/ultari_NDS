#include <stdio.h>
#include "mongoose.h"
#include <nftables/libnftables.h>
#include <string.h>

// Define the allowed port as a constant
#define ALLOWED_PORT 8000

static char port_rule[100];

const char *cmds[] = {
    "flush ruleset",
    "add table inet firewall",
    "add chain inet firewall input { type filter hook input priority 0; policy drop; }",
    "add chain inet firewall forward { type filter hook forward priority 0; policy drop; }",
    "add chain inet firewall output { type filter hook output priority 0; policy accept; }",
    "add chain inet firewall postrouting { type nat hook postrouting priority 100; }",

    // Allow localhost traffic
    "add rule inet firewall input iifname lo accept",
    "add rule inet firewall output oifname lo accept",

    // State-based tracking rules
    "add rule inet firewall input ct state established,related accept",

    // Allow only port 8000
    port_rule,

    // Allow DNS and DHCP
    "add rule inet firewall input udp dport {53, 67, 68} accept",
    "add rule inet firewall output udp sport {53, 67, 68} accept",

    // Limited ICMP allowance
    "add rule inet firewall input icmp type echo-request limit rate 1/second accept",

    // Logging rule
    "add rule inet firewall input limit rate 5/minute log prefix \"[FIREWALL] Dropped: \" counter drop",

    // NAT configuration
    "add rule inet firewall postrouting oifname eth0 masquerade",
};

/* Function to initialize nftables rules */
int apply_nftables_rules(void) {

    MG_DEBUG(("Starting to make NFTABLES RULE.."));
    struct nft_ctx *nft = nft_ctx_new(NFT_CTX_DEFAULT);
    snprintf(port_rule, sizeof(port_rule), "add rule inet firewall input tcp dport %d accept", ALLOWED_PORT);	
    if (!nft) {
        MG_ERROR(("Failed to create nftables context"));
        return -1;
    }
    for (size_t i = 0; i < sizeof(cmds) / sizeof(cmds[0]); i++) {
        if (nft_run_cmd_from_buffer(nft, cmds[i]) != 0) {
            MG_ERROR(("Failed to run command : [%s]! exiting!!", cmds[i]));
            nft_ctx_free(nft);
            return -1;
        }
    }
    MG_DEBUG(("NFTABLES rule set complete."));
    nft_ctx_free(nft);
    printf("NFTABLES rule set complete.\n");
    return 0;
}

/* Allow internet access for specific MAC and IP pair */
int allow_mac_ip_rule(const char *mac_str, const char *ip_str) {
    struct nft_ctx *nft = nft_ctx_new(NFT_CTX_DEFAULT);
    if (!nft) {
        MG_ERROR(("Failed to create nftables context"));
        return -1;
    }

    char cmd[256];
    snprintf(cmd, sizeof(cmd), 
             "add rule inet firewall forward ether saddr %s ip saddr %s accept", 
             mac_str, ip_str);

    if (nft_run_cmd_from_buffer(nft, cmd) != 0) {
        MG_ERROR(("Failed to add allow rule for MAC %s and IP %s", mac_str, ip_str));
        nft_ctx_free(nft);
        return -1;
    }

    nft_ctx_free(nft);
    printf("Allow rule added for MAC %s and IP %s\n", mac_str, ip_str);
    return 0;
}

/* Deny internet access for specific MAC and IP pair */
int deny_mac_ip_rule(const char *mac_str, const char *ip_str) {
    struct nft_ctx *nft = nft_ctx_new(NFT_CTX_DEFAULT);
    if (!nft) {
        MG_ERROR(("Failed to create nftables context"));
        return -1;
    }

    char cmd[256];
    snprintf(cmd, sizeof(cmd), 
             "add rule inet firewall forward ether saddr %s ip saddr %s drop", 
             mac_str, ip_str);

    if (nft_run_cmd_from_buffer(nft, cmd) != 0) {
        MG_ERROR(("Failed to add deny rule for MAC %s and IP %s", mac_str, ip_str));
        nft_ctx_free(nft);
        return -1;
    }

    nft_ctx_free(nft);
    printf("Deny rule added for MAC %s and IP %s\n", mac_str, ip_str);
}
