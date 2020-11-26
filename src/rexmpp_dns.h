/**
   @file rexmpp_dns.h
   @brief DNS helper functions
   @author defanor <defanor@uberspace.net>
   @date 2020
   @copyright MIT license.
*/


#ifndef REXMPP_DNS_H
#define REXMPP_DNS_H

#include <stdint.h>

struct rexmpp_dns_srv {
  uint16_t priority;
  uint16_t weight;
  uint16_t port;
  char target[256];
};

/**
   @brief Parses an SRV DNS RR's RDATA.
   @param[in] in SRV record's RDATA.
   @param[in] in_len Length of the input data in octets.
   @param[out] out A structure to fill with data.
   @returns 0 on success, non-zero on parsing failure.
*/
int
rexmpp_parse_srv (char *in, int in_len, struct rexmpp_dns_srv *out);

#endif
