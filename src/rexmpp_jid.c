/**
   @file rexmpp_jid.c
   @brief JID parsing and manipulation
   @author defanor <defanor@uberspace.net>
   @date 2020
   @copyright MIT license.
*/

#include <stddef.h>
#include <string.h>
#include "rexmpp_jid.h"

int rexmpp_jid_parse (const char *str, struct rexmpp_jid *jid) {
  const char *resource = NULL, *domain = NULL;
  size_t i;
  size_t resource_len = 0, local_len = 0;
  size_t domain_len, bare_len, full_len = strlen(str);
  domain_len = full_len;
  bare_len = full_len;

  /* Find the separators. */
  for (i = 0; i < full_len; i++) {
    if (local_len == 0 && str[i] == '@') {
      local_len = i;
      domain_len -= local_len + 1;
      domain = str + i + 1;
    }
    if (str[i] == '/') {
      resource_len = full_len - i - 1;
      domain_len -= resource_len + 1;
      bare_len -= resource_len + 1;
      resource = str + i + 1;
      break;
    }
  }

  /* Check all the lengths. */
  if (full_len > 3071 || bare_len > 2047 ||
      local_len > 1023 || resource_len > 1023 ||
      domain_len > 1023 || domain_len < 1) {
    return -1;
  }

  /* Copy all the parts. */
  strncpy(jid->full, str, full_len);
  jid->full[full_len] = '\0';
  strncpy(jid->bare, str, bare_len);
  jid->bare[bare_len] = '\0';
  strncpy(jid->local, str, local_len);
  jid->local[local_len] = '\0';
  strncpy(jid->domain, domain, domain_len);
  jid->domain[domain_len] = '\0';
  strncpy(jid->resource, resource, resource_len);
  jid->resource[resource_len] = '\0';

  return 0;
}
