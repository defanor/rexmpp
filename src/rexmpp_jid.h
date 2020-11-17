/**
   @file rexmpp_jid.h
   @brief JID parsing and manipulation
   @author defanor <defanor@uberspace.net>
   @date 2020
   @copyright MIT license.
*/

#ifndef REXMPP_JID_H
#define REXMPP_JID_H

/** @brief A redundant structure for easy access to JID parts and
    avoidance of dynamic allocations. */
struct rexmpp_jid {
  char local[1024];
  char domain[1024];
  char resource[1024];
  char bare[2048];
  char full[3072];
};

int rexmpp_jid_parse (const char *str, struct rexmpp_jid *jid);

#endif
