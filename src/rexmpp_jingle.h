/**
   @file rexmpp_jingle.h
   @brief Jingle routines
   @author defanor <defanor@uberspace.net>
   @date 2021
   @copyright MIT license.

*/


#ifndef REXMPP_JINGLE_H
#define REXMPP_JINGLE_H

#include "rexmpp.h"

/** @brief Processes incoming Jingle IQs. */
int rexmpp_jingle_iq (rexmpp_t *s, xmlNodePtr elem);

/** @brief Destroys Jingle sessions. */
void rexmpp_jingle_stop (rexmpp_t *s);

/** @brief Accepts a file, given a sid and a path to save it to. */
rexmpp_err_t
rexmpp_jingle_accept_file_by_id (rexmpp_t *s,
                                 const char *sid,
                                 const char *path);

/** @brief Sends a file to a given full JID. */
rexmpp_err_t
rexmpp_jingle_send_file (rexmpp_t *s,
                         const char *jid,
                         char *path);

/** @brief Terminates a Jingle session. */
rexmpp_err_t
rexmpp_jingle_session_terminate (rexmpp_t *s,
                                 const char *sid,
                                 xmlNodePtr reason_node,
                                 const char *reason_text);

typedef struct rexmpp_jingle_session rexmpp_jingle_session_t;

struct rexmpp_jingle_session {
  char *jid;
  char *sid;
  char *ibb_sid;
  uint16_t ibb_seq;
  /* The most recent <jingle/> elmment in negotiation. */
  xmlNodePtr negotiation;
  FILE *f;
  rexmpp_jingle_session_t *next;
};


#endif
