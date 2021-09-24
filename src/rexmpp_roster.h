/**
   @file rexmpp_roster.h
   @brief Roster-related functions.
   @author defanor <defanor@uberspace.net>
   @date 2020
   @copyright MIT license.
*/


xmlNodePtr rexmpp_roster_find_item (rexmpp_t *s,
                                    const char *jid,
                                    xmlNodePtr *prev_item);
rexmpp_err_t rexmpp_modify_roster (rexmpp_t *s, xmlNodePtr item);
void rexmpp_roster_set (rexmpp_t *s, xmlNodePtr query);
void rexmpp_roster_cache_read (rexmpp_t *s);
void rexmpp_roster_cache_write (rexmpp_t *s);
void rexmpp_iq_roster_get (rexmpp_t *s,
                           void *ptr,
                           xmlNodePtr req,
                           xmlNodePtr response,
                           int success);
