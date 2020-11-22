/**
   @file rexmpp_console.h
   @brief A console module
   @author defanor <defanor@uberspace.net>
   @date 2020
   @copyright MIT license.
*/

#ifndef REXMPP_CONSOLE_H
#define REXMPP_CONSOLE_H

#include "rexmpp.h"

void rexmpp_console_on_send (rexmpp_t *s, xmlNodePtr node);
void rexmpp_console_on_recv (rexmpp_t *s, xmlNodePtr node);
void rexmpp_console_feed (rexmpp_t *s, char *str, ssize_t str_len);

#endif
