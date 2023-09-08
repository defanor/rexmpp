/**
   @file rexmpp_roster.c
   @brief Roster-related functions.
   @author defanor <defanor@uberspace.net>
   @date 2020
   @copyright MIT license.
*/

#include "rexmpp.h"
#include "rexmpp_xml.h"
#include <syslog.h>
#include <string.h>

rexmpp_xml_t *
rexmpp_roster_find_item (rexmpp_t *s,
                         const char *jid,
                         rexmpp_xml_t **prev_item)
{
  rexmpp_xml_t *prev = NULL, *cur = s->roster_items;
  while (cur != NULL) {
    const char *cur_jid = rexmpp_xml_find_attr_val(cur, "jid");
    if (cur_jid == NULL) {
      rexmpp_log(s, LOG_ALERT, "No jid found in a roster item.");
      return NULL;
    }
    int match = (strcmp(cur_jid, jid) == 0);
    if (match) {
      if (prev_item != NULL) {
        *prev_item = prev;
      }
      return cur;
    }
    prev = cur;
    cur = cur->next;
  }
  return NULL;
}

rexmpp_err_t rexmpp_modify_roster (rexmpp_t *s, rexmpp_xml_t *item) {
  rexmpp_err_t ret = REXMPP_SUCCESS;
  if (! rexmpp_xml_match(item, "jabber:iq:roster", "item")) {
    rexmpp_log(s, LOG_ERR, "No roster item.");
    return REXMPP_E_PARAM;
  }
  const char *subscription = rexmpp_xml_find_attr_val(item, "subscription");
  const char *jid = rexmpp_xml_find_attr_val(item, "jid");
  if (subscription != NULL && strcmp(subscription, "remove") == 0) {
    /* Delete the item. */
    rexmpp_xml_t *prev, *cur;
    cur = rexmpp_roster_find_item(s, jid, &prev);
    if (cur != NULL) {
      if (prev != NULL) {
        prev->next = cur->next;
      } else {
        s->roster_items = cur->next;
      }
      rexmpp_xml_free(cur);
    } else {
      ret = REXMPP_E_ROSTER_ITEM_NOT_FOUND;
    }
  } else {
    /* Add or modify the item. */
    rexmpp_xml_t *cur, *prev;
    cur = rexmpp_roster_find_item(s, jid, &prev);
    /* Remove the item if it was in the roster before. */
    if (cur != NULL) {
      if (prev != NULL) {
        prev->next = cur->next;
      } else {
        s->roster_items = cur->next;
      }
      rexmpp_xml_free(cur);
    }
    /* Add the new item. */
    rexmpp_xml_t *new_item = rexmpp_xml_clone(item);
    new_item->next = s->roster_items;
    s->roster_items = new_item;
  }
  if (s->roster_modify_cb != NULL) {
    s->roster_modify_cb(s, item);
  }
  return ret;
}

void rexmpp_roster_set (rexmpp_t *s, rexmpp_xml_t *query) {
  if (s->roster_items != NULL) {
    rexmpp_xml_free_list(s->roster_items);
  }
  if (s->roster_ver != NULL) {
    free(s->roster_ver);
  }
  const char *roster_ver = rexmpp_xml_find_attr_val(query, "ver");
  s->roster_ver = NULL;
  if (roster_ver != NULL) {
    s->roster_ver = strdup(roster_ver);
  }
  s->roster_items = rexmpp_xml_clone_list(query->alt.elem.children);
  if (s->roster_modify_cb != NULL) {
    rexmpp_xml_t *item;
    for (item = query->alt.elem.children;
         item != NULL;
         item = item->next)
      {
        s->roster_modify_cb(s, item);
      }
  }
}

void rexmpp_roster_cache_read (rexmpp_t *s) {
  if (s->roster_cache_file == NULL) {
    rexmpp_log(s, LOG_WARNING, "No roster cache file path is set.");
    return;
  }
  rexmpp_xml_t *query = rexmpp_xml_read_file(s->roster_cache_file);
  if (query != NULL) {
    rexmpp_roster_set(s, query);
    rexmpp_xml_free(query);
  }
}

void rexmpp_roster_cache_write (rexmpp_t *s) {
  if (s->roster_cache_file == NULL) {
    rexmpp_log(s, LOG_WARNING, "No roster cache file path is set.");
    return;
  }

  rexmpp_xml_t *query = rexmpp_xml_new_elem("query", "jabber:iq:roster");
  if (s->roster_ver != NULL) {
    rexmpp_xml_add_attr(query, "ver", s->roster_ver);
  }
  if (s->roster_items != NULL) {
    rexmpp_xml_add_child(query, rexmpp_xml_clone_list(s->roster_items));
  }
  rexmpp_xml_write_file(s->roster_cache_file, query);
  rexmpp_xml_free(query);
}

void rexmpp_iq_roster_get (rexmpp_t *s,
                           void *ptr,
                           rexmpp_xml_t *req,
                           rexmpp_xml_t *response,
                           int success)
{
  (void)ptr;
  (void)req;     /* Nothing interesting in the request. */
  if (! success) {
    rexmpp_log(s, LOG_ERR, "Roster loading failed.");
    return;
  }
  rexmpp_xml_t *query = response->alt.elem.children;
  if (! rexmpp_xml_match(query, "jabber:iq:roster", "query")) {
    rexmpp_log(s, LOG_DEBUG, "No roster query in reply.");
    return;
  }
  rexmpp_roster_set(s, query);
  if (s->roster_cache_file != NULL) {
    rexmpp_roster_cache_write(s);
  }
}
