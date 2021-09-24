/**
   @file rexmpp_roster.c
   @brief Roster-related functions.
   @author defanor <defanor@uberspace.net>
   @date 2020
   @copyright MIT license.
*/

#include "rexmpp.h"
#include <syslog.h>
#include <string.h>
#include <libxml/tree.h>
#include <libxml/xmlsave.h>

xmlNodePtr rexmpp_roster_find_item (rexmpp_t *s,
                                    const char *jid,
                                    xmlNodePtr *prev_item)
{
  xmlNodePtr prev = NULL, cur = s->roster_items;
  while (cur != NULL) {
    char *cur_jid = xmlGetProp(cur, "jid");
    if (cur_jid == NULL) {
      rexmpp_log(s, LOG_ALERT, "No jid found in a roster item.");
      return NULL;
    }
    int match = (strcmp(cur_jid, jid) == 0);
    free(cur_jid);
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

rexmpp_err_t rexmpp_modify_roster (rexmpp_t *s, xmlNodePtr item) {
  rexmpp_err_t ret = REXMPP_SUCCESS;
  if (! rexmpp_xml_match(item, "jabber:iq:roster", "item")) {
    rexmpp_log(s, LOG_ERR, "No roster item.");
    return REXMPP_E_PARAM;
  }
  char *subscription = xmlGetProp(item, "subscription");
  char *jid = xmlGetProp(item, "jid");
  if (subscription != NULL && strcmp(subscription, "remove") == 0) {
    /* Delete the item. */
    xmlNodePtr prev, cur;
    cur = rexmpp_roster_find_item(s, jid, &prev);
    if (cur != NULL) {
      if (prev != NULL) {
        prev->next = cur->next;
      } else {
        s->roster_items = cur->next;
      }
      xmlFreeNode(cur);
    } else {
      ret = REXMPP_E_ROSTER_ITEM_NOT_FOUND;
    }
  } else {
    /* Add or modify the item. */
    xmlNodePtr cur, prev;
    cur = rexmpp_roster_find_item(s, jid, &prev);
    /* Remove the item if it was in the roster before. */
    if (cur != NULL) {
      if (prev != NULL) {
        prev->next = cur->next;
      } else {
        s->roster_items = cur->next;
      }
      xmlFreeNode(cur);
    }
    /* Add the new item. */
    xmlNodePtr new_item = xmlCopyNode(item, 1);
    new_item->next = s->roster_items;
    s->roster_items = new_item;
  }
  free(jid);
  if (subscription != NULL) {
    free(subscription);
  }
  if (s->roster_modify_cb != NULL) {
    s->roster_modify_cb(s, item);
  }
  return ret;
}

void rexmpp_roster_set (rexmpp_t *s, xmlNodePtr query) {
  if (s->roster_items != NULL) {
    xmlFreeNodeList(s->roster_items);
  }
  if (s->roster_ver != NULL) {
    free(s->roster_ver);
  }
  s->roster_ver = xmlGetProp(query, "ver");
  s->roster_items = xmlCopyNodeList(xmlFirstElementChild(query));
  if (s->roster_modify_cb != NULL) {
    xmlNodePtr item;
    for (item = xmlFirstElementChild(query);
         item != NULL;
         item = xmlNextElementSibling(item))
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
  xmlDocPtr doc = xmlReadFile(s->roster_cache_file, "utf-8", XML_PARSE_NONET);
  xmlNodePtr query = xmlDocGetRootElement(doc);
  rexmpp_roster_set(s, query);
  xmlFreeDoc(doc);
}

void rexmpp_roster_cache_write (rexmpp_t *s) {
  if (s->roster_cache_file == NULL) {
    rexmpp_log(s, LOG_WARNING, "No roster cache file path is set.");
    return;
  }
  xmlDocPtr doc = xmlNewDoc("1.0");
  xmlNodePtr query = xmlNewDocNode(doc, NULL, "query", NULL);
  xmlDocSetRootElement(doc, query);
  xmlNewNs(query, "jabber:iq:roster", NULL);
  if (s->roster_ver != NULL) {
    xmlNewProp(query, "ver", s->roster_ver);
  }
  if (s->roster_items != NULL) {
    xmlAddChild(query, xmlDocCopyNodeList(doc, s->roster_items));
  }
  xmlSaveFileEnc(s->roster_cache_file, doc, "utf-8");
  xmlFreeDoc(doc);
}

void rexmpp_iq_roster_get (rexmpp_t *s,
                           void *ptr,
                           xmlNodePtr req,
                           xmlNodePtr response,
                           int success)
{
  (void)ptr;
  (void)req;     /* Nothing interesting in the request. */
  if (! success) {
    rexmpp_log(s, LOG_ERR, "Roster loading failed.");
    return;
  }
  xmlNodePtr query = xmlFirstElementChild(response);
  if (! rexmpp_xml_match(query, "jabber:iq:roster", "query")) {
    rexmpp_log(s, LOG_DEBUG, "No roster query in reply.");
    return;
  }
  rexmpp_roster_set(s, query);
  if (s->roster_cache_file != NULL) {
    rexmpp_roster_cache_write(s);
  }
}
