/**
   @file rexmpp_pubsub.c
   @brief XEP-0060 helper functions
   @author defanor <defanor@uberspace.net>
   @date 2021
   @copyright MIT license.
*/

#include "rexmpp.h"

void
rexmpp_pubsub_iq (rexmpp_t *s,
                  const char *iq_type,
                  const char *pubsub_namespace,
                  const char *service_jid,
                  xmlNodePtr payload,
                  rexmpp_iq_callback_t callback,
                  void *cb_data)
{
  xmlNodePtr pubsub = xmlNewNode(NULL, "pubsub");
  if (pubsub_namespace == NULL) {
    xmlNewNs(pubsub, "http://jabber.org/protocol/pubsub", NULL);
  } else {
    xmlNewNs(pubsub, pubsub_namespace, NULL);
  }

  xmlAddChild(pubsub, payload);

  rexmpp_iq_new(s, iq_type, service_jid, pubsub, callback, cb_data);
}

void
rexmpp_pubsub_item_publish (rexmpp_t *s,
                            const char *service_jid,
                            const char *node,
                            const char *item_id,
                            xmlNodePtr payload,
                            rexmpp_iq_callback_t callback,
                            void *cb_data)
{
  xmlNodePtr item = xmlNewNode(NULL, "item");
  xmlNewNs(item, "http://jabber.org/protocol/pubsub", NULL);
  if (item_id != NULL) {
    xmlNewProp(item, "id", item_id);
  }
  xmlAddChild(item, payload);

  xmlNodePtr publish = xmlNewNode(NULL, "publish");
  xmlNewNs(publish, "http://jabber.org/protocol/pubsub", NULL);
  xmlNewProp(publish, "node", node);
  xmlAddChild(publish, item);

  rexmpp_pubsub_iq(s, "set", NULL, service_jid, publish, callback, cb_data);
}

void
rexmpp_pubsub_item_retract (rexmpp_t *s,
                            const char *service_jid,
                            const char *node,
                            const char *item_id,
                            rexmpp_iq_callback_t callback,
                            void *cb_data)
{
  xmlNodePtr item = xmlNewNode(NULL, "item");
  xmlNewNs(item, "http://jabber.org/protocol/pubsub", NULL);
  if (item_id != NULL) {
    xmlNewProp(item, "id", item_id);
  }

  xmlNodePtr retract = xmlNewNode(NULL, "retract");
  xmlNewNs(retract, "http://jabber.org/protocol/pubsub", NULL);
  xmlNewProp(retract, "node", node);
  xmlAddChild(retract, item);

  rexmpp_pubsub_iq(s, "set", NULL, service_jid, retract, callback, cb_data);
}

void
rexmpp_pubsub_node_delete (rexmpp_t *s,
                           const char *service_jid,
                           const char *node,
                           rexmpp_iq_callback_t callback,
                           void *cb_data)
{
  xmlNodePtr delete = xmlNewNode(NULL, "delete");
  xmlNewNs(delete, "http://jabber.org/protocol/pubsub#owner", NULL);
  xmlNewProp(delete, "node", node);

  rexmpp_pubsub_iq(s, "set", "http://jabber.org/protocol/pubsub#owner",
                   service_jid, delete, callback, cb_data);
}
