/**
   @file rexmpp_pubsub.c
   @brief XEP-0060 helper functions
   @author defanor <defanor@uberspace.net>
   @date 2021
   @copyright MIT license.
*/

#include "rexmpp.h"
#include "rexmpp_xml.h"

void
rexmpp_pubsub_iq (rexmpp_t *s,
                  const char *iq_type,
                  const char *pubsub_namespace,
                  const char *service_jid,
                  rexmpp_xml_t *payload,
                  rexmpp_iq_callback_t callback,
                  void *cb_data)
{
  if (pubsub_namespace == NULL) {
    pubsub_namespace = "http://jabber.org/protocol/pubsub";
  }
  rexmpp_xml_t *pubsub = rexmpp_xml_new_elem("pubsub", pubsub_namespace);
  rexmpp_xml_add_child(pubsub, payload);
  rexmpp_iq_new(s, iq_type, service_jid, pubsub, callback, cb_data);
}

void
rexmpp_pubsub_item_publish (rexmpp_t *s,
                            const char *service_jid,
                            const char *node,
                            const char *item_id,
                            rexmpp_xml_t *payload,
                            rexmpp_iq_callback_t callback,
                            void *cb_data)
{
  rexmpp_xml_t *item =
    rexmpp_xml_new_elem("item", "http://jabber.org/protocol/pubsub");
  if (item_id != NULL) {
    rexmpp_xml_add_attr(item, "id", item_id);
  }
  rexmpp_xml_add_child(item, payload);

  rexmpp_xml_t *publish =
    rexmpp_xml_new_elem("publish", "http://jabber.org/protocol/pubsub");
  rexmpp_xml_add_attr(publish, "node", node);
  rexmpp_xml_add_child(publish, item);

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
  rexmpp_xml_t *item =
    rexmpp_xml_new_elem("item", "http://jabber.org/protocol/pubsub");
  if (item_id != NULL) {
    rexmpp_xml_add_attr(item, "id", item_id);
  }

  rexmpp_xml_t *retract =
    rexmpp_xml_new_elem("retract", "http://jabber.org/protocol/pubsub");
  rexmpp_xml_add_attr(retract, "node", node);
  rexmpp_xml_add_child(retract, item);

  rexmpp_pubsub_iq(s, "set", NULL, service_jid, retract, callback, cb_data);
}

void
rexmpp_pubsub_node_delete (rexmpp_t *s,
                           const char *service_jid,
                           const char *node,
                           rexmpp_iq_callback_t callback,
                           void *cb_data)
{
  rexmpp_xml_t *delete =
    rexmpp_xml_new_elem("delete", "http://jabber.org/protocol/pubsub#owner");
  rexmpp_xml_add_attr(delete, "node", node);

  rexmpp_pubsub_iq(s, "set", "http://jabber.org/protocol/pubsub#owner",
                   service_jid, delete, callback, cb_data);
}
