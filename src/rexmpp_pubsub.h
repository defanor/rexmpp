/**
   @file rexmpp_pubsub.h
   @brief XEP-0060 helper functions
   @author defanor <defanor@uberspace.net>
   @date 2021
   @copyright MIT license.
*/

void
rexmpp_pubsub_iq (rexmpp_t *s,
                  const char *iq_type,
                  const char *pubsub_namespace,
                  const char *service_jid,
                  rexmpp_xml_t *payload,
                  rexmpp_iq_callback_t callback,
                  void *cb_data);

void
rexmpp_pubsub_item_publish (rexmpp_t *s,
                            const char *service_jid,
                            const char *node,
                            const char *item_id,
                            rexmpp_xml_t *payload,
                            rexmpp_iq_callback_t callback,
                            void *cb_data);

void
rexmpp_pubsub_item_retract (rexmpp_t *s,
                            const char *service_jid,
                            const char *node,
                            const char *item_id,
                            rexmpp_iq_callback_t callback,
                            void *cb_data);

void
rexmpp_pubsub_node_delete (rexmpp_t *s,
                           const char *service_jid,
                           const char *node,
                           rexmpp_iq_callback_t callback,
                           void *cb_data);
