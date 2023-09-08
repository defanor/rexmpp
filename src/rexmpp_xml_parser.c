/**
   @file rexmpp_xml_parser.c
   @brief XML parsing for rexmpp
   @author defanor <defanor@uberspace.net>
   @date 2023
   @copyright MIT license.
*/

#include "rexmpp.h"
#include "rexmpp_xml.h"
#include "rexmpp_xml_parser.h"
#include "config.h"

#if defined(USE_LIBXML2)

void rexmpp_xml_sax_characters (rexmpp_xml_parser_ctx_t ctx,
                                const char *ch,
                                int len)
{
  ctx->handlers->text(ctx->user_data, ch, len);
}

void rexmpp_xml_sax_elem_start (rexmpp_xml_parser_ctx_t ctx,
                                const char *localname,
                                const char *prefix,
                                const char *URI,
                                int nb_namespaces,
                                const char **namespaces,
                                int nb_attributes,
                                int nb_defaulted,
                                const char **attributes)
{
  (void)prefix;
  (void)nb_namespaces;
  (void)namespaces;
  (void)nb_defaulted;
  rexmpp_xml_attr_t *attrs = NULL;
  int i;
  for (i = nb_attributes - 1; i >= 0; i--) {
    size_t attr_len = attributes[i * 5 + 4] - attributes[i * 5 + 3];
    char *attr_val = malloc(attr_len + 1);
    attr_val[attr_len] = '\0';
    strncpy(attr_val, attributes[i * 5 + 3], attr_len);
    rexmpp_xml_attr_t *attr =
      rexmpp_xml_attr_new(attributes[i * 5], NULL, attr_val);
    free(attr_val);
    attr->next = attrs;
    attrs = attr;
  }

  ctx->handlers->elem_start(ctx->user_data, localname, URI, attrs);
}

void rexmpp_xml_sax_elem_end (rexmpp_xml_parser_ctx_t ctx,
                              const char *localname,
                              const char *prefix,
                              const char *URI)
{
  (void)localname;
  (void)prefix;
  (void)URI;
  ctx->handlers->elem_end(ctx->user_data);
}

xmlSAXHandler rexmpp_xml_parser_sax = {
  .initialized = XML_SAX2_MAGIC,
  .characters = (charactersSAXFunc)rexmpp_xml_sax_characters,
  .startElementNs = (startElementNsSAX2Func)rexmpp_xml_sax_elem_start,
  .endElementNs = (endElementNsSAX2Func)rexmpp_xml_sax_elem_end,
};


/* rexmpp_xml_t *rexmpp_xml_from_libxml2 (xmlNodePtr from) { */
/*   if (from == NULL) { */
/*     return NULL; */
/*   } */

/*   rexmpp_xml_t *to = NULL; */
/*   if (from->type == XML_ELEMENT_NODE) { */
/*     to = malloc(sizeof(rexmpp_xml_t)); */

/*     /\* Type *\/ */
/*     to->type = REXMPP_XML_ELEMENT; */

/*     /\* Name and namespace *\/ */
/*     to->alt.elem.qname.name = strdup(from->name); */
/*     if (from->nsDef != NULL && from->nsDef->href != NULL) { */
/*       to->alt.elem.qname.namespace = strdup(from->nsDef->href); */
/*     } else { */
/*       to->alt.elem.qname.namespace = NULL; */
/*     } */

/*     /\* Attributes *\/ */
/*     to->alt.elem.attributes = NULL; */
/*     struct _xmlAttr *from_attr; */
/*     rexmpp_xml_attr_t **to_next_attr = &(to->alt.elem.attributes); */
/*     for (from_attr = from->properties; */
/*          from_attr != NULL; */
/*          from_attr = from_attr->next) */
/*       { */
/*         rexmpp_xml_attr_t *to_attr = */
/*           malloc(sizeof(rexmpp_xml_attr_t)); */
/*         to_attr->qname.name = strdup(from_attr->name); */
/*         to_attr->qname.namespace = NULL; */
/*         if (from_attr->ns != NULL && from_attr->ns->href != NULL) { */
/*           to_attr->qname.namespace = strdup(from_attr->ns->href); */
/*           to_attr->value = */
/*             xmlGetNsProp(from, to_attr->qname.name, to_attr->qname.namespace); */
/*         } else { */
/*           to_attr->value = xmlGetProp(from, to_attr->qname.name); */
/*         } */
/*         to_attr->next = NULL; */

/*         *to_next_attr = to_attr; */
/*         to_next_attr = &(to_attr->next); */
/*       } */

/*     /\* Children *\/ */
/*     to->alt.elem.children = NULL; */
/*     xmlNodePtr from_child; */
/*     rexmpp_xml_t **to_next_child = &(to->alt.elem.children); */
/*     for (from_child = from->children; */
/*          from_child != NULL; */
/*          from_child = from_child->next) */
/*       { */
/*         rexmpp_xml_t *next_child = rexmpp_xml_from_libxml2(from_child); */
/*         if (next_child != NULL) { */
/*           *to_next_child = next_child; */
/*           to_next_child = &(next_child->next); */
/*         } */
/*       } */

/*     /\* Next *\/ */
/*     to->next = NULL; */

/*   } else if (from->type == XML_TEXT_NODE) { */
/*     to = malloc(sizeof(rexmpp_xml_t)); */
/*     to->type = REXMPP_XML_TEXT; */
/*     to->alt.text = xmlNodeGetContent(from); */
/*     to->next = NULL; */
/*   } */
/*   return to; */
/* } */

/* rexmpp_xml_t *rexmpp_xml_from_libxml2_list (xmlNodePtr from) { */
/*   if (from == NULL) { */
/*     return NULL; */
/*   } */
/*   rexmpp_xml_t *to = rexmpp_xml_from_libxml2(from); */
/*   if (from->next != NULL) { */
/*     to->next = rexmpp_xml_from_libxml2_list(from->next); */
/*   } */
/*   return to; */
/* } */

/* xmlNodePtr rexmpp_xml_to_libxml2 (rexmpp_xml_t *from) { */
/*   if (from == NULL) { */
/*     return NULL; */
/*   } */

/*   if (from->type == REXMPP_XML_TEXT) { */
/*     xmlNodePtr to = xmlNewText(from->alt.text); */
/*     to->next = rexmpp_xml_to_libxml2(from->next); */
/*     return to; */
/*   } */

/*   /\* Name and namespace *\/ */
/*   xmlNodePtr to = xmlNewNode(NULL, from->alt.elem.qname.name); */
/*   if (from->alt.elem.qname.namespace != NULL) { */
/*     xmlNewNs(to, from->alt.elem.qname.namespace, NULL); */
/*   } */

/*   /\* Attributes *\/ */
/*   rexmpp_xml_attr_t *attr = from->alt.elem.attributes; */
/*   while (attr != NULL) { */
/*     /\* TODO: Would be nice to take namespaces into account, though */
/*        they are currently not used for attributes. *\/ */
/*     xmlNewProp(to, attr->qname.name, attr->value); */
/*     attr = attr->next; */
/*   } */

/*   /\* Children *\/ */
/*   rexmpp_xml_t *child = from->alt.elem.children; */
/*   while (child != NULL) { */
/*     xmlAddChild(to, rexmpp_xml_to_libxml2(child)); */
/*     child = child->next; */
/*   } */
/*   return to; */
/* } */

/* xmlNodePtr rexmpp_xml_to_libxml2_list (rexmpp_xml_t *from) { */
/*   xmlNodePtr to = rexmpp_xml_to_libxml2(from); */
/*   if (from->next != NULL) { */
/*     xmlAddNextSibling(to, rexmpp_xml_to_libxml2_list(from->next)); */
/*   } */
/*   return to; */
/* } */

#elif defined(USE_EXPAT)

void XMLCALL
rexmpp_xml_sax_elem_start (rexmpp_xml_parser_ctx_t ctx,
                           const char *el,
                           const char **attributes)
{
  char *buf = strdup(el);
  char *name = NULL, *namespace = buf;
  size_t i;
  for (i = 0; i < strlen(namespace); i++) {
    if (namespace[i] == '\xff') {
      name = namespace + i + 1;
      namespace[i] = '\0';
    }
  }
  if (name == NULL) {
    name = namespace;
    namespace = NULL;
  }
  rexmpp_xml_attr_t *attrs = NULL;
  for (i = 0; attributes[i] != NULL; i += 2) {
    rexmpp_xml_attr_t *attr =
      rexmpp_xml_attr_new(attributes[i], NULL, attributes[i + 1]);
    attr->next = attrs;
    attrs = attr;
  }

  ctx->handlers->elem_start(ctx->user_data, name, namespace, attrs);
  free(buf);
}

void XMLCALL
rexmpp_xml_sax_elem_end(rexmpp_xml_parser_ctx_t ctx,
                        const XML_Char *name)
{
  (void)name;
  ctx->handlers->elem_end(ctx->user_data);
}

void XMLCALL
rexmpp_xml_sax_characters (rexmpp_xml_parser_ctx_t ctx,
                           const XML_Char *ch,
                           int len)
{
  ctx->handlers->text(ctx->user_data, ch, len);
}

#endif



rexmpp_xml_parser_ctx_t
rexmpp_xml_parser_new (rexmpp_xml_parser_handlers_t handlers,
                       void *data)
{
  rexmpp_xml_parser_ctx_t ctx = malloc(sizeof(struct rexmpp_xml_parser_ctx));
  if (ctx == NULL) {
    return NULL;
  }
#if defined(USE_LIBXML2)
  xmlParserCtxtPtr p =
    xmlCreatePushParserCtxt(&rexmpp_xml_parser_sax, ctx, "", 0, NULL);
#elif defined(USE_EXPAT)
  XML_Parser p = XML_ParserCreateNS("utf-8", '\xff');
  XML_SetUserData(p, ctx);
  XML_SetStartElementHandler(p, (XML_StartElementHandler)
                             rexmpp_xml_sax_elem_start);
  XML_SetEndElementHandler(p, (XML_EndElementHandler)
                           rexmpp_xml_sax_elem_end);
  XML_SetCharacterDataHandler(p, (XML_CharacterDataHandler)
                              rexmpp_xml_sax_characters);
#endif
  if (p == NULL) {
    free(ctx);
    return NULL;
  }

  ctx->xml_parser = p;
  ctx->handlers = handlers;
  ctx->user_data = data;
  return ctx;
}

void rexmpp_xml_parser_free (rexmpp_xml_parser_ctx_t ctx) {
#if defined(USE_LIBXML2)
  xmlFreeParserCtxt(ctx->xml_parser);
#elif defined(USE_EXPAT)
  XML_ParserFree(ctx->xml_parser);
#endif
  free(ctx);
}

rexmpp_xml_parser_ctx_t rexmpp_xml_parser_reset (rexmpp_xml_parser_ctx_t ctx) {
#if defined(USE_LIBXML2)
  xmlCtxtResetPush(ctx->xml_parser, "", 0, "", "utf-8");
#elif defined(USE_EXPAT)
  XML_ParserReset(ctx->xml_parser, "utf-8");
  XML_SetUserData(ctx->xml_parser, ctx);
  XML_SetStartElementHandler(ctx->xml_parser, (XML_StartElementHandler)
                             rexmpp_xml_sax_elem_start);
  XML_SetEndElementHandler(ctx->xml_parser, (XML_EndElementHandler)
                           rexmpp_xml_sax_elem_end);
  XML_SetCharacterDataHandler(ctx->xml_parser, (XML_CharacterDataHandler)
                              rexmpp_xml_sax_characters);
#endif
  return ctx;
}

void
rexmpp_xml_parser_feed (rexmpp_xml_parser_ctx_t ctx,
                        const char *chunk,
                        size_t len)
{
#if defined(USE_LIBXML2)
  xmlParseChunk(ctx->xml_parser, chunk, len, 0);
#elif defined(USE_EXPAT)
  XML_Parse(ctx->xml_parser, chunk, len, 0);
#endif
}
