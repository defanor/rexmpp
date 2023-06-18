/**
   @file rexmpp_xml.c
   @brief XML structures and functions for rexmpp
   @author defanor <defanor@uberspace.net>
   @date 2023
   @copyright MIT license.
*/

#include <string.h>
#include <libxml/tree.h>
#include <libxml/xmlsave.h>
#include "rexmpp.h"
#include "rexmpp_xml.h"

#ifndef USE_RUST
void rexmpp_xml_qname_free (rexmpp_xml_qname_t *qname) {
  if (qname->name != NULL) {
    free(qname->name);
    qname->name = NULL;
  }
  if (qname->namespace != NULL) {
    free(qname->namespace);
    qname->namespace = NULL;
  }
}

void rexmpp_xml_attribute_free (rexmpp_xml_attr_t *attr) {
  if (attr == NULL) {
    return;
  }
  rexmpp_xml_qname_free(&(attr->qname));
  if (attr->value != NULL) {
    free(attr->value);
    attr->value = NULL;
  }
  free(attr);
}

void rexmpp_xml_attribute_free_list (rexmpp_xml_attr_t *attr) {
  rexmpp_xml_attr_t *next = attr;
  while (attr != NULL) {
    next = attr->next;
    rexmpp_xml_attribute_free(attr);
    attr = next;
  }
}

void rexmpp_xml_free (rexmpp_xml_t *node) {
  if (node == NULL) {
    return;
  }
  if (node->type == REXMPP_XML_TEXT) {
    if (node->alt.text != NULL) {
      free(node->alt.text);
      node->alt.text = NULL;
    }
  } if (node->type == REXMPP_XML_ELEMENT) {
    rexmpp_xml_qname_free(&(node->alt.elem.qname));
    rexmpp_xml_attribute_free_list(node->alt.elem.attributes);
    rexmpp_xml_free_list(node->alt.elem.children);
  }
  free(node);
}

void rexmpp_xml_free_list (rexmpp_xml_t *node) {
  rexmpp_xml_t *next = node;
  while (node != NULL) {
    next = node->next;
    rexmpp_xml_free(node);
    node = next;
  }
}

rexmpp_xml_t *rexmpp_xml_clone (rexmpp_xml_t *node) {
  if (node == NULL) {
    return NULL;
  }

  if (node->type == REXMPP_XML_TEXT) {
    return rexmpp_xml_new_text(node->alt.text);
  } else if (node->type == REXMPP_XML_ELEMENT) {
    rexmpp_xml_t *ret =
      rexmpp_xml_new_elem(node->alt.elem.qname.name,
                          node->alt.elem.qname.namespace);
    rexmpp_xml_attr_t **next_attr = &(ret->alt.elem.attributes);
    rexmpp_xml_attr_t *old_attr;
    for (old_attr = node->alt.elem.attributes;
         old_attr != NULL;
         old_attr = old_attr->next)
      {
        rexmpp_xml_attr_t *new_attr =
          rexmpp_xml_attr_new(old_attr->qname.name,
                              old_attr->qname.namespace,
                              old_attr->value);
        *next_attr = new_attr;
        next_attr = &(new_attr->next);
      }

    ret->alt.elem.children =
      rexmpp_xml_clone_list(node->alt.elem.children);
    return ret;
  }
  return NULL;
}

rexmpp_xml_t *rexmpp_xml_clone_list (rexmpp_xml_t *node) {
  rexmpp_xml_t *first, *last;
  if (node == NULL) {
    return NULL;
  }
  first = rexmpp_xml_clone(node);
  for (last = first, node = node->next;
       node != NULL;
       last = last->next, node = node->next)
    {
      last->next = rexmpp_xml_clone(node);
    }
  return first;
}
#endif

rexmpp_xml_t *rexmpp_xml_from_libxml2 (xmlNodePtr from) {
  if (from == NULL) {
    return NULL;
  }

  rexmpp_xml_t *to = NULL;
  if (from->type == XML_ELEMENT_NODE) {
    to = malloc(sizeof(rexmpp_xml_t));

    /* Type */
    to->type = REXMPP_XML_ELEMENT;

    /* Name and namespace */
    to->alt.elem.qname.name = strdup(from->name);
    if (from->nsDef != NULL && from->nsDef->href != NULL) {
      to->alt.elem.qname.namespace = strdup(from->nsDef->href);
    } else {
      to->alt.elem.qname.namespace = NULL;
    }

    /* Attributes */
    to->alt.elem.attributes = NULL;
    struct _xmlAttr *from_attr;
    rexmpp_xml_attr_t **to_next_attr = &(to->alt.elem.attributes);
    for (from_attr = from->properties;
         from_attr != NULL;
         from_attr = from_attr->next)
      {
        rexmpp_xml_attr_t *to_attr =
          malloc(sizeof(rexmpp_xml_attr_t));
        to_attr->qname.name = strdup(from_attr->name);
        to_attr->qname.namespace = NULL;
        if (from_attr->ns != NULL && from_attr->ns->href != NULL) {
          to_attr->qname.namespace = strdup(from_attr->ns->href);
          to_attr->value =
            xmlGetNsProp(from, to_attr->qname.name, to_attr->qname.namespace);
        } else {
          to_attr->value = xmlGetProp(from, to_attr->qname.name);
        }
        to_attr->next = NULL;

        *to_next_attr = to_attr;
        to_next_attr = &(to_attr->next);
      }

    /* Children */
    to->alt.elem.children = NULL;
    xmlNodePtr from_child;
    rexmpp_xml_t **to_next_child = &(to->alt.elem.children);
    for (from_child = from->children;
         from_child != NULL;
         from_child = from_child->next)
      {
        rexmpp_xml_t *next_child = rexmpp_xml_from_libxml2(from_child);
        if (next_child != NULL) {
          *to_next_child = next_child;
          to_next_child = &(next_child->next);
        }
      }

    /* Next */
    to->next = NULL;

  } else if (from->type == XML_TEXT_NODE) {
    to = malloc(sizeof(rexmpp_xml_t));
    to->type = REXMPP_XML_TEXT;
    to->alt.text = xmlNodeGetContent(from);
    to->next = NULL;
  }
  return to;
}

rexmpp_xml_t *rexmpp_xml_from_libxml2_list (xmlNodePtr from) {
  if (from == NULL) {
    return NULL;
  }
  rexmpp_xml_t *to = rexmpp_xml_from_libxml2(from);
  if (from->next != NULL) {
    to->next = rexmpp_xml_from_libxml2_list(from->next);
  }
  return to;
}

xmlNodePtr rexmpp_xml_to_libxml2 (rexmpp_xml_t *from) {
  if (from == NULL) {
    return NULL;
  }

  if (from->type == REXMPP_XML_TEXT) {
    xmlNodePtr to = xmlNewText(from->alt.text);
    to->next = rexmpp_xml_to_libxml2(from->next);
    return to;
  }

  /* Name and namespace */
  xmlNodePtr to = xmlNewNode(NULL, from->alt.elem.qname.name);
  if (from->alt.elem.qname.namespace != NULL) {
    xmlNewNs(to, from->alt.elem.qname.namespace, NULL);
  }

  /* Attributes */
  rexmpp_xml_attr_t *attr = from->alt.elem.attributes;
  while (attr != NULL) {
    /* TODO: Would be nice to take namespaces into account, though
       they are currently not used for attributes. */
    xmlNewProp(to, attr->qname.name, attr->value);
    attr = attr->next;
  }

  /* Children */
  rexmpp_xml_t *child = from->alt.elem.children;
  while (child != NULL) {
    xmlAddChild(to, rexmpp_xml_to_libxml2(child));
    child = child->next;
  }
  return to;
}

xmlNodePtr rexmpp_xml_to_libxml2_list (rexmpp_xml_t *from) {
  xmlNodePtr to = rexmpp_xml_to_libxml2(from);
  if (from->next != NULL) {
    xmlAddNextSibling(to, rexmpp_xml_to_libxml2_list(from->next));
  }
  return to;
}

#ifndef USE_RUST
rexmpp_xml_t *rexmpp_xml_new_text (const char *str) {
  rexmpp_xml_t *node = malloc(sizeof(rexmpp_xml_t));
  node->type = REXMPP_XML_TEXT;
  node->alt.text = strdup(str);
  node->next = NULL;
  return node;
}

void rexmpp_xml_add_child (rexmpp_xml_t *node,
                           rexmpp_xml_t *child)
{
  rexmpp_xml_t **last_ptr = &(node->alt.elem.children);
  while (*last_ptr != NULL) {
    last_ptr = &((*last_ptr)->next);
  }
  *last_ptr = child;
}

int rexmpp_xml_add_text (rexmpp_xml_t *node,
                         const char *str)
{
  rexmpp_xml_t *text_node = rexmpp_xml_new_text(str);
  if (text_node != NULL) {
    rexmpp_xml_add_child(node, text_node);
    return 0;
  }
  return -1;
}

rexmpp_xml_t *rexmpp_xml_new_elem (const char *name,
                                   const char *namespace)
{
  rexmpp_xml_t *node = malloc(sizeof(rexmpp_xml_t));
  node->type = REXMPP_XML_ELEMENT;
  node->alt.elem.qname.name = strdup(name);
  if (namespace != NULL) {
    node->alt.elem.qname.namespace = strdup(namespace);
  } else {
    node->alt.elem.qname.namespace = NULL;
  }
  node->alt.elem.attributes = NULL;
  node->alt.elem.children = NULL;
  node->next = NULL;
  return node;
}

rexmpp_xml_attr_t *rexmpp_xml_attr_new (const char *name,
                                        const char *namespace,
                                        const char *value)
{
  rexmpp_xml_attr_t *attr = malloc(sizeof(rexmpp_xml_attr_t));
  attr->qname.name = strdup(name);
  if (namespace != NULL) {
    attr->qname.namespace = strdup(namespace);
  } else {
    attr->qname.namespace = NULL;
  }
  attr->value = strdup(value);
  attr->next = NULL;
  return attr;
}

int rexmpp_xml_add_attr_ns (rexmpp_xml_t *node,
                            const char *name,
                            const char *namespace,
                            const char *value)
{
  if (node == NULL || node->type != REXMPP_XML_ELEMENT) {
    return -1;
  }
  rexmpp_xml_attr_t *attr =
    rexmpp_xml_attr_new(name, namespace, value);
  attr->next = node->alt.elem.attributes;
  node->alt.elem.attributes = attr;
  return 0;
}

int rexmpp_xml_remove_attr_ns (rexmpp_xml_t *node,
                               const char *name,
                               const char *namespace) {
  if (node == NULL || node->type != REXMPP_XML_ELEMENT) {
    return -1;
  }

  rexmpp_xml_attr_t **attr, *next_attr;
  for (attr = &(node->alt.elem.attributes); *attr != NULL; attr = &((*attr)->next)) {
    if (rexmpp_xml_attr_match(*attr, namespace, name)) {
      next_attr = (*attr)->next;
      rexmpp_xml_attribute_free(*attr);
      *attr = next_attr;
      return 0;
    }
  }
  return 1;
}

int rexmpp_xml_add_attr (rexmpp_xml_t *node,
                         const char *name,
                         const char *value)
{
  return rexmpp_xml_add_attr_ns(node, name, NULL, value);
}

int rexmpp_xml_remove_attr (rexmpp_xml_t *node,
                            const char *name) {
  return rexmpp_xml_remove_attr_ns(node, name, NULL);
}
#endif

rexmpp_xml_t *
rexmpp_xml_add_id (rexmpp_t *s,
                   rexmpp_xml_t *node)
{
  char *buf = rexmpp_gen_id(s);
  if (buf == NULL) {
    return NULL;
  }
  rexmpp_xml_add_attr(node, "id", buf);
  free(buf);
  return node;
}

char *rexmpp_xml_serialize (rexmpp_xml_t *node) {
  xmlNodePtr node_libxml2 = rexmpp_xml_to_libxml2(node);
  xmlBufferPtr buf = xmlBufferCreate();
  xmlSaveCtxtPtr ctx = xmlSaveToBuffer(buf, "utf-8", 0);
  xmlSaveTree(ctx, node_libxml2);
  xmlSaveFlush(ctx);
  xmlSaveClose(ctx);
  unsigned char *out = xmlBufferDetach(buf);
  xmlBufferFree(buf);
  xmlFreeNode(node_libxml2);
  return out;
}

xmlNodePtr rexmpp_xml_parse_libxml2 (const char *str, int str_len) {
  xmlNodePtr elem = NULL;
  xmlDocPtr doc = xmlReadMemory(str, str_len, "", "utf-8", XML_PARSE_NONET);
  if (doc != NULL) {
    elem = xmlCopyNode(xmlDocGetRootElement(doc), 1);
    xmlFreeDoc(doc);
  }
  return elem;
}

rexmpp_xml_t *rexmpp_xml_parse (const char *str, int str_len) {
  xmlNodePtr node_lxml2 = rexmpp_xml_parse_libxml2(str, str_len);
  if (node_lxml2 != NULL) {
    rexmpp_xml_t *node = rexmpp_xml_from_libxml2(node_lxml2);
    xmlFreeNode(node_lxml2);
    return node;
  }
  return NULL;
}

rexmpp_xml_t *rexmpp_xml_read_file (const char *path) {
  xmlDocPtr doc = xmlReadFile(path, "utf-8", XML_PARSE_NONET);
  xmlNodePtr lxml2 = xmlDocGetRootElement(doc);
  rexmpp_xml_t *ret = rexmpp_xml_from_libxml2(lxml2);
  xmlFreeDoc(doc);
  return ret;
}

int rexmpp_xml_write_file (const char *path, rexmpp_xml_t* node) {
  xmlDocPtr doc = xmlNewDoc("1.0");
  xmlNodePtr node_lxml2 = rexmpp_xml_to_libxml2(node);
  xmlDocSetRootElement(doc, node_lxml2);
  xmlSaveFileEnc(path, doc, "utf-8");
  xmlFreeDoc(doc);
  return 0;
}

#ifndef USE_RUST
unsigned int rexmpp_xml_siblings_count (rexmpp_xml_t *node) {
  unsigned int i = 0;
  for (i = 0; node != NULL; i++) {
    node = node->next;
  }
  return i;
}

int rexmpp_xml_match (rexmpp_xml_t *node,
                      const char *namespace,
                      const char *name)
{
  if (node == NULL) {
    return 0;
  }
  if (node->type != REXMPP_XML_ELEMENT) {
    return 0;
  }
  if (name != NULL) {
    if (strcmp(name, node->alt.elem.qname.name) != 0) {
      return 0;
    }
  }
  if (namespace != NULL) {
    if (node->alt.elem.qname.namespace == NULL &&
        strcmp(namespace, "jabber:client") != 0) {
      return 0;
    } else if (node->alt.elem.qname.namespace != NULL) {
      if (strcmp(namespace, node->alt.elem.qname.namespace) != 0) {
        return 0;
      }
    }
  }
  return 1;
}

int rexmpp_xml_attr_match (rexmpp_xml_attr_t *attr,
                           const char *namespace,
                           const char *name)
{
  if (attr == NULL) {
    return 0;
  }
  if (name != NULL) {
    if (strcmp(name, attr->qname.name) != 0) {
      return 0;
    }
  }
  if (namespace != NULL) {
    if (attr->qname.namespace == NULL &&
        strcmp(namespace, "jabber:client") != 0) {
      return 0;
    } else if (strcmp(namespace, attr->qname.namespace) != 0) {
      return 0;
    }
  }
  return 1;
}

int rexmpp_xml_is_stanza (rexmpp_xml_t *node) {
  return rexmpp_xml_match(node, "jabber:client", "message") ||
    rexmpp_xml_match(node, "jabber:client", "iq") ||
    rexmpp_xml_match(node, "jabber:client", "presence");
}

rexmpp_xml_t *rexmpp_xml_error (const char *type, const char *condition) {
  rexmpp_xml_t * error = rexmpp_xml_new_elem("error", NULL);
  rexmpp_xml_add_attr(error, "type", type);
  rexmpp_xml_t * cond =
    rexmpp_xml_new_elem(condition, "urn:ietf:params:xml:ns:xmpp-stanzas");
  rexmpp_xml_add_child(error, cond);
  return error;
}

rexmpp_xml_attr_t *
rexmpp_xml_find_attr (rexmpp_xml_t *node,
                      const char *name,
                      const char *namespace)
{
  if (node == NULL || node->type != REXMPP_XML_ELEMENT) {
    return NULL;
  }
  rexmpp_xml_attr_t *attr;
  for (attr = node->alt.elem.attributes; attr != NULL; attr = attr->next) {
    if (rexmpp_xml_attr_match(attr, namespace, name)) {
      return attr;
    }
  }
  return NULL;
}

const char *rexmpp_xml_find_attr_val_ns (rexmpp_xml_t *node,
                                         const char *name,
                                         const char *namespace) {
  rexmpp_xml_attr_t *attr = rexmpp_xml_find_attr(node, name, namespace);
  if (attr != NULL) {
    return attr->value;
  }
  return NULL;
}

const char *rexmpp_xml_find_attr_val (rexmpp_xml_t *node,
                                      const char *name) {
  return rexmpp_xml_find_attr_val_ns(node, name, NULL);
}

rexmpp_xml_t *
rexmpp_xml_find_child (rexmpp_xml_t *node,
                       const char *namespace,
                       const char *name)
{
  if (node == NULL || node->type != REXMPP_XML_ELEMENT) {
    return NULL;
  }
  rexmpp_xml_t *child;
  for (child = node->alt.elem.children; child != NULL; child = child->next) {
    if (rexmpp_xml_match(child, namespace, name)) {
      return child;
    }
  }
  return NULL;
}
#endif

int rexmpp_xml_eq (rexmpp_xml_t *n1, rexmpp_xml_t *n2) {
  /* Just serialize and compare strings for now: awkward, but
     simple. */
  char *n1str = rexmpp_xml_serialize(n1);
  char *n2str = rexmpp_xml_serialize(n2);
  int eq = (strcmp(n1str, n2str) == 0);
  free(n1str);
  free(n2str);
  return eq;
}

#ifndef USE_RUST
rexmpp_xml_t *rexmpp_xml_children (rexmpp_xml_t *node) {
  if (node != NULL && node->type == REXMPP_XML_ELEMENT) {
    return node->alt.elem.children;
  }
  return NULL;
}

rexmpp_xml_t *rexmpp_xml_first_elem_child (rexmpp_xml_t *node) {
  rexmpp_xml_t *child;
  for (child = rexmpp_xml_children(node); child != NULL; child = child->next) {
    if (child->type == REXMPP_XML_ELEMENT) {
      return child;
    }
  }
  return NULL;
}

rexmpp_xml_t *rexmpp_xml_next_elem_sibling (rexmpp_xml_t *node) {
  if (node == NULL) {
    return NULL;
  }
  rexmpp_xml_t *sibling;
  for (sibling = node->next; sibling != NULL; sibling = sibling->next) {
    if (sibling->type == REXMPP_XML_ELEMENT) {
      return sibling;
    }
  }
  return NULL;
}

char *rexmpp_xml_text (rexmpp_xml_t *node) {
  if (node != NULL && node->type == REXMPP_XML_TEXT) {
    return node->alt.text;
  }
  return NULL;
}

char *rexmpp_xml_text_child (rexmpp_xml_t *node) {
  return rexmpp_xml_text(rexmpp_xml_children(node));
}
#endif
