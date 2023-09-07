/**
   @file rexmpp_xml.c
   @brief XML structures and functions for rexmpp
   @author defanor <defanor@uberspace.net>
   @date 2023
   @copyright MIT license.
*/

#include <string.h>
#include <stdio.h>
#include <libxml/tree.h>
#include <libxml/xmlsave.h>
#include "rexmpp.h"
#include "rexmpp_utf8.h"
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

rexmpp_xml_t *rexmpp_xml_new_text_len (const char *str, size_t len) {
  rexmpp_xml_t *node = malloc(sizeof(rexmpp_xml_t));
  node->type = REXMPP_XML_TEXT;
  node->alt.text = strndup(str, len);
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

int rexmpp_xml_add_text_len (rexmpp_xml_t *node,
                             const char *str,
                             size_t len)
{
  rexmpp_xml_t *text_node = rexmpp_xml_new_text_len(str, len);
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

/* Adds a character, grows the string as needed. */
inline char *rexmpp_str_putc (char *str, size_t *len, char c) {
  char *ret = str;
  if ((*len) % 1024 == 0) {
    ret = realloc(str, (*len) + 1024);
    if (ret == NULL) {
      /* A failure to realloc. */
      if (str != NULL) {
        free(str);
      }
      return NULL;
    }
  }
  ret[*len] = c;
  *len = (*len) + 1;
  return ret;
}

inline char *rexmpp_str_putc_escaped (char *str, size_t *len, char c) {
  char *ret = str;
  char buf[7];
  char *esc = buf;
  size_t i = 0;
  size_t esc_len;
  if (c == '<') {
    esc = "&lt;";
  } else if (c == '>') {
    esc = "&gt;";
  } else if (c == '&') {
    esc = "&amp;";
  } else if (c == '\'') {
    esc = "&apos;";
  } else if (c == '"') {
    esc = "&quot;";
  } else {
    snprintf(esc, 7, "&#%u;", c);
  }
  esc_len = strlen(esc);
  while (i < esc_len) {
    ret = rexmpp_str_putc(ret, len, esc[i]);
    i++;
  }
  return ret;
}

char *rexmpp_xml_print_name (char *str, size_t *len, const char *name) {
  char *ret = str;
  size_t name_len = strlen(name);
  size_t i = 0;
  int32_t c = 0;                /* matches ICU's UChar32 */
  size_t prev_i = 0, j;
  do {
    REXMPP_U8_NEXT(name, i, name_len, c);
    if (c >= 0) {
      if (c == ':'
          || (c >= 'A' && c <= 'Z')
          || c == '_'
          || (c >= 'a' && c <= 'z')
          || (c >= 0xC0 && c <= 0xD6)
          || (c >= 0xD8 && c <= 0xF6)
          || (c >= 0xF8 && c <= 0x2FF)
          || (c >= 0x370 && c <= 0x37D)
          || (c >= 0x37F && c <= 0x1FFF)
          || (c >= 0x200C && c <= 0x200D)
          || (c >= 0x2070 && c <= 0x218F)
          || (c >= 0x2C00 && c <= 0x2FEF)
          || (c >= 0x3001 && c <= 0xD7FF)
          || (c >= 0xF900 && c <= 0xFDCF)
          || (c >= 0xFDF0 && c <= 0xFFF0)
          || (c >= 0x10000 && c <= 0xEFFFF)
          || ((i > 0) &&
              (c == '-'
               || c == '.'
               || (c >= '0' && c <= '9')
               || c == 0xB7
               || (c >= 0x0300 && c <= 0x036F)
               || (c >= 0x203F && c <= 0x2040))))
        {
          /* Print the allowed characters. */
          for (j = prev_i; j < i; j++) {
            ret = rexmpp_str_putc(ret, len, name[j]);
          }
        }
    } else {
      /* Skip invalid characters. */
      i++;
    }
    prev_i = i;
  } while (i < name_len);
  return ret;
}

char *rexmpp_xml_print_text (char *str, size_t *len, const char *text) {
  char *ret = str;
  size_t i = 0;
  size_t text_len = strlen(text);
  while (i < text_len && ret != NULL) {
    char c = text[i];
    if (strchr("<&>'\"", c)) {
      /* Escape the few special characters. */
      ret = rexmpp_str_putc_escaped(ret, len, c);
    } else {
      /* Write others as is. */
      ret = rexmpp_str_putc(ret, len, c);
    }
    i++;
  }
  return ret;
}

char *rexmpp_xml_print_raw (char *str, size_t *len, const char *text) {
  char *ret = str;
  size_t i = 0;
  size_t text_len = strlen(text);
  while (i < text_len && ret != NULL) {
    char c = text[i];
    ret = rexmpp_str_putc(ret, len, c);
    i++;
  }
  return ret;
}

inline char *rexmpp_xml_print_indent (char *str,
                                      size_t *len,
                                      int indent) {
  if (indent <= 0) {
    return str;
  }
  int i;
  char *ret = str;
  for (i = 0; i < indent * 2; i++) {
    ret = rexmpp_str_putc(ret, len, ' ');
  }
  return ret;
}

char *rexmpp_xml_print (char *str,
                        size_t *len,
                        const rexmpp_xml_t *node,
                        int indent) {
  char *ret = str;
  if (node->type == REXMPP_XML_TEXT) {
    ret = rexmpp_xml_print_text(ret, len, node->alt.text);
  } else if (node->type == REXMPP_XML_ELEMENT) {
    if (indent > 0) {
      ret = rexmpp_str_putc(ret, len, '\n');
      ret = rexmpp_xml_print_indent(ret, len, indent);
    }
    ret = rexmpp_str_putc(ret, len, '<');
    ret = rexmpp_xml_print_name(ret, len, node->alt.elem.qname.name);
    if (node->alt.elem.qname.namespace != NULL) {
      ret = rexmpp_xml_print_raw(ret, len, " xmlns=\"");
      ret = rexmpp_xml_print_text(ret, len, node->alt.elem.qname.namespace);
      ret = rexmpp_str_putc(ret, len, '"');
    }
    if (node->alt.elem.attributes != NULL) {
      rexmpp_xml_attr_t *attr;
      for (attr = node->alt.elem.attributes; attr != NULL; attr = attr->next) {
        ret = rexmpp_str_putc(ret, len, ' ');
        /* Ignoring namespaces here for now. */
        ret = rexmpp_xml_print_name(ret, len, attr->qname.name);
        ret = rexmpp_xml_print_raw(ret, len, "=\"");
        ret = rexmpp_xml_print_text(ret, len, attr->value);
        ret = rexmpp_str_putc(ret, len, '"');
      }
    }
    if (node->alt.elem.children == NULL) {
      ret = rexmpp_xml_print_raw(ret, len, "/>");
    } else {
      ret = rexmpp_str_putc(ret, len, '>');
      rexmpp_xml_t *child;
      int last_child_is_textual = 0;
      for (child = rexmpp_xml_children(node);
           child != NULL;
           child = child->next)
        {
          ret = rexmpp_xml_print(ret, len, child,
                                 indent > -1 ? indent + 1 : -1);
          last_child_is_textual = child->type == REXMPP_XML_TEXT;
        }
      if (indent >= 0 && ! last_child_is_textual) {
        ret = rexmpp_str_putc(ret, len, '\n');
        ret = rexmpp_xml_print_indent(ret, len, indent);
      }
      ret = rexmpp_xml_print_raw(ret, len, "</");
      ret = rexmpp_xml_print_name(ret, len, node->alt.elem.qname.name);
      ret = rexmpp_str_putc(ret, len, '>');
    }
  }
  return ret;
}

char *rexmpp_xml_serialize (const rexmpp_xml_t *node, int pretty) {
  size_t s_len = 0;
  char *s = NULL;
  s = rexmpp_xml_print(s, &s_len, node, pretty ? 0 : -1);
  s = rexmpp_str_putc(s, &s_len, '\0');
  return s;
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

#ifndef USE_RUST
int rexmpp_xml_write_file (const char *path, rexmpp_xml_t* node) {
  FILE *fd = fopen(path, "w");
  if (fd == NULL) {
    return -1;
  }
  char *serialized = rexmpp_xml_serialize(node, 1);
  fputs("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n", fd);
  fputs(serialized, fd);
  fclose(fd);
  return 0;
}

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
  char *n1str = rexmpp_xml_serialize(n1, 0);
  char *n2str = rexmpp_xml_serialize(n2, 0);
  int eq = (strcmp(n1str, n2str) == 0);
  free(n1str);
  free(n2str);
  return eq;
}

#ifndef USE_RUST
rexmpp_xml_t *rexmpp_xml_children (const rexmpp_xml_t *node) {
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

rexmpp_xml_t *rexmpp_xml_reverse (rexmpp_xml_t *node) {
  rexmpp_xml_t *next, *prev = NULL;
  while (node != NULL) {
    next = node->next;
    node->next = prev;
    prev = node;
    node = next;
  }
  return prev;
}

rexmpp_xml_t *rexmpp_xml_reverse_all (rexmpp_xml_t *node) {
  node = rexmpp_xml_reverse(node);
  rexmpp_xml_t *cur;
  for (cur = node; cur != NULL; cur = cur->next) {
    if (cur->type == REXMPP_XML_ELEMENT) {
      cur->alt.elem.children = rexmpp_xml_reverse_all(cur->alt.elem.children);
    }
  }
  return node;
}

#endif
