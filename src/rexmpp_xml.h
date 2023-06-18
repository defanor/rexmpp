/**
   @file rexmpp_xml.h
   @brief XML structures and functions for rexmpp
   @author defanor <defanor@uberspace.net>
   @date 2023
   @copyright MIT license.
*/

#ifndef REXMPP_XML_H
#define REXMPP_XML_H

#include <libxml/tree.h>

typedef struct rexmpp_xml_qname rexmpp_xml_qname_t;
typedef struct rexmpp_xml_attribute rexmpp_xml_attr_t;
typedef struct rexmpp_xml_node rexmpp_xml_t;

struct rexmpp_xml_qname {
  char *name;
  char *namespace;
};

struct rexmpp_xml_attribute {
  rexmpp_xml_qname_t qname;
  char *value;
  rexmpp_xml_attr_t *next;
};

enum rexmpp_xml_node_type {
  REXMPP_XML_ELEMENT,
  REXMPP_XML_TEXT
};

typedef enum rexmpp_xml_node_type rexmpp_xml_node_type_t;

struct rexmpp_xml_node {
  rexmpp_xml_node_type_t type;
  union {
    struct {
      rexmpp_xml_qname_t qname;
      rexmpp_xml_attr_t *attributes;
      rexmpp_xml_t *children;
    } elem;
    char *text;
  } alt;
  rexmpp_xml_t *next;
};


void rexmpp_xml_qname_free (rexmpp_xml_qname_t *qname);
void rexmpp_xml_attribute_free (rexmpp_xml_attr_t *attr);
void rexmpp_xml_attribute_free_list (rexmpp_xml_attr_t *attr);

/**
   @brief Frees a single XML node. Does not free its siblings.
*/
void rexmpp_xml_free (rexmpp_xml_t *node);

/**
   @brief Frees an XML node and its siblings.
*/
void rexmpp_xml_free_list (rexmpp_xml_t *node);

/**
   @brief Clones a single XML node, without its siblings.
*/
rexmpp_xml_t *rexmpp_xml_clone (rexmpp_xml_t *node);

/**
   @brief Clones an XML node, together with its siblings.
*/
rexmpp_xml_t *rexmpp_xml_clone_list (rexmpp_xml_t *node);

/**
   @brief Creates a single ::rexmpp_xml_t XML node out of libxml2's
   xmlNode, without siblings.
*/
rexmpp_xml_t *rexmpp_xml_from_libxml2 (xmlNodePtr from);

/**
   @brief Creates a ::rexmpp_xml_t XML node out of libxml2's xmlNode,
   with siblings.
*/
rexmpp_xml_t *rexmpp_xml_from_libxml2_list (xmlNodePtr from);

xmlNodePtr rexmpp_xml_to_libxml2 (rexmpp_xml_t *from);

xmlNodePtr rexmpp_xml_to_libxml2_list (rexmpp_xml_t *from);

/**
   @brief Creates a textual ::rexmpp_xml_t XML node (with type =
   ::REXMPP_XML_TEXT).
*/
rexmpp_xml_t *rexmpp_xml_new_text (const char *str);

/**
   @brief Creates an element ::rexmpp_xml_t XML node (with type =
   ::REXMPP_XML_ELEMENT).
*/
rexmpp_xml_t *rexmpp_xml_new_elem (const char *name,
                                   const char *namespace);

/**
   @brief Adds a child node.
*/
void rexmpp_xml_add_child (rexmpp_xml_t *node,
                           rexmpp_xml_t *child);

/**
   @brief Creates a text node, and adds it as a child.
*/
int rexmpp_xml_add_text (rexmpp_xml_t *node,
                         const char *str);

rexmpp_xml_attr_t *rexmpp_xml_attr_new (const char *name,
                                        const char *namespace,
                                        const char *value);

int rexmpp_xml_add_attr (rexmpp_xml_t *node,
                         const char *name,
                         const char *value);

int rexmpp_xml_remove_attr_ns (rexmpp_xml_t *node,
                               const char *name,
                               const char *namespace);

int rexmpp_xml_remove_attr (rexmpp_xml_t *node,
                            const char *name);

int rexmpp_xml_add_attr_ns (rexmpp_xml_t *node,
                            const char *name,
                            const char *namespace,
                            const char *value);

/**
   @brief Adds an "id" attribute to an XML stanza.
   @param[in,out] s ::rexmpp
   @param[in] node A pointer to an XML stanza.
   @returns The same pointer as on input, for more convenient
   composition.
*/
rexmpp_xml_t *
rexmpp_xml_add_id (rexmpp_t *s,
                   rexmpp_xml_t *node);

/**
   @brief A helper function for XML serialisation.
   @param[in] node An XML node.
   @returns A string (must be freed by the caller).
*/
char *rexmpp_xml_serialize (rexmpp_xml_t *node);

/**
   @brief Count the number of siblings after a given node.
*/
unsigned int rexmpp_xml_siblings_count (rexmpp_xml_t *node);

/**
   @brief Compares the node's name and namespace to given ones.
*/
int rexmpp_xml_match (rexmpp_xml_t *node,
                      const char *namespace,
                      const char *name);

int rexmpp_xml_is_stanza (rexmpp_xml_t *node);

/**
   @brief Compose an 'error' element.
*/
rexmpp_xml_t *rexmpp_xml_error (const char *type, const char *condition);

/**
   @brief Matches an XML node against a namespace and an element name.
   @param[in] node An XML node to match.
   @param[in] namespace An XML namespace. Can be NULL (matches
   anything), and it is assumed that the default namespace is
   "jabber:client" (so if it is "jabber:client" and an element doesn't
   have a namespace defined, this function counts that as a match).
   @param[in] name Element name. Can be NULL (matches anything).
   @returns 1 on a successful match, 0 otherwise.
*/
int rexmpp_xml_attr_match (rexmpp_xml_attr_t *attr,
                           const char *namespace,
                           const char *name);

rexmpp_xml_attr_t *rexmpp_xml_find_attr (rexmpp_xml_t *node,
                                         const char *name,
                                         const char *namespace);

const char *rexmpp_xml_find_attr_val_ns (rexmpp_xml_t *node,
                                         const char *name,
                                         const char *namespace);

const char *rexmpp_xml_find_attr_val (rexmpp_xml_t *node,
                                      const char *name);

/**
   @brief Finds a child element of an XML node, which matches the
   given namespace and name.
   @param[in] node The node containing child nodes.
   @param[in] namespace The namespace to look for.
   @param[in] name The element name to look for.
   @returns A pointer to the first matching child node, or NULL if no
   matching child elements found.
*/
rexmpp_xml_t *rexmpp_xml_find_child (rexmpp_xml_t *node,
                                     const char *namespace,
                                     const char *name);

rexmpp_xml_t *rexmpp_xml_children (rexmpp_xml_t *node);

char *rexmpp_xml_text (rexmpp_xml_t *node);

char *rexmpp_xml_text_child (rexmpp_xml_t *node);

rexmpp_xml_t *rexmpp_xml_first_elem_child (rexmpp_xml_t *node);

rexmpp_xml_t *rexmpp_xml_next_elem_sibling (rexmpp_xml_t *node);

/**
   @brief Compares two XML elements.
*/
int rexmpp_xml_eq (rexmpp_xml_t *n1, rexmpp_xml_t *n2);

/**
   @brief A helper function for XML parsing.
   @param[in] str A string to parse.
   @param[in] str_len String length.
   @returns Parsed XML, or NULL on failure.
*/
rexmpp_xml_t *rexmpp_xml_parse (const char *str, int str_len);

rexmpp_xml_t *rexmpp_xml_read_file (const char *path);
int rexmpp_xml_write_file (const char *path, rexmpp_xml_t* node);

#endif
