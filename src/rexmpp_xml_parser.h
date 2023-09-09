/**
   @file rexmpp_xml_parser.h
   @brief XML parsing for rexmpp
   @author defanor <defanor@uberspace.net>
   @date 2023
   @copyright MIT license.
*/

#ifndef REXMPP_XML_PARSER_H
#define REXMPP_XML_PARSER_H


#if defined(USE_LIBXML2)
  #include <libxml/tree.h>
#elif defined(USE_EXPAT)
  #include <expat.h>
#endif

#include "config.h"

typedef void (*rexmpp_xml_parser_element_start) (void *data,
                                                 const char *name,
                                                 const char *namespace,
                                                 rexmpp_xml_attr_t *attributes);
typedef void (*rexmpp_xml_parser_element_end) (void *data);
typedef void (*rexmpp_xml_parser_characters) (void *data,
                                              const char *ch,
                                              size_t len);

struct rexmpp_xml_parser_handlers {
  rexmpp_xml_parser_element_start elem_start;
  rexmpp_xml_parser_element_end elem_end;
  rexmpp_xml_parser_characters text;
};


typedef struct rexmpp_xml_parser_ctx* rexmpp_xml_parser_ctx_t;
typedef struct rexmpp_xml_parser_handlers* rexmpp_xml_parser_handlers_t;

struct rexmpp_xml_parser_ctx {
#if defined(USE_LIBXML2)
  xmlParserCtxtPtr xml_parser;
#elif defined(USE_EXPAT)
  XML_Parser xml_parser;
#else
  void *xml_parser;
#endif
  rexmpp_xml_parser_handlers_t handlers;
  void *user_data;
};

/**
   @brief Allocates a new XML parser context
   @param[in] handlers SAX-like parser event handlers
   @param[in] data User-provided data to pass to the handlers
   @returns A parser context pointer, or NULL on failure.
*/
rexmpp_xml_parser_ctx_t
rexmpp_xml_parser_new (rexmpp_xml_parser_handlers_t handlers,
                       void *data);

/**
   @brief Frees an XML parser context
   @param[in] ctx An XML parser context
*/
void rexmpp_xml_parser_free (rexmpp_xml_parser_ctx_t ctx);

/**
   @brief Feeds data to parse into an XML parser
   @param[in] ctx An XML parser context
   @param[in] chunk A chunk of data to parse
   @param[in] len Length of the data chunk
*/
void
rexmpp_xml_parser_feed (rexmpp_xml_parser_ctx_t ctx,
                        const char *chunk,
                        size_t len,
                        int final);

/**
   @brief Resets a parser context
   @param[in] ctx An XML parser context
   @returns A new pointer, since it may change during a reset
*/
rexmpp_xml_parser_ctx_t rexmpp_xml_parser_reset (rexmpp_xml_parser_ctx_t ctx);


/* #if defined(USE_LIBXML2) */
/* /\** */
/*    @brief Creates a single ::rexmpp_xml_t XML node out of libxml2's */
/*    xmlNode, without siblings. */
/* *\/ */
/* rexmpp_xml_t *rexmpp_xml_from_libxml2 (xmlNodePtr from); */

/* /\** */
/*    @brief Creates a ::rexmpp_xml_t XML node out of libxml2's xmlNode, */
/*    with siblings. */
/* *\/ */
/* rexmpp_xml_t *rexmpp_xml_from_libxml2_list (xmlNodePtr from); */

/* xmlNodePtr rexmpp_xml_to_libxml2 (rexmpp_xml_t *from); */

/* xmlNodePtr rexmpp_xml_to_libxml2_list (rexmpp_xml_t *from); */
/* #endif */

#endif
