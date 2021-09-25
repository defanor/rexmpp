/**
   @file rexmpp_http_upload.h
   @brief XEP-0363: HTTP file upload
   @author defanor <defanor@uberspace.net>
   @date 2021
   @copyright MIT license.
*/

#ifndef REXMPP_HTTP_UPLOAD_H
#define REXMPP_HTTP_UPLOAD_H

#include "config.h"
#include "rexmpp.h"


typedef void (*http_upload_cb) (rexmpp_t *s, void *cb_data, const char *url);

#ifdef HAVE_CURL
struct rexmpp_http_upload_task {
  char *fname;
  uint32_t fsize;
  FILE *fh;
  char *content_type;
  char *get_url;
  http_upload_cb cb;
  void *cb_data;
  struct curl_slist *http_headers;
  rexmpp_t *s;
};

void rexmpp_upload_task_finish (struct rexmpp_http_upload_task *task);
#endif

rexmpp_err_t
rexmpp_http_upload (rexmpp_t *s,
                    const char *jid,
                    const char *fname,
                    size_t fsize,
                    FILE *fh,
                    const char *content_type,
                    http_upload_cb cb,
                    void *cb_data);

rexmpp_err_t
rexmpp_http_upload_path (rexmpp_t *s,
                         const char *jid,
                         char *fpath,
                         const char *content_type,
                         http_upload_cb cb,
                         void *cb_data);

#endif
