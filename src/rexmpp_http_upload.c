/**
   @file rexmpp_http_upload.c
   @brief XEP-0363: HTTP file upload
   @author defanor <defanor@uberspace.net>
   @date 2021
   @copyright MIT license.
*/

#include <syslog.h>
#include <string.h>
#include <libgen.h>
#include <errno.h>
#include <stdlib.h>

#include "config.h"

#ifdef HAVE_CURL
#include <curl/curl.h>
#endif

#include "rexmpp.h"
#include "rexmpp_xml.h"
#include "rexmpp_http_upload.h"



#ifdef HAVE_CURL
void rexmpp_upload_task_finish (struct rexmpp_http_upload_task *task) {
  task->cb(task->s, task->cb_data, task->get_url);
  free(task->fname);
  if (task->fh != NULL) {
    fclose(task->fh);
  }
  if (task->content_type != NULL) {
    free(task->content_type);
  }
  if (task->get_url != NULL) {
    free(task->get_url);
  }
  if (task->http_headers != NULL) {
    curl_slist_free_all(task->http_headers);
  }
  free(task);
}

void rexmpp_http_upload_slot_cb (rexmpp_t *s,
                                 void *ptr,
                                 rexmpp_xml_t *request,
                                 rexmpp_xml_t *response,
                                 int success)
{
  (void)request;
  struct rexmpp_http_upload_task *task = ptr;
  if (success) {
    rexmpp_xml_t *slot = rexmpp_xml_find_child(response, "urn:xmpp:http:upload:0", "slot");
    rexmpp_xml_t *put = rexmpp_xml_find_child(slot, "urn:xmpp:http:upload:0", "put");
    rexmpp_xml_t *get = rexmpp_xml_find_child(slot, "urn:xmpp:http:upload:0", "get");
    if (put != NULL && get != NULL) {
      const char *put_url = rexmpp_xml_find_attr_val(put, "url");
      const char *get_url = rexmpp_xml_find_attr_val(get, "url");
      if (put_url != NULL && get_url != NULL) {
        task->get_url = strdup(get_url);

        CURL *ce = curl_easy_init();
        curl_easy_setopt(ce, CURLOPT_PRIVATE, task);
        curl_easy_setopt(ce, CURLOPT_UPLOAD, 1);
        curl_easy_setopt(ce, CURLOPT_READDATA, task->fh);
        curl_easy_setopt(ce, CURLOPT_URL, put_url);
        curl_easy_setopt(ce, CURLOPT_INFILESIZE, task->fsize);

        rexmpp_xml_t *header = rexmpp_xml_first_elem_child(put);
        while (header) {
          const char *header_name = rexmpp_xml_find_attr_val(header, "name");
          if (header_name != NULL) {
            const char *header_str = rexmpp_xml_text_child(header);
            if (header_str != NULL) {
              size_t full_header_str_len =
                strlen(header_name) + 3 + strlen(header_str);
              char *full_header_str = malloc(full_header_str_len);
              if (full_header_str != NULL) {
                snprintf(full_header_str, full_header_str_len, "%s: %s",
                         header_name, header_str);
                task->http_headers =
                  curl_slist_append(task->http_headers, full_header_str);
                free(full_header_str);
              } else {
                rexmpp_log(s, LOG_ERR,
                           "Failed to allocate memory for a header");
              }
            }
          }
          header = rexmpp_xml_next_elem_sibling(header);
        }
        curl_easy_setopt(ce, CURLOPT_HTTPHEADER, task->http_headers);

        curl_multi_add_handle(s->curl_multi, ce);
        rexmpp_log(s, LOG_DEBUG, "Uploading %s to %s", task->fname, put_url);
        return;
      } else {
        rexmpp_log(s, LOG_ERR, "Unexpected structure for a HTTP file upload slot.");
      }
    } else {
      rexmpp_log(s, LOG_ERR, "Unexpected structure for a HTTP file upload slot.");
    }
  } else {
    rexmpp_log(s, LOG_ERR, "Failed to obtain a slot for HTTP file upload.");
  }
  rexmpp_upload_task_finish(task);
}

void rexmpp_http_upload_feature_cb (rexmpp_t *s,
                                    void *ptr,
                                    rexmpp_xml_t *request,
                                    rexmpp_xml_t *response,
                                    int success)
{
  (void)response;
  struct rexmpp_http_upload_task *task = ptr;
  if (! success) {
    rexmpp_log(s, LOG_ERR, "No HTTP file upload service found.");
    rexmpp_upload_task_finish(task);
    return;
  }
  rexmpp_xml_t *req =
    rexmpp_xml_new_elem("request", "urn:xmpp:http:upload:0");
  rexmpp_xml_add_attr(req, "filename", task->fname);
  char buf[11];
  snprintf(buf, 11, "%u", task->fsize);
  rexmpp_xml_add_attr(req, "size", buf);
  if (task->content_type) {
    rexmpp_xml_add_attr(req, "content-type", task->content_type);
  }
  const char *to = rexmpp_xml_find_attr_val(request, "to");
  rexmpp_iq_new(s, "get", to, req, rexmpp_http_upload_slot_cb, task);
}

rexmpp_err_t
rexmpp_http_upload (rexmpp_t *s,
                    const char *jid,
                    const char *fname,
                    size_t fsize,
                    FILE *fh,
                    const char *content_type,
                    http_upload_cb cb,
                    void *cb_data)
{
  if (fname == NULL) {
    rexmpp_log(s, LOG_ERR, "No file name is provided");
    fclose(fh);
    return REXMPP_E_PARAM;
  }
  struct rexmpp_http_upload_task *task =
    malloc(sizeof(struct rexmpp_http_upload_task));
  if (task == NULL) {
    rexmpp_log(s, LOG_ERR, "Failed to allocate memory for an upload task");
    fclose(fh);
    return REXMPP_E_MALLOC;
  }
  task->fname = strdup(fname);
  task->fsize = fsize;
  task->fh = fh;
  task->content_type = content_type ? strdup(content_type) : NULL;
  task->get_url = NULL;
  task->http_headers = NULL;
  task->cb = cb;
  task->cb_data = cb_data;
  task->s = s;
  return rexmpp_disco_find_feature(s, jid, "urn:xmpp:http:upload:0",
                                   rexmpp_http_upload_feature_cb, task, 0, 20);
}
#else
rexmpp_err_t
rexmpp_http_upload (rexmpp_t *s,
                    const char *jid,
                    const char *fname,
                    size_t fsize,
                    FILE *fh,
                    const char *content_type,
                    http_upload_cb cb,
                    void *cb_data)
{
  (void)jid;
  (void)fname;
  (void)fsize;
  (void)content_type;
  rexmpp_log(s, LOG_ERR, "rexmpp is built without curl support");
  fclose(fh);
  cb(s, cb_data, NULL);
  return REXMPP_E_OTHER;
}
#endif

rexmpp_err_t
rexmpp_http_upload_path (rexmpp_t *s,
                         const char *jid,
                         char *fpath,
                         const char *content_type,
                         http_upload_cb cb,
                         void *cb_data)
{
  FILE *fh = fopen(fpath, "rb");
  if (fh == NULL) {
    rexmpp_log(s, LOG_ERR, "Failed to open %s for reading: %s.\n",
               fpath, strerror(errno));
    cb(s, cb_data, NULL);
    return REXMPP_E_OTHER;
  }

  char *fname = basename(fpath);
  fseek(fh, 0, SEEK_END);
  long fsize = ftell(fh);
  fseek(fh, 0, SEEK_SET);

  return
    rexmpp_http_upload(s, jid, fname, fsize, fh, content_type, cb, cb_data);
}
