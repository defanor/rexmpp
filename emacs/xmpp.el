;;; xmpp.el --- an XMPP client             -*- lexical-binding: t; -*-

;; Copyright (C) 2021 defanor

;; Author: defanor <defanor@uberspace.net>
;; Maintainer: defanor <defanor@uberspace.net>
;; Created: 2021-02-24
;; Keywords: xmpp, rexmpp
;; Homepage: https://git.uberspace.net/rexmpp/
;; Version: 0.0.0

;; This file is not part of GNU Emacs.

;; This program is free software: you can redistribute it and/or modify
;; it under the terms of the GNU General Public License as published by
;; the Free Software Foundation, either version 3 of the License, or
;; (at your option) any later version.

;; This program is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU General Public License for more details.

;; You should have received a copy of the GNU General Public License
;; along with this program.  If not, see <http://www.gnu.org/licenses/>.

;;; Commentary:

;; See rexmpp's xml_interface.c. Possibly it'll also work with other
;; libraries later.

;; This is even less polished than the library.

;;; Code:

(require 'xml)
(require 'seq)
(require 'tracking)
(require 'auth-source)

(defgroup xmpp nil
  "An Emacs interface to rexmpp."
  :prefix "xmpp-"
  :group 'applications)

(defface xmpp-timestamp
  '((((type graphic) (class color) (background dark)) :foreground "SteelBlue")
    (((type graphic) (class color) (background light)) :foreground "SteelBlue"))
  "Timestamp face."
  :group 'xmpp)

(defface xmpp-my-nick
  '((((type graphic) (class color) (background dark)) :foreground "LightSkyBlue")
    (((type graphic) (class color) (background light)) :foreground "Blue")
    (t :weight bold))
  "Own nick face."
  :group 'xmpp)

(defface xmpp-other-nick
  '((((type graphic) (class color) (background dark)) :foreground "PaleGreen")
    (((type graphic) (class color) (background light)) :foreground "DarkGreen")
    (t :weight bold))
  "Others' nick face."
  :group 'xmpp)

(defface xmpp-presence
  '((((type graphic) (class color) (background dark)) :foreground "wheat1")
    (((type graphic) (class color) (background light)) :foreground "wheat4"))
  "Presence notification face."
  :group 'xmpp)

(defface xmpp-action
  '((((type graphic) (class color) (background dark)) :foreground "thistle1")
    (((type graphic) (class color) (background light)) :foreground "thistle4"))
  "Action (/me) face."
  :group 'xmpp)


(defvar xmpp-command "rexmpp_xml_interface"
  "A command to run an XMPP client subprocess.")

(defvar xmpp-timestamp-format "%H:%M"
  "Time string format to use in query buffers.")

(defvar xmpp-proc nil
  "XMPP process buffer. This should be defined for all the
  XMPP-related buffers.")
(make-variable-buffer-local 'xmpp-proc)

(defvar xmpp-jid nil
  "User JID related to a current XMPP-related buffer.")
(make-variable-buffer-local 'xmpp-jid)

(defvar xmpp-query-buffers nil
  "An association list of query buffers corresponding to JIDs.")
(make-variable-buffer-local 'xmpp-query-buffers)

(defvar xmpp-muc-buffers nil
  "An association list of MUC buffers corresponding to conference
  JIDs.")
(make-variable-buffer-local 'xmpp-muc-buffers)

(defvar xmpp-log-buffer nil
  "An XMPP log buffer.")
(make-variable-buffer-local 'xmpp-log-buffer)

(defvar xmpp-console-buffer nil
  "An XMPP text console buffer.")
(make-variable-buffer-local 'xmpp-console-buffer)

(defvar xmpp-xml-buffer nil
  "An XMPP XML console buffer.")
(make-variable-buffer-local 'xmpp-xml-buffer)

(defvar xmpp-active-requests nil
  "Active requests for a subprocess.")
(make-variable-buffer-local 'xmpp-active-requests)

(defvar xmpp-truncate-buffer-at 100000
  "The buffer size at which to truncate an XMPP-related buffer by
  approximately halving it.")

(defun xmpp-timestamp-string (&optional time)
  (let ((str (format-time-string xmpp-timestamp-format time)))
    (add-face-text-property 0 (length str) 'xmpp-timestamp nil str)
    str))

(defun xmpp-activity-notify ()
  (tracking-add-buffer (current-buffer)))

(defun xmpp-jid-to-bare (jid)
  (let* ((jid-list (reverse (string-to-list jid)))
         (resource-pos (seq-position jid-list ?/)))
    (if resource-pos
        (concat (reverse (seq-drop jid-list (1+ resource-pos))))
      jid)))

(defun xmpp-jid-localpart (jid)
  (let* ((jid-list (string-to-list jid))
         (at-pos (seq-position jid-list ?@)))
    (when at-pos
      (concat (seq-take jid-list at-pos)))))

(defun xmpp-jid-resource (jid)
  (let* ((jid-list (reverse (string-to-list jid)))
         (resource-pos (seq-position jid-list ?/)))
    (if resource-pos
        (concat (reverse (seq-take jid-list resource-pos)))
      jid)))


(defun xmpp-gen-id ()
  (number-to-string (random)))

(defun xmpp-xml-set-xmlns (node &optional parent-ns)
  "Propagates xmlns to child elements. This is a temporary hack
to keep using xml.el without proper namespace parsing, so that
its printing--which doesn't handle namespaces--can be used too."
  (if (listp node)
      (let* ((xmlns (xml-get-attribute-or-nil node 'xmlns))
             (ns (or xmlns parent-ns))
             (attrs (xml-node-attributes node)))
        (cons (xml-node-name node)
              (cons (if xmlns
                        attrs
                      (if ns
                          (cons (cons 'xmlns ns) attrs)
                        attrs))
                    (mapcar (lambda (x) (xmpp-xml-set-xmlns x ns)) (xml-node-children node)))))
    node))

(defun xmpp-xml-parse-region (&optional beg end buffer)
  (mapcar 'xmpp-xml-set-xmlns
          (xml-parse-region beg end buffer)))

(defun xmpp-xml-match (xml name ns)
  (and (consp xml)
       (eq (xml-node-name xml) name)
       (equal (xml-get-attribute-or-nil xml 'xmlns) ns)))

(defun xmpp-xml-child (xml name &optional ns)
  (seq-find (lambda (x) (xmpp-xml-match x name ns)) xml))

(defun xmpp-proc-write (xml &optional proc)
  (let ((cur-proc (or proc xmpp-proc)))
    (with-temp-buffer
      (xml-print xml)
      (insert "\n")
      (process-send-region cur-proc (point-min) (point-max)))))

(defun xmpp-with-message-body (proc message-xml func)
  (let* ((message-contents (xml-node-children message-xml))
         (message-body (xmpp-xml-child message-contents 'body "jabber:client"))
         (message-openpgp (xmpp-xml-child message-contents 'openpgp "urn:xmpp:openpgp:0")))
    (if message-openpgp
        ;; TODO: check validation results.
        (xmpp-request `(openpgp-decrypt-message nil ,message-xml)
                      (lambda (response)
                        (let* ((payload (xmpp-xml-child response 'payload "urn:xmpp:openpgp:0")))
                          (funcall func (car (xml-node-children payload)))))
                      proc)
      (funcall func message-body))))

(defun xmpp-message-string (str)
  (if (string-prefix-p "/me " str)
      (let ((action (substring str 3)))
        (add-face-text-property
         0
         (length action)
         'xmpp-action
         nil
         action)
        action)
    (concat ": " str)))

(defun xmpp-process-input (proc xml)
  (with-current-buffer (process-buffer proc)
    (with-current-buffer xmpp-xml-buffer
      (xmpp-insert (format "<!-- server, %s -->\n" (current-time-string)))
      (xmpp-insert-xml (list xml))
      (xmpp-insert "\n"))
    (when (xmpp-xml-match xml 'presence "jabber:client")
      (let* ((presence-from (xml-get-attribute-or-nil xml 'from))
             (presence-type (or (xml-get-attribute-or-nil xml 'type) "available"))
             (presence-show (car (xml-node-children (xmpp-xml-child xml 'show "jabber:client"))))
             (presence-status (car (xml-node-children (xmpp-xml-child xml 'status "jabber:client"))))
             (presence-string
              (concat
               presence-from " is "
               presence-type
               (when presence-show
                 (concat " (" presence-show ")"))
               (when presence-status
                 (concat ": " presence-status))))
             (bare-jid (xmpp-jid-to-bare presence-from))
             (resourcepart (xmpp-jid-resource presence-from)))
        (add-face-text-property
         0
         (length presence-string)
         'xmpp-presence
         nil
         presence-string)
        (when (assoc bare-jid xmpp-query-buffers)
          (with-current-buffer (cdr (assoc bare-jid xmpp-query-buffers))
            (xmpp-insert (concat
                          (xmpp-timestamp-string) ", "
                          presence-string "\n"))))
        (when (assoc bare-jid xmpp-muc-buffers)
          (with-current-buffer (cdr (assoc bare-jid xmpp-muc-buffers))
            (xmpp-insert
             (concat (xmpp-timestamp-string) ", "
                     presence-string "\n")))))))
  (when (xmpp-xml-match xml 'message "jabber:client")
    (let* ((carbons-sent (xmpp-xml-child xml 'sent "urn:xmpp:carbons:2"))
           (carbons-received (xmpp-xml-child xml 'received "urn:xmpp:carbons:2"))
           (carbons-forwarded (xmpp-xml-child (or carbons-sent carbons-received)
                                              'forwarded "urn:xmpp:forward:0"))
           (carbons-message (xmpp-xml-child carbons-forwarded 'message "jabber:client"))
           (message-xml (or carbons-message xml))
           (message-from (xml-get-attribute-or-nil message-xml 'from))
           (message-delay (xmpp-xml-child message-xml 'delay "urn:xmpp:delay"))
           (message-time (if message-delay
                             (encode-time
                              (iso8601-parse
                               (xml-get-attribute-or-nil message-delay 'stamp)))
                           (current-time)))
           (chat-with (cond (carbons-sent (xml-get-attribute-or-nil message-xml 'to))
                            (t message-from))))
      (xmpp-with-message-body
       proc message-xml
       (lambda (message-body)
         (when message-body
           (let ((message-str
                  (xmpp-message-string (car (xml-node-children message-body)))))
             (xmpp-with-name
              message-from
              (lambda (message-from-name)
                (pcase (xml-get-attribute-or-nil xml 'type)
                  ("chat"
                   (with-current-buffer (xmpp-query chat-with proc)
                     (add-face-text-property
                      0
                      (length message-from-name)
                      (if (equal (with-current-buffer (process-buffer xmpp-proc) xmpp-jid)
                                 (xmpp-jid-to-bare chat-with))
                          'xmpp-my-nick
                        'xmpp-other-nick)
                      nil
                      message-from-name)
                     (xmpp-insert
                      (concat (xmpp-timestamp-string message-time) ", "
                              message-from-name
                              message-str "\n"))
                     (xmpp-activity-notify)))
                  ("groupchat"
                   (with-current-buffer (xmpp-muc-buffer chat-with proc)
                     (let ((from-nick (xmpp-jid-resource message-from)))
                       (add-face-text-property
                        0
                        (length from-nick)
                        (if (equal xmpp-muc-my-occupant-jid message-from)
                            'xmpp-my-nick
                          'xmpp-other-nick)
                        nil
                        from-nick)
                       (xmpp-insert
                        (concat (xmpp-timestamp-string message-time) ", "
                                from-nick
                                message-str "\n"))
                       (xmpp-activity-notify))))))))))))))

(defun xmpp-set-from (proc xml)
  (let* ((name (xml-node-name xml))
         (attr (xml-node-attributes xml))
         (children (xml-node-children xml))
         (new-attr (if (assoc 'from attr)
                       attr
                     (cons (cons 'from
                                 (with-current-buffer
                                     (process-buffer proc)
                                   xmpp-jid))
                           attr))))
    (cons name (cons new-attr children))))

(defun xmpp-process-output (proc xml)
  (with-current-buffer (process-buffer proc)
    (with-current-buffer xmpp-xml-buffer
      (xmpp-insert (format "<!-- client, %s -->\n" (current-time-string)))
      (xmpp-insert-xml (list xml))
      (xmpp-insert "\n")))
  (when (xmpp-xml-match xml 'message "jabber:client")
    (xmpp-with-message-body
     ;; The "from" attribute is needed for validation.
     proc (xmpp-set-from proc xml)
     (lambda (message-body)
       (xmpp-with-name
        xmpp-jid
        (lambda (my-name)
          (add-face-text-property 0 (length my-name) 'xmpp-my-nick nil my-name)
          (let ((message-to (xml-get-attribute-or-nil xml 'to)))
            (pcase (xml-get-attribute-or-nil xml 'type)
              ("chat"
               (when message-body
                 (let ((buf (xmpp-query message-to proc)))
                   (when buf
                     (with-current-buffer buf
                       (xmpp-insert
                        (concat
                         (xmpp-timestamp-string) ", "
                         my-name
                         (xmpp-message-string
                          (car (xml-node-children message-body)))
                         "\n")))))))
              ("groupchat" nil))))))))
  (when (and (xmpp-xml-match xml 'presence "jabber:client")
             (or (not (xml-get-attribute-or-nil xml 'type))
                 (equal (xml-get-attribute-or-nil xml 'type) "available"))
             (xmpp-xml-child xml 'x "http://jabber.org/protocol/muc"))
    ;; Joining a MUC
    (let* ((occupant-jid (xml-get-attribute xml 'to))
           (muc-jid (xmpp-jid-to-bare occupant-jid))
           (buf (xmpp-muc-buffer muc-jid proc)))
      (with-current-buffer buf
        (setq-local xmpp-muc-my-occupant-jid occupant-jid)))))

(defun xmpp-process (proc xml)
  (let* ((buf (process-buffer proc))
         (log-buf (with-current-buffer buf xmpp-log-buffer))
         (console-buf (with-current-buffer buf xmpp-console-buffer))
         (my-jid (with-current-buffer buf xmpp-jid))
         (xml-elem (car xml)))
    (pcase (xml-node-name xml-elem)
      ('request
       (let ((rid (xml-get-attribute xml-elem 'id)))
         (pcase (car (xml-node-children xml-elem))
           (`(sasl ((property . ,prop)))
            (let ((resp
                   (if (equal prop "password")
                       (let ((secret
                              (plist-get
                               (car
                                (auth-source-search
                                 :max 1
                                 :user my-jid
                                 :port "xmpp"
                                 :require '(:user :secret))) :secret)))
                         (if (functionp secret)
                             (funcall secret)
                           secret))
                     (read-passwd
                      (concat "SASL " prop ": ")))))
              (xmpp-proc-write `((response ((id . ,rid)) ,resp))
                               proc)))
           (`(xml-in nil ,xml-in)
            (progn (xmpp-process-input proc xml-in)
                   (xmpp-proc-write `((response ((id . ,rid)) "0")) proc)))
           (`(xml-out nil ,xml-out)
            (progn (xmpp-process-output proc xml-out)
                   (xmpp-proc-write `((response ((id . ,rid)) "0")) proc))))))
      ('log
       (with-current-buffer log-buf
         (goto-char (point-max))
         (insert (format "%s [%s] %s\n" (current-time-string)
                         (xml-get-attribute xml-elem 'priority)
                         (car (xml-node-children xml-elem))))))
      ('console
       (with-current-buffer console-buf
         (xmpp-insert (car (xml-node-children xml-elem)))))
      ('response
       (with-current-buffer buf
         (let* ((rid (xml-get-attribute xml-elem 'id))
                (cb (alist-get rid xmpp-active-requests nil nil 'string-equal)))
           (setq xmpp-active-requests
                 (assoc-delete-all rid xmpp-active-requests))
           (when cb
             (funcall cb (car (xml-node-children xml-elem))))))))))

(defun xmpp-request (req cb &optional proc)
  (let ((cur-proc (or proc xmpp-proc))
        (req-id (xmpp-gen-id)))
    (with-current-buffer (process-buffer cur-proc)
      (xmpp-proc-write `((request ((id . ,req-id)) ,req)) cur-proc)
      (push (cons req-id cb) xmpp-active-requests))))

(defun xmpp-with-name (jid cb &optional proc)
  (let ((cur-proc (or proc xmpp-proc))
        (bare-jid (xmpp-jid-to-bare jid)))
    (with-current-buffer (process-buffer cur-proc)
      ;; Use resource for MUC private messages, determine a nick
      ;; otherwise.
      (if (assoc bare-jid xmpp-muc-buffers)
          (funcall cb (xmpp-jid-resource jid))
        (xmpp-request `(get-name nil ,jid) cb proc)))))

(defun xmpp-http-upload (path &optional proc)
  (interactive "fFile path: ")
  (xmpp-request
   `(http-upload nil ,path)
   (lambda (url)
     (kill-new url)
     (message "Uploaded the file to %s" url))
   proc))

(defun xmpp-stop (&optional proc)
  (interactive)
  (xmpp-request '(stop) nil proc))

(defun xmpp-kill-buffers (&optional proc)
  (interactive)
  (when (and xmpp-log-buffer
             xmpp-console-buffer
             xmpp-xml-buffer)
    (mapcar (lambda (b) (kill-buffer (cdr b))) xmpp-query-buffers)
    (mapcar (lambda (b) (kill-buffer (cdr b))) xmpp-muc-buffers)
    (kill-buffer xmpp-log-buffer)
    (kill-buffer xmpp-console-buffer)
    (kill-buffer xmpp-xml-buffer)
    (kill-buffer)))

(defun xmpp-send (xml &optional proc)
  (xmpp-request `(send nil ,xml) nil proc))

(defun xmpp-filter (proc str)
  (when (buffer-live-p (process-buffer proc))
    (with-current-buffer (process-buffer proc)
      (save-excursion
        (goto-char (point-max))
        (insert str)
        (goto-char (point-min))
        (let ((zero (search-forward "\0" nil t)))
          (while zero
            (let ((xml (xmpp-xml-parse-region (point-min) (1- zero))))
              (xmpp-process proc xml)
              (delete-region (point-min) zero)
              (setq zero (search-forward "\0" nil t)))))))))

;;;###autoload
(defun xmpp (jid)
  "Initiates a new XMPP session."
  (interactive "sJID: ")
  (let* ((bare-jid (xmpp-jid-to-bare jid))
         (proc-buf (generate-new-buffer
                    (concat "*xmpp:" bare-jid " process*"))))
    (with-current-buffer proc-buf
      (setq-local xmpp-jid bare-jid)
      (setq-local xmpp-active-requests nil)
      (setq-local xmpp-query-buffers '())
      (setq-local xmpp-muc-buffers '())
      (setq-local xmpp-log-buffer
                  (generate-new-buffer
                   (concat "*xmpp:" bare-jid " log*")))
      (setq-local xmpp-console-buffer
                  (generate-new-buffer
                   (concat "*xmpp:" bare-jid " text console*")))
      (setq-local xmpp-xml-buffer
                  (generate-new-buffer
                   (concat "*xmpp:" bare-jid " XML console*")))
      (with-current-buffer xmpp-console-buffer
        (xmpp-console-mode))
      (with-current-buffer xmpp-xml-buffer
        (xmpp-xml-mode))
      (setq-local xmpp-proc
                  (make-process :name "xmpp"
                                :command (list xmpp-command jid)
                                :buffer proc-buf
                                :filter 'xmpp-filter))
      (let ((new-proc xmpp-proc))
        (with-current-buffer xmpp-console-buffer
          (setq-local xmpp-proc new-proc))
        (with-current-buffer xmpp-xml-buffer
          (setq-local xmpp-proc new-proc))
        (with-current-buffer xmpp-log-buffer
          (setq-local xmpp-proc new-proc))))))

(defun xmpp-restart (&optional proc)
  "Restarts an XMPP process."
  (interactive)
  (let* ((cur-proc (or proc xmpp-proc))
         (proc-buf (process-buffer cur-proc)))
    (when (and cur-proc (process-live-p cur-proc))
      (xmpp-stop cur-proc))
    (with-current-buffer proc-buf
      (setq-local xmpp-active-requests nil)
      (setq-local xmpp-proc
                  (make-process :name "xmpp"
                                :command (list xmpp-command xmpp-jid)
                                :buffer proc-buf
                                :filter 'xmpp-filter))
      (let ((new-proc xmpp-proc))
        (mapcar (lambda (b)
                  (with-current-buffer b (setq-local xmpp-proc new-proc)))
                (append (list xmpp-console-buffer xmpp-xml-buffer xmpp-log-buffer)
                        (mapcar 'cdr xmpp-query-buffers)
                        (mapcar 'cdr xmpp-muc-buffers)))))))

(defun xmpp-insert (args)
  (save-excursion
    (when (and xmpp-truncate-buffer-at
               (> xmpp-prompt-start-marker xmpp-truncate-buffer-at))
      (goto-char (/ xmpp-truncate-buffer-at 2))
      (search-forward "\n")
      (delete-region (point-min) (point)))
    (goto-char xmpp-prompt-start-marker)
    (funcall 'insert args)
    (set-marker xmpp-prompt-start-marker (point))
    (set-marker xmpp-prompt-end-marker (+ 2 (point)))))

(defun xmpp-insert-xml (xml)
  (save-excursion
    (goto-char xmpp-prompt-start-marker)
    (xml-print xml)
    (setq-local xmpp-prompt-start-marker (point-marker))
    (goto-char (+ 2 xmpp-prompt-start-marker))
    (setq-local xmpp-prompt-end-marker (point-marker))))

(defun xmpp-send-input ()
  (interactive)
  (let ((input (buffer-substring xmpp-prompt-end-marker (point-max))))
    (unless (string-empty-p input)
      (pcase major-mode
        ('xmpp-query-mode (xmpp-send `(message ((xmlns . "jabber:client")
                                                (id . ,(xmpp-gen-id))
                                                (to . ,xmpp-jid)
                                                (type . "chat"))
                                               (body nil ,input))))
        ('xmpp-muc-mode (xmpp-send `(message ((xmlns . "jabber:client")
                                              (id . ,(xmpp-gen-id))
                                              (to . ,xmpp-jid)
                                              (type . "groupchat"))
                                             (body nil ,input))))
        ('xmpp-console-mode (xmpp-request `(console nil ,input) nil xmpp-proc))
        ('xmpp-xml-mode
         (mapcar 'xmpp-send (xmpp-xml-parse-region xmpp-prompt-end-marker (point-max))))))
    (delete-region xmpp-prompt-end-marker (point-max))))


(defvar xmpp-mode-map
  (let ((map (make-sparse-keymap)))
    (define-key map (kbd "RET") 'xmpp-send-input)
    map)
  "Keymap for `xmpp-mode'.")

(define-derived-mode xmpp-mode nil "XMPP"
  "XMPP major mode."
  (insert "> ")
  (add-text-properties (point-min) (point-max)
		       '(field t read-only t rear-nonsticky t))
  (setq-local xmpp-prompt-start-marker (point-min-marker))
  (setq-local xmpp-prompt-end-marker (point-max-marker)))

(define-derived-mode xmpp-query-mode xmpp-mode "XMPP-query"
  "XMPP Query major mode.")

(define-derived-mode xmpp-muc-mode xmpp-mode "XMPP-MUC"
  "XMPP Query major mode.")

(define-derived-mode xmpp-console-mode xmpp-mode "XMPP-text-console"
  "XMPP Text Console major mode.")

(define-derived-mode xmpp-xml-mode xmpp-mode "XMPP-XML-console"
  "XMPP XML Console major mode.")


(defun xmpp-query-buffer-on-close ()
  (let ((query-jid xmpp-jid))
    (when (buffer-live-p (process-buffer xmpp-proc))
      (with-current-buffer (process-buffer xmpp-proc)
        (setq xmpp-query-buffers
              (seq-remove (lambda (x) (equal (car x) query-jid))
                          xmpp-query-buffers)))))
  t)

(defun xmpp-muc-buffer-on-close ()
  (let ((muc-jid xmpp-jid))
    (when (buffer-live-p (process-buffer xmpp-proc))
      (with-current-buffer (process-buffer xmpp-proc)
        (setq xmpp-muc-buffers
              (seq-remove (lambda (x) (equal (car x) muc-jid))
                          xmpp-muc-buffers)))))
  t)

(defun xmpp-query (jid &optional proc)
  (interactive "sQuery JID: ")
  (let ((process (or proc xmpp-proc)))
    (with-current-buffer (process-buffer process)
      ;; Use full JID for MUC private messages, but a bare JID for
      ;; regular chats.
      (let* ((bare-jid (xmpp-jid-to-bare jid))
             (target-jid (if (assoc bare-jid xmpp-muc-buffers)
                             jid
                           bare-jid))
             (buf (if (assoc target-jid xmpp-query-buffers)
                      (cdr (assoc target-jid xmpp-query-buffers))
                    (let ((query-buf (generate-new-buffer
                                      (concat "*xmpp:" target-jid "*"))))
                      (with-current-buffer query-buf
                        (xmpp-query-mode)
                        (setq-local xmpp-jid target-jid)
                        (setq-local xmpp-proc process)
                        (setq-local kill-buffer-query-functions
                                    (cons #'xmpp-query-buffer-on-close
                                          kill-buffer-query-functions)))
                      (push (cons target-jid query-buf) xmpp-query-buffers)
                      query-buf))))
        (when (interactive-p)
          (display-buffer buf))
        buf))))

(defun xmpp-muc-join (jid &optional nick proc)
  (interactive "sConference JID: ")
  (with-current-buffer (process-buffer (or proc xmpp-proc))
    (let* ((bare-jid (xmpp-jid-to-bare jid))
           (my-nick (or nick (xmpp-jid-localpart xmpp-jid)))
           (full-jid (concat bare-jid "/" my-nick)))
      (xmpp-send `(presence ((xmlns . "jabber:client")
                             (id . ,(xmpp-gen-id))
                             (to . ,full-jid))
                            (x ((xmlns . "http://jabber.org/protocol/muc")))))
      (xmpp-request
       `(muc-ping-set ((occupant-jid . ,full-jid)
                       (delay . "600"))
                      nil)
       nil
       proc))))

(defun xmpp-muc-leave (jid &optional proc)
  (interactive "sConference JID: ")
  (with-current-buffer (process-buffer (or proc xmpp-proc))
    (with-current-buffer (cdr (assoc jid xmpp-muc-buffers))
      (xmpp-send `(presence ((xmlns . "jabber:client")
                             (id . ,(xmpp-gen-id))
                             (to . ,xmpp-muc-my-occupant-jid)
                             (type . "unavailable"))))
      (xmpp-request
       `(muc-ping-remove ((occupant-jid . ,xmpp-muc-my-occupant-jid))
                         nil)
       nil))))

(defun xmpp-muc-buffer (jid &optional proc)
  (let* ((process (or proc xmpp-proc))
         (bare-jid (xmpp-jid-to-bare jid)))
    (with-current-buffer (process-buffer process)
      (let ((buf (if (assoc bare-jid xmpp-muc-buffers)
                     (cdr (assoc bare-jid xmpp-muc-buffers))
                   (let ((muc-buf (generate-new-buffer (concat "*xmpp:" bare-jid "*"))))
                     (with-current-buffer muc-buf
                       (xmpp-muc-mode)
                       (setq-local xmpp-jid bare-jid)
                       (setq-local xmpp-proc process)
                       (setq-local kill-buffer-query-functions
                                   (cons #'xmpp-muc-buffer-on-close
                                         kill-buffer-query-functions)))
                     (push (cons bare-jid muc-buf) xmpp-muc-buffers)
                     muc-buf))))
        (when (interactive-p)
          (display-buffer buf))
        buf))))

(provide 'xmpp)

;;; xmpp.el ends here
