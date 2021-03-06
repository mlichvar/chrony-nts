/*
  chronyd/chronyc - Programs for keeping computer clocks accurate.

 **********************************************************************
 * Copyright (C) Miroslav Lichvar  2020
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 * 
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 * 
 **********************************************************************

  =======================================================================

  NTS-KE session used by server and client
  */

#include "config.h"

#include "sysincl.h"

#include "nts_ke_session.h"

#include "conf.h"
#include "logging.h"
#include "memory.h"
#include "siv.h"
#include "socket.h"
#include "sched.h"
#include "util.h"

#include <gnutls/gnutls.h>

#define INVALID_SOCK_FD (-8)

struct RecordHeader {
  uint16_t type;
  uint16_t body_length;
};

struct Message {
  int length;
  int sent;
  int parsed;
  int complete;
  unsigned char data[NKE_MAX_MESSAGE_LENGTH];
};

typedef enum {
  KE_WAIT_CONNECT,
  KE_HANDSHAKE,
  KE_SEND,
  KE_RECEIVE,
  KE_SHUTDOWN,
  KE_STOPPED,
} KeState;

struct NKSN_Instance_Record {
  int server;
  char *name;
  NKSN_MessageHandler handler;
  void *handler_arg;

  KeState state;
  int sock_fd;
  gnutls_session_t tls_session;
  SCH_TimeoutID timeout_id;

  struct Message message;
  int new_message;
  int ended_message;
};

/* ================================================== */

static gnutls_priority_t priority_cache;

static int credentials_counter = 0;

/* ================================================== */

static void
reset_message(struct Message *message)
{
  message->length = 0;
  message->sent = 0;
  message->parsed = 0;
  message->complete = 0;
}

/* ================================================== */

static int
add_record(struct Message *message, int critical, int type, const void *body, int body_length)
{
  struct RecordHeader header;

  if (body_length < 0 || body_length > 0xffff || type < 0 || type > 0x7fff ||
      message->length + sizeof (header) + body_length > sizeof (message->data))
    return 0;

  header.type = htons(!!critical * NKE_RECORD_CRITICAL_BIT | type);
  header.body_length = htons(body_length);

  memcpy(&message->data[message->length], &header, sizeof (header));
  message->length += sizeof (header);

  if (body_length > 0) {
    memcpy(&message->data[message->length], body, body_length);
    message->length += body_length;
  }

  return 1;
}

/* ================================================== */

static void
reset_message_parsing(struct Message *message)
{
  message->parsed = 0;
}

/* ================================================== */

static int
get_record(struct Message *message, int *critical, int *type, int *body_length,
           void *body, int buffer_length)
{
  struct RecordHeader header;
  int blen, rlen;

  if (message->length < message->parsed + sizeof (header) ||
      buffer_length < 0)
    return 0;

  memcpy(&header, &message->data[message->parsed], sizeof (header));

  blen = ntohs(header.body_length);
  rlen = sizeof (header) + blen;

  if (message->length < message->parsed + rlen)
    return 0;

  if (critical)
    *critical = !!(ntohs(header.type) & NKE_RECORD_CRITICAL_BIT);
  if (type)
    *type = ntohs(header.type) & ~NKE_RECORD_CRITICAL_BIT;
  if (body)
    memcpy(body, &message->data[message->parsed + sizeof (header)], MIN(buffer_length, blen));
  if (body_length)
    *body_length = blen;

  message->parsed += rlen;

  return 1;
}

/* ================================================== */

static int
check_message_format(struct Message *message, int eof)
{
  int critical = 0, type = -1, length = -1, ends = 0;

  reset_message_parsing(message);
  message->complete = 0;

  while (get_record(message, &critical, &type, &length, NULL, 0)) {
    if (type == NKE_RECORD_END_OF_MESSAGE) {
      if (!critical || length != 0 || ends > 0)
        return 0;
      ends++;
    }
  }

  /* If the message cannot be fully parsed, but more data may be coming,
     consider the format to be ok */
  if (message->length == 0 || message->parsed < message->length)
    return !eof;

  if (type != NKE_RECORD_END_OF_MESSAGE)
    return !eof;

  message->complete = 1;

  return 1;
}

/* ================================================== */

static gnutls_session_t
create_tls_session(int server_mode, int sock_fd, const char *server_name,
                   gnutls_certificate_credentials_t credentials,
                   gnutls_priority_t priority)
{
  unsigned char alpn_name[sizeof (NKE_ALPN_NAME)];
  gnutls_session_t session;
  gnutls_datum_t alpn;
  int r;

  r = gnutls_init(&session, GNUTLS_NONBLOCK | (server_mode ? GNUTLS_SERVER : GNUTLS_CLIENT));
  if (r < 0) {
    LOG(LOGS_ERR, "Could not %s TLS session : %s", "create", gnutls_strerror(r));
    return NULL;
  }

  if (!server_mode) {
    r = gnutls_server_name_set(session, GNUTLS_NAME_DNS, server_name, strlen(server_name));
    if (r < 0)
      goto error;
    gnutls_session_set_verify_cert(session, server_name, 0);
  }

  r = gnutls_priority_set(session, priority);
  if (r < 0)
    goto error;

  r = gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, credentials);
  if (r < 0)
    goto error;

  memcpy(alpn_name, NKE_ALPN_NAME, sizeof (alpn_name));
  alpn.data = alpn_name;
  alpn.size = sizeof (alpn_name) - 1;

  r = gnutls_alpn_set_protocols(session, &alpn, 1, 0);
  if (r < 0)
    goto error;

  gnutls_transport_set_int(session, sock_fd);

  return session;

error:
  LOG(LOGS_ERR, "Could not %s TLS session : %s", "set", gnutls_strerror(r));
  gnutls_deinit(session);
  return NULL;
}

/* ================================================== */

static void
stop_session(NKSN_Instance inst)
{
  if (inst->state == KE_STOPPED)
    return;

  inst->state = KE_STOPPED;

  SCH_RemoveFileHandler(inst->sock_fd);
  SCK_CloseSocket(inst->sock_fd);
  inst->sock_fd = INVALID_SOCK_FD;

  gnutls_deinit(inst->tls_session);
  inst->tls_session = NULL;

  SCH_RemoveTimeout(inst->timeout_id);
  inst->timeout_id = 0;
}

/* ================================================== */

static void
session_timeout(void *arg)
{
  NKSN_Instance inst = arg;

  LOG(inst->server ? LOGS_DEBUG : LOGS_ERR, "NTS-KE session with %s timed out", inst->name);

  inst->timeout_id = 0;
  stop_session(inst);
}

/* ================================================== */

static int
get_socket_error(int sock_fd)
{
  int optval;
  socklen_t optlen = sizeof (optval);

  if (getsockopt(sock_fd, SOL_SOCKET, SO_ERROR, &optval, &optlen) < 0) {
    DEBUG_LOG("getsockopt() failed : %s", strerror(errno));
    return EINVAL;
  }

  return optval;
}

/* ================================================== */

static int
check_alpn(NKSN_Instance inst)
{
  gnutls_datum_t alpn;
  int r;

  r = gnutls_alpn_get_selected_protocol(inst->tls_session, &alpn);
  if (r < 0 || alpn.size != sizeof (NKE_ALPN_NAME) - 1 ||
      strncmp((const char *)alpn.data, NKE_ALPN_NAME, sizeof (NKE_ALPN_NAME) - 1))
    return 0;

  return 1;
}

/* ================================================== */

static void
change_state(NKSN_Instance inst, KeState state)
{
  int output;

  switch (state) {
    case KE_HANDSHAKE:
      output = !inst->server;
      break;
    case KE_WAIT_CONNECT:
    case KE_SEND:
    case KE_SHUTDOWN:
      output = 1;
      break;
    case KE_RECEIVE:
      output = 0;
      break;
    default:
      assert(0);
  }

  SCH_SetFileHandlerEvent(inst->sock_fd, SCH_FILE_OUTPUT, output);

  inst->state = state;
}

/* ================================================== */

static int
handle_event(NKSN_Instance inst, int event)
{
  struct Message *message = &inst->message;
  int r;

  DEBUG_LOG("Session event %d fd=%d state=%d", event, inst->sock_fd, (int)inst->state);

  switch (inst->state) {
    case KE_WAIT_CONNECT:
      /* Check if connect() succeeded */
      if (event != SCH_FILE_OUTPUT)
        return 0;

      r = get_socket_error(inst->sock_fd);

      if (r) {
        LOG(LOGS_ERR, "Could not connect to %s : %s", inst->name, strerror(r));
        stop_session(inst);
        return 0;
      }

      DEBUG_LOG("Connected to %s", inst->name);

      change_state(inst, KE_HANDSHAKE);
      return 0;

    case KE_HANDSHAKE:
      r = gnutls_handshake(inst->tls_session);

      if (r < 0) {
        if (gnutls_error_is_fatal(r)) {
          LOG(inst->server ? LOGS_DEBUG : LOGS_ERR,
              "TLS handshake with %s failed : %s", inst->name, gnutls_strerror(r));
          stop_session(inst);
          return 0;
        }

        /* Disable output when the handshake is trying to receive data */
        SCH_SetFileHandlerEvent(inst->sock_fd, SCH_FILE_OUTPUT,
                                gnutls_record_get_direction(inst->tls_session));
        return 0;
      }

      if (DEBUG) {
        char *description = gnutls_session_get_desc(inst->tls_session);
        DEBUG_LOG("Handshake with %s completed %s",
                  inst->name, description ? description : "");
        gnutls_free(description);
      }

      if (!check_alpn(inst)) {
        LOG(inst->server ? LOGS_DEBUG : LOGS_ERR, "NTS-KE not supported by %s", inst->name);
        stop_session(inst);
        return 0;
      }

      /* Client will send a request to the server */
      change_state(inst, inst->server ? KE_RECEIVE : KE_SEND);
      return 0;

    case KE_SEND:
      assert(inst->new_message && message->complete);

      r = gnutls_record_send(inst->tls_session, &message->data[message->sent],
                             message->length - message->sent);

      if (r < 0) {
        if (gnutls_error_is_fatal(r)) {
          LOG(inst->server ? LOGS_DEBUG : LOGS_ERR,
              "Could not send NTS-KE message to %s : %s", inst->name, gnutls_strerror(r));
          stop_session(inst);
        }
        return 0;
      }

      DEBUG_LOG("Sent %d bytes to %s", r, inst->name);

      message->sent += r;
      if (message->sent < message->length)
        return 0;

      /* Client will receive a response */
      change_state(inst, inst->server ? KE_SHUTDOWN : KE_RECEIVE);
      reset_message(&inst->message);
      inst->new_message = 0;
      return 0;

    case KE_RECEIVE:
      do {
        if (message->length >= sizeof (message->data)) {
          DEBUG_LOG("Message is too long");
          stop_session(inst);
          return 0;
        }

        r = gnutls_record_recv(inst->tls_session, &message->data[message->length],
                               sizeof (message->data) - message->length);

        if (r < 0) {
          /* Handle a renegotiation request on both client and server as
             a protocol error */
          if (gnutls_error_is_fatal(r) || r == GNUTLS_E_REHANDSHAKE) {
            LOG(inst->server ? LOGS_DEBUG : LOGS_ERR,
                "Could not receive NTS-KE message from %s : %s",
                inst->name, gnutls_strerror(r));
            stop_session(inst);
          }
          return 0;
        }

        DEBUG_LOG("Received %d bytes from %s", r, inst->name);

        message->length += r;

      } while (gnutls_record_check_pending(inst->tls_session) > 0);

      if (!check_message_format(message, r == 0)) {
        LOG(inst->server ? LOGS_DEBUG : LOGS_ERR,
            "Received invalid NTS-KE message from %s", inst->name);
        stop_session(inst);
        return 0;
      }

      /* Wait for more data if the message is not complete yet */
      if (!message->complete)
        return 0;

      /* Server will send a response to the client */
      change_state(inst, inst->server ? KE_SEND : KE_SHUTDOWN);
      break;

    case KE_SHUTDOWN:
      r = gnutls_bye(inst->tls_session, GNUTLS_SHUT_RDWR);

      if (r < 0) {
        if (gnutls_error_is_fatal(r)) {
          DEBUG_LOG("Shutdown with %s failed : %s", inst->name, gnutls_strerror(r));
          stop_session(inst);
          return 0;
        }

        /* Disable output when the TLS shutdown is trying to receive data */
        SCH_SetFileHandlerEvent(inst->sock_fd, SCH_FILE_OUTPUT,
                                gnutls_record_get_direction(inst->tls_session));
        return 0;
      }

      SCK_ShutdownConnection(inst->sock_fd);
      stop_session(inst);

      DEBUG_LOG("Shutdown completed");
      return 0;

    default:
      assert(0);
  }

  return 1;
}

/* ================================================== */

static void
read_write_socket(int fd, int event, void *arg)
{
  NKSN_Instance inst = arg;

  if (!handle_event(inst, event))
    return;

  reset_message_parsing(&inst->message);

  if (!(inst->handler)(inst->handler_arg)) {
    stop_session(inst);
    return;
  }
}

/* ================================================== */

static int gnutls_initialised = 0;

static void
init_gnutls(void)
{
  int r;

  if (gnutls_initialised)
    return;

  r = gnutls_global_init();
  if (r < 0)
    LOG_FATAL("Could not initialise %s : %s", "gnutls", gnutls_strerror(r));

  /* NTS specification requires TLS1.2 or later */
  r = gnutls_priority_init2(&priority_cache, "-VERS-SSL3.0:-VERS-TLS1.0:-VERS-TLS1.1",
                            NULL, GNUTLS_PRIORITY_INIT_DEF_APPEND);
  if (r < 0)
    LOG_FATAL("Could not initialise %s : %s", "priority cache", gnutls_strerror(r));

  gnutls_initialised = 1;
}

/* ================================================== */

static void
deinit_gnutls(void)
{
  assert(gnutls_initialised);

  gnutls_priority_deinit(priority_cache);
  gnutls_global_deinit();
  gnutls_initialised = 0;
}

/* ================================================== */

void *
NKSN_CreateCertCredentials(char *cert, char *key, char *trusted_certs)
{
  gnutls_certificate_credentials_t credentials = NULL;
  int r;

  init_gnutls();

  r = gnutls_certificate_allocate_credentials(&credentials);
  if (r < 0)
    goto error;

  if (cert && key) {
    r = gnutls_certificate_set_x509_key_file(credentials, cert, key,
                                             GNUTLS_X509_FMT_PEM);
    if (r < 0)
      goto error;
  } else {
    if (!CNF_GetNoSystemCert()) {
      r = gnutls_certificate_set_x509_system_trust(credentials);
      if (r < 0)
        goto error;
    }

    if (trusted_certs) {
      r = gnutls_certificate_set_x509_trust_file(credentials, trusted_certs,
                                                 GNUTLS_X509_FMT_PEM);
      if (r < 0)
        goto error;
    }
  }

  credentials_counter++;

  return credentials;

error:
  LOG(LOGS_ERR, "Could not set credentials : %s", gnutls_strerror(r));
  if (credentials)
    gnutls_certificate_free_credentials(credentials);
  return NULL;
}

/* ================================================== */

void
NKSN_DestroyCertCredentials(void *credentials)
{
  gnutls_certificate_free_credentials(credentials);
  credentials_counter--;
  if (credentials_counter != 0)
    return;

  deinit_gnutls();
}

/* ================================================== */

NKSN_Instance
NKSN_CreateInstance(int server_mode, const char *name,
                    NKSN_MessageHandler handler, void *handler_arg)
{
  NKSN_Instance inst;

  inst = MallocNew(struct NKSN_Instance_Record);

  inst->server = server_mode;
  inst->name = Strdup(name);
  inst->handler = handler;
  inst->handler_arg = handler_arg;
  /* Replace NULL arg with the session itself */
  if (!inst->handler_arg)
    inst->handler_arg = inst;

  inst->state = KE_STOPPED;
  inst->sock_fd = INVALID_SOCK_FD;
  inst->tls_session = NULL;
  inst->timeout_id = 0;

  return inst;
}

/* ================================================== */

void
NKSN_DestroyInstance(NKSN_Instance inst)
{
  stop_session(inst);

  Free(inst->name);
  Free(inst);
}

/* ================================================== */

int
NKSN_StartSession(NKSN_Instance inst, int sock_fd, void *credentials, double timeout)
{
  assert(inst->state == KE_STOPPED);

  inst->tls_session = create_tls_session(inst->server, sock_fd,
                                         inst->server ? NULL : inst->name,
                                         credentials, priority_cache);
  if (!inst->tls_session)
    return 0;

  inst->sock_fd = sock_fd;
  SCH_AddFileHandler(sock_fd, SCH_FILE_INPUT, read_write_socket, inst);

  inst->timeout_id = SCH_AddTimeoutByDelay(timeout, session_timeout, inst);

  reset_message(&inst->message);
  inst->new_message = 0;
  inst->ended_message = 0;

  change_state(inst, inst->server ? KE_HANDSHAKE : KE_WAIT_CONNECT);

  return 1;
}

/* ================================================== */

void
NKSN_BeginMessage(NKSN_Instance inst)
{
  reset_message(&inst->message);
  inst->new_message = 1;
}

/* ================================================== */

int
NKSN_AddRecord(NKSN_Instance inst, int critical, int type, const void *body, int body_length)
{
  assert(inst->new_message && !inst->message.complete);
  assert(type != NKE_RECORD_END_OF_MESSAGE);

  return add_record(&inst->message, critical, type, body, body_length);
}

/* ================================================== */

int
NKSN_EndMessage(NKSN_Instance inst)
{
  assert(!inst->message.complete);

  if (!add_record(&inst->message, 1, NKE_RECORD_END_OF_MESSAGE, NULL, 0))
    return 0;

  inst->message.complete = 1;

  return 1;
}

/* ================================================== */

int
NKSN_GetRecord(NKSN_Instance inst, int *critical, int *type, int *body_length,
               void *body, int buffer_length)
{
  int type2;

  assert(inst->message.complete);

  if (!get_record(&inst->message, critical, &type2, body_length, body, buffer_length))
    return 0;

  if (type2 == NKE_RECORD_END_OF_MESSAGE)
    return 0;

  if (type)
    *type = type2;

  return 1;
}

/* ================================================== */

int
NKSN_GetKeys(NKSN_Instance inst, SIV_Algorithm siv, NKE_Key *c2s, NKE_Key *s2c)
{
  c2s->length = SIV_GetKeyLength(siv);
  s2c->length = SIV_GetKeyLength(siv);
  assert(c2s->length <= sizeof (c2s->key));
  assert(s2c->length <= sizeof (s2c->key));

  if (gnutls_prf_rfc5705(inst->tls_session,
                         sizeof (NKE_EXPORTER_LABEL) - 1, NKE_EXPORTER_LABEL,
                         sizeof (NKE_EXPORTER_CONTEXT_C2S) - 1, NKE_EXPORTER_CONTEXT_C2S,
                         c2s->length, (char *)c2s->key) < 0)
    return 0;
  if (gnutls_prf_rfc5705(inst->tls_session,
                         sizeof (NKE_EXPORTER_LABEL) - 1, NKE_EXPORTER_LABEL,
                         sizeof (NKE_EXPORTER_CONTEXT_S2C) - 1, NKE_EXPORTER_CONTEXT_S2C,
                         s2c->length, (char *)s2c->key) < 0)
    return 0;

  return 1;
}

/* ================================================== */

int
NKSN_IsStopped(NKSN_Instance inst)
{
  return inst->state == KE_STOPPED;
}

/* ================================================== */

void
NKSN_StopSession(NKSN_Instance inst)
{
  stop_session(inst);
}
