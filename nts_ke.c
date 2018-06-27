/*
  chronyd/chronyc - Programs for keeping computer clocks accurate.

 **********************************************************************
 * Copyright (C) Miroslav Lichvar  2018
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

  Implementation of the NTS Key Establishment protocol
  */

#include "config.h"

#include "sysincl.h"

#include "nts_ke.h"

#include "logging.h"
#include "memory.h"
#include "sched.h"
#include "util.h"

#include <gnutls/gnutls.h>

#define ALPN_NAME "ntske/1"
#define EXPORTER_LABEL "EXPORTER-network-time-security/1"
#define EXPORTER_CONTEXT_C2S "\x0\x0\x0\xf\x0"
#define EXPORTER_CONTEXT_S2C "\x0\x0\x0\xf\x1"

#define MAX_MESSAGE_LENGTH 16384

#define INVALID_SOCK_FD -4

/* TODO: make configurable */
#define CA_CERT "nts/ca.crt"
#define SERVER_CERT "nts/server.crt"
#define SERVER_KEY "nts/server.key"

#define SERVER_ADDRESS "127.0.0.1"
#define SERVER_PORT 11443
#define SERVER_NAME "localhost"

#define SERVER_BIND_ADDRESS "0.0.0.0"

struct RecordHeader {
  uint16_t type;
  uint16_t body_length;
};

typedef enum {
  KE_UNKNOWN,
  KE_SERVER,
  KE_CLIENT
} NtsKeMode;

typedef enum {
  KE_WAIT_CONNECT,
  KE_HANDSHAKE,
  KE_SEND,
  KE_RECEIVE,
  KE_SHUTDOWN,
  KE_CLOSED,
} NtsKeState;

struct NKE_Message {
  int length;
  int sent;
  int eof;
  int parsed;
  unsigned char data[MAX_MESSAGE_LENGTH];
};

typedef enum {
  MSG_INCOMPLETE,
  MSG_ERROR,
  MSG_OK,
} NtsKeMsgFormat;

struct NKE_Instance_Record {
  NtsKeMode mode;
  NtsKeState state;
  int sock_fd;
  gnutls_session_t session;
  SCH_TimeoutID timeout;
  struct NKE_Message message;
};

static int server_sock_fd4;
static int server_sock_fd6;

static void update_state(NKE_Instance inst);
static void read_write_socket(int fd, int event, void *arg);
static int accept_server_connection(NKE_Instance inst, int sock_fd);

static int
prepare_socket(NtsKeMode mode, IPAddr *ip, int port)
{
  struct sockaddr_in sin;
  int sock_fd, optval = 1;

  if (!UTI_IPAndPortToSockaddr(ip, port, (struct sockaddr *)&sin))
    return INVALID_SOCK_FD;

  if ((sock_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    return INVALID_SOCK_FD;

  if (fcntl(sock_fd, F_SETFL, O_NONBLOCK)) {
    DEBUG_LOG("Could not set O_NONBLOCK : %s", strerror(errno));
    close(sock_fd);
    return INVALID_SOCK_FD;
  }

  switch (mode) {
    case KE_SERVER:
      if (setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof (optval)) < 0) {
        DEBUG_LOG("setsockopt(SO_REUSEADDR) failed : %s", strerror(errno));
        close(sock_fd);
        return INVALID_SOCK_FD;
      }

      if (bind(sock_fd, &sin, sizeof (sin)) < 0) {
        DEBUG_LOG("bind() failed : %s", strerror(errno));
        close(sock_fd);
        return INVALID_SOCK_FD;
      }

      if (listen(sock_fd, 10) < 0) {
        DEBUG_LOG("listen() failed : %s", strerror(errno));
        close(sock_fd);
        return INVALID_SOCK_FD;
      }
      break;
    case KE_CLIENT:
      if (connect(sock_fd, &sin, sizeof (sin)) < 0 && errno != EINPROGRESS) {
        DEBUG_LOG("connect() failed : %s", strerror(errno));
        close(sock_fd);
        return INVALID_SOCK_FD;
      }
      break;
    default:
      assert(0);
  }

  UTI_FdSetCloexec(sock_fd);

  return sock_fd;
}

static gnutls_session_t
create_session(NtsKeMode mode, int sock_fd)
{
  gnutls_certificate_credentials_t xcred;
  gnutls_session_t session;
  gnutls_datum_t alpn;

  if (gnutls_certificate_allocate_credentials(&xcred) < 0)
    return NULL;

  if (gnutls_certificate_set_x509_system_trust(xcred) < 0)
    return NULL;


  if (mode == KE_SERVER) {
    if (gnutls_certificate_set_x509_trust_file(xcred, CA_CERT, GNUTLS_X509_FMT_PEM) < 0)
      return NULL;

    if (gnutls_certificate_set_x509_key_file(xcred, SERVER_CERT, SERVER_KEY,
                                             GNUTLS_X509_FMT_PEM) < 0)
      return NULL;
  }

  if (gnutls_init(&session, GNUTLS_NONBLOCK |
                  (mode == KE_SERVER ? GNUTLS_SERVER : GNUTLS_CLIENT)) < 0)
    return NULL;

  if (mode == KE_CLIENT) {
#if 0
    if (gnutls_server_name_set(session, GNUTLS_NAME_DNS, SERVER_NAME, strlen(SERVER_NAME)) < 0)
      return NULL;
    gnutls_session_set_verify_cert(session, SERVER_NAME, 0);
#endif
  }

  if (gnutls_set_default_priority(session) < 0)
    return NULL;

  if (gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, xcred) < 0)
    return NULL;

  //TODO: disable TLS < 1.2, disable RC4!

  alpn.data = (unsigned char *)ALPN_NAME; //TODO: is this safe?
  alpn.size = sizeof (ALPN_NAME) - 1;

  if (gnutls_alpn_set_protocols(session, &alpn, 1, 0) < 0)
    return NULL;

  gnutls_transport_set_int(session, sock_fd);

  return session;
}

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

static int
check_alpn(gnutls_session_t session)
{
  gnutls_datum_t alpn;

  alpn.data = (unsigned char *)ALPN_NAME; //TODO: is this safe?
  alpn.size = sizeof (ALPN_NAME) - 1;

  if (gnutls_alpn_get_selected_protocol(session, &alpn) < 0)
    return 0;

  if (alpn.size != sizeof (ALPN_NAME) - 1 ||
      strncmp((const char *)alpn.data, ALPN_NAME, sizeof (ALPN_NAME) - 1)) {
    DEBUG_LOG("ALPN mismatch");
    return 0;
  }

  return 1;
}

static NKE_Instance inst_server;

static void
accept_connection(int server_fd, int event, void *arg)
{
  NKE_Instance inst;
  int sock_fd;

  sock_fd = accept(server_fd, NULL, NULL);
  if (sock_fd < 0) {
    DEBUG_LOG("accept() failed : %s", strerror(errno));
    return;
  }

  //TODO: reuse code, merge with CLOEXEC?
  if (fcntl(sock_fd, F_SETFL, O_NONBLOCK)) {
    DEBUG_LOG("Could not set O_NONBLOCK : %s", strerror(errno));
    close(sock_fd);
    return;
  }

  UTI_FdSetCloexec(sock_fd);

  inst = NKE_CreateInstance();

  if (!accept_server_connection(inst, sock_fd)) {
    NKE_DestroyInstance(inst);
    close(sock_fd);
    return;
  }

  DEBUG_LOG("Accepted connection");

  /* TODO: save inst */
  inst_server = inst;
}

static void
close_connection(NKE_Instance inst)
{
  if (inst->state == KE_CLOSED)
    return;

  //SCH_RemoveTimeout(inst->timeout);

  gnutls_deinit(inst->session);

  if (inst->sock_fd != INVALID_SOCK_FD) {
    SCH_RemoveFileHandler(inst->sock_fd);
    close(inst->sock_fd);
    inst->sock_fd = INVALID_SOCK_FD;
  }

  inst->state = KE_CLOSED;
}

static void
reset_message(struct NKE_Message *message)
{
  message->length = 0;
  message->sent = 0;
  message->eof = 0;
  message->parsed = 0;
}

static NtsKeMsgFormat
check_message_format(struct NKE_Message *message)
{
  return MSG_OK;
}

static int
prepare_request(NKE_Instance inst)
{
  reset_message(&inst->message);

  memset(inst->message.data, 0, sizeof (inst->message.data));
  inst->message.length = sizeof (inst->message.data);

  return 1;
}

static int
prepare_response(NKE_Instance inst)
{
  reset_message(&inst->message);

  memset(inst->message.data, 0, sizeof (inst->message.data));
  inst->message.length = sizeof (inst->message.data);

  return 1;
}

static int
process_request(NKE_Instance inst)
{
  prepare_response(inst);

  return 1;
}

static int
process_response(NKE_Instance inst)
{
  return 1;
}

static void
update_state(NKE_Instance inst)
{
  NtsKeState next_state;
  int enable_output;

  switch (inst->mode) {
    case KE_SERVER:
      switch (inst->state) {
        case KE_WAIT_CONNECT:
          enable_output = 0;
          next_state = KE_HANDSHAKE;
          break;
        case KE_HANDSHAKE:
          if (!check_alpn(inst->session)) {
            close_connection(inst);
            return;
          }
          enable_output = 0;
          next_state = KE_RECEIVE;
          break;
        case KE_RECEIVE:
          switch (check_message_format(&inst->message)) {
            case MSG_INCOMPLETE:
              /* Wait for more data */
              return;
            case MSG_OK:
              if (process_request(inst))
                break;
              /* Fall through */
            default:
              close_connection(inst);
              return;
          }
          enable_output = 1;
          next_state = KE_SEND;
          break;
        case KE_SEND:
          enable_output = 1;
          next_state = KE_SHUTDOWN;
          break;
        case KE_SHUTDOWN:
          close_connection(inst);
          return;
        default:
          assert(0);
      }
      break;

    case KE_CLIENT:
      switch (inst->state) {
        case KE_WAIT_CONNECT:
          enable_output = 1;
          next_state = KE_HANDSHAKE;
          break;
        case KE_HANDSHAKE:
          if (!check_alpn(inst->session)) {
            close_connection(inst);
            return;
          }
          if (!prepare_request(inst)) {
            close_connection(inst);
            return;
          }
          enable_output = 1;
          next_state = KE_SEND;
          break;
        case KE_SEND:
          reset_message(&inst->message);
          enable_output = 0;
          next_state = KE_RECEIVE;
          break;
        case KE_RECEIVE:
          switch (check_message_format(&inst->message)) {
            case MSG_INCOMPLETE:
              /* Wait for more data */
              return;
            case MSG_OK:
              /* TODO: Should this be in NKE_GetCookies() ? */
              if (process_response(inst))
                break;
              /* Fall through */
            default:
              close_connection(inst);
              return;
          }
          enable_output = 1;
          next_state = KE_SHUTDOWN;
          break;
        case KE_SHUTDOWN:
          close_connection(inst);
          return;
        default:
          assert(0);
      }
      break;

    default:
      assert(0);
  }

  inst->state = next_state;
  SCH_SetFileHandlerEvent(inst->sock_fd, SCH_FILE_OUTPUT, enable_output);
}

static void
read_write_socket(int fd, int event, void *arg)
{
  NKE_Instance inst = arg;
  int r;

  DEBUG_LOG("Handling event %d on fd %d in state %u", event, fd, inst->state);

  switch (inst->state) {
    case KE_WAIT_CONNECT:
      /* Check if connect() succeeded */
      if (event != SCH_FILE_OUTPUT)
        return;

      r = get_socket_error(inst->sock_fd);

      if (r) {
        DEBUG_LOG("connect() failed : %s", strerror(r));
        close_connection(inst);
        return;
      }

      DEBUG_LOG("Connected");
      break;

    case KE_HANDSHAKE:
      r = gnutls_handshake(inst->session);

      if (r < 0) {
        DEBUG_LOG("gnutls_handshake() failed : %s", gnutls_strerror(r));
        if (gnutls_error_is_fatal(r)) {
          close_connection(inst);
          return;
        }

        /* Disable output when the handshake is trying to receive data */
        SCH_SetFileHandlerEvent(inst->sock_fd, SCH_FILE_OUTPUT,
                                gnutls_record_get_direction(inst->session));
        return;
      }

      DEBUG_LOG("Handshake completed");

      break;

    case KE_SEND:
      r = gnutls_record_send(inst->session, &inst->message.data[inst->message.sent],
                             inst->message.length - inst->message.sent);

      if (r < 0) {
        DEBUG_LOG("gnutls_record_send() failed : %s", gnutls_strerror(r));
        if (gnutls_error_is_fatal(r))
          close_connection(inst);
        return;
      }

      DEBUG_LOG("Sent %d bytes", r);

      inst->message.sent += r;
      if (inst->message.sent < inst->message.length)
        return;

      break;

    case KE_RECEIVE:
      /* TODO: handle/disable RENEGOTIATION? */
      do {
        if (inst->message.length >= sizeof (inst->message.data)) {
          DEBUG_LOG("Message is too long");
          close_connection(inst);
          return;
        }

        r = gnutls_record_recv(inst->session, &inst->message.data[inst->message.length],
                               sizeof (inst->message.data) - inst->message.length);

        if (r < 0) {
          DEBUG_LOG("gnutls_record_recv() failed : %s", gnutls_strerror(r));
          if (gnutls_error_is_fatal(r))
            close_connection(inst);
          return;
        } else if (r == 0) {
          inst->message.eof = 1;
        }

        DEBUG_LOG("Received %d bytes", r);

        inst->message.length += r;

      } while (gnutls_record_check_pending(inst->session) > 0);

      break;

    case KE_SHUTDOWN:
      r = gnutls_bye(inst->session, GNUTLS_SHUT_RDWR);

      if (r < 0) {
        DEBUG_LOG("gnutls_bye() failed : %s", gnutls_strerror(r));
        if (gnutls_error_is_fatal(r)) {
          close_connection(inst);
          return;
        }

        /* Disable output when the TLS shutdown is trying to receive data */
        SCH_SetFileHandlerEvent(inst->sock_fd, SCH_FILE_OUTPUT,
                                gnutls_record_get_direction(inst->session));
        return;
      }

      if (shutdown(inst->sock_fd, SHUT_RDWR) < 0)
        DEBUG_LOG("shutdown() failed : %s", strerror(errno));

      DEBUG_LOG("Shutdown completed");

      break;

    default:
      assert(0);
  }

  update_state(inst);
}

void
NKE_Initialise(void)
{
  /* Must be called after closing unknown file descriptors */
  gnutls_global_init();

  server_sock_fd4 = INVALID_SOCK_FD;
  server_sock_fd6 = INVALID_SOCK_FD;

  IPAddr ip;
  if (!UTI_StringToIP(SERVER_BIND_ADDRESS, &ip))
    return;

#if 1
  server_sock_fd4 = prepare_socket(KE_SERVER, &ip, SERVER_PORT);
  if (server_sock_fd4 != INVALID_SOCK_FD)
    SCH_AddFileHandler(server_sock_fd4, SCH_FILE_INPUT, accept_connection, NULL);
#endif
}

void
NKE_Finalise(void)
{
}

NKE_Instance
NKE_CreateInstance(void)
{
  NKE_Instance inst;

  inst = MallocNew(struct NKE_Instance_Record);

  inst->mode = KE_UNKNOWN;
  inst->state = KE_CLOSED;
  inst->sock_fd = INVALID_SOCK_FD;
  inst->session = NULL;
  reset_message(&inst->message);

  return inst;
}

static int
accept_server_connection(NKE_Instance inst, int sock_fd)
{
  gnutls_session_t session;

  assert(inst->mode == KE_UNKNOWN);

  session = create_session(KE_SERVER, sock_fd);
  if (!session)
    return 0;

  inst->mode = KE_SERVER;
  inst->state = KE_HANDSHAKE;
  inst->sock_fd = sock_fd;
  inst->session = session;

  SCH_AddFileHandler(inst->sock_fd, SCH_FILE_INPUT, read_write_socket, inst);

  return 1;
}

int
NKE_OpenClientConnection(NKE_Instance inst, IPAddr *addr, int port, const char *name)
{
  int sock_fd;

  assert(inst->mode == KE_UNKNOWN);

  sock_fd = prepare_socket(KE_CLIENT, addr, port);
  if (sock_fd == INVALID_SOCK_FD)
    return 0;

  inst->session = create_session(KE_CLIENT, sock_fd);
  if (!inst->session) {
    close(sock_fd);
    return 0;
  }

  inst->mode = KE_CLIENT;
  inst->state = KE_WAIT_CONNECT;
  inst->sock_fd = sock_fd;

  SCH_AddFileHandler(sock_fd, SCH_FILE_INPUT | SCH_FILE_OUTPUT, read_write_socket, inst);

  return 1;
}

int
NKE_GetKeysAndCookies(NKE_Instance inst, NKE_Key *c2s, NKE_Key *s2c,
                      NKE_Cookie *cookies, int max_cookies)
{
  if (gnutls_prf_rfc5705(inst->session, sizeof (EXPORTER_LABEL) - 1, EXPORTER_LABEL,
                         sizeof (EXPORTER_CONTEXT_C2S) - 1, EXPORTER_CONTEXT_C2S,
                         sizeof (c2s->key), c2s->key) < 0)
    return 0;
  if (gnutls_prf_rfc5705(inst->session, sizeof (EXPORTER_LABEL) - 1, EXPORTER_LABEL,
                         sizeof (EXPORTER_CONTEXT_S2C) - 1, EXPORTER_CONTEXT_S2C,
                         sizeof (s2c->key), s2c->key) < 0)
    return 0;

  c2s->length = sizeof (c2s->key);
  s2c->length = sizeof (s2c->key);

  return 0;
}

void NKE_Disconnect(NKE_Instance inst)
{
  close_connection(inst);
}

void
NKE_DestroyInstance(NKE_Instance inst)
{
  close_connection(inst);

  Free(inst);
}

static NKE_Instance inst1;

void
NKE_test(void)
{

  IPAddr ip;

  NKE_Initialise();

  if (!UTI_StringToIP(SERVER_ADDRESS, &ip))
    return;

  inst1 = NKE_CreateInstance();
  NKE_OpenClientConnection(inst1, &ip, SERVER_PORT, "");

  /*
  NKE_DestroyInstance(inst1);

  NKE_Finalise();
  */
}
