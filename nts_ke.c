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

#include "siv_cmac.h"

#include <gnutls/gnutls.h>

#define ALPN_NAME "ntske/1"
#define EXPORTER_LABEL "EXPORTER-network-time-security/1"
#define EXPORTER_CONTEXT_C2S "\x0\x0\x0\xf\x0"
#define EXPORTER_CONTEXT_S2C "\x0\x0\x0\xf\x1"

#define RECORD_CRITICAL_BIT (1U << 15)
#define RECORD_END_OF_MESSAGE 0
#define RECORD_NEXT_PROTOCOL 1
#define RECORD_ERROR 2
#define RECORD_WARNING 3
#define RECORD_AEAD_ALGORITHM 4
#define RECORD_COOKIE 5
#define RECORD_NTPV4_SERVER_NEGOTIATION 6
#define RECORD_NTPV4_PORT_NEGOTIATION 7

#define ERROR_BAD_RESPONSE -2
#define ERROR_NONE -1
#define ERROR_UNRECOGNIZED_CRITICAL_RECORD 0
#define ERROR_BAD_REQUEST 1

#define NEXT_PROTOCOL_NONE -1
#define NEXT_PROTOCOL_NTPV4 0
#define AEAD_NONE -1
#define AEAD_AES_SIV_CMAC_256 15

#define MAX_MESSAGE_LENGTH 16384
#define MAX_RECORD_BODY_LENGTH 256
#define MAX_COOKIES 8

#define INVALID_SOCK_FD -4

/* TODO: make configurable */
#define CA_CERT "nts/ca.crt"
#define SERVER_CERT "nts/server.crt"
#define SERVER_KEY "nts/server.key"

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

typedef struct {
  uint32_t key_id;
  uint8_t nonce[16];
  uint8_t ciphertext[64 + 16];
} ServerCookie;

typedef struct {
  uint32_t id;
  struct siv_aes128_cmac_ctx siv;
} ServerKey;

#define MAX_SERVER_KEYS 4
ServerKey server_keys[MAX_SERVER_KEYS];
int current_server_key;

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

static int
add_record(struct NKE_Message *message, int critical, int type, void *body, int body_length)
{
  struct RecordHeader header;

  if (body_length < 0 || body_length > 0xffff ||
      message->length + sizeof (header) + body_length > sizeof (message->data))
    return 0;

  header.type = htons(!!critical * RECORD_CRITICAL_BIT | type);
  header.body_length = htons(body_length);

  memcpy(&message->data[message->length], &header, sizeof (header));
  message->length += sizeof (header);

  if (body_length > 0) {
    memcpy(&message->data[message->length], body, body_length);
    message->length += body_length;
  }

  return 1;
}

static void
reset_message_parsing(struct NKE_Message *message)
{
  message->parsed = 0;
}

static int
get_record(struct NKE_Message *message, int *critical, int *type, void *body, int *body_length)
{
  struct RecordHeader header;
  int blen, rlen;

  if (message->length < message->parsed + sizeof (header))
    return 0;

  memcpy(&header, &message->data[message->parsed], sizeof (header));

  blen = ntohs(header.body_length);
  rlen = sizeof (header) + blen;

  if (message->length < message->parsed + rlen)
    return 0;

  if (critical)
    *critical = !!(ntohs(header.type) & 0x8000);
  if (type)
    *type = ntohs(header.type) & 0x7fff;
  if (body)
    memcpy(body, &message->data[message->parsed + sizeof (header)], MIN(*body_length, blen));
  if (body_length)
    *body_length = blen;

  message->parsed += rlen;

  return 1;
}

static NtsKeMsgFormat
check_message_format(struct NKE_Message *message)
{
  int critical, type, length;

  reset_message_parsing(message);

  while (get_record(message, &critical, &type, NULL, &length))
    ;

  if (message->length == 0 || message->parsed < message->length)
    return message->eof ? MSG_ERROR : MSG_INCOMPLETE;

  if (!critical || type != RECORD_END_OF_MESSAGE || length != 0)
    return MSG_ERROR;

  return MSG_OK;
}

static int
prepare_request(NKE_Instance inst)
{
  uint16_t datum;

  reset_message(&inst->message);

  datum = htons(NEXT_PROTOCOL_NTPV4);
  if (!add_record(&inst->message, 1, RECORD_NEXT_PROTOCOL, &datum, sizeof (datum)))
    return 0;

  datum = htons(AEAD_AES_SIV_CMAC_256);
  if (!add_record(&inst->message, 1, RECORD_AEAD_ALGORITHM, &datum, sizeof (datum)))
    return 0;

  if (!add_record(&inst->message, 1, RECORD_END_OF_MESSAGE, NULL, 0))
    return 0;

  return 1;
}

static int
prepare_response(NKE_Instance inst, int error, int next_protocol, int aead_algorithm)
{
  NKE_Cookie cookie;
  NKE_Key c2s, s2c;
  uint16_t datum;
  int i;

  DEBUG_LOG("NTS KE response: error=%d next=%d aead=%d", error, next_protocol, aead_algorithm);

  reset_message(&inst->message);

  if (error != ERROR_NONE) {
    datum = htons(error);
    if (!add_record(&inst->message, 1, RECORD_ERROR, &datum, sizeof (datum)))
      return 0;
  } else {
    datum = htons(next_protocol);
    if (!add_record(&inst->message, 1, RECORD_NEXT_PROTOCOL, &datum, sizeof (datum)))
      return 0;

    datum = htons(aead_algorithm);
    if (!add_record(&inst->message, 1, RECORD_AEAD_ALGORITHM, &datum, sizeof (datum)))
      return 0;

    if (!NKE_GetKeys(inst, &c2s, &s2c))
      return 0;

    for (i = 0; i < MAX_COOKIES; i++) {
      if (!NKE_GenerateCookie(&c2s, &s2c, &cookie))
        return 0;
      if (!add_record(&inst->message, 0, RECORD_COOKIE, cookie.cookie, cookie.length))
        return 0;
    }
  }

  if (!add_record(&inst->message, 1, RECORD_END_OF_MESSAGE, NULL, 0))
    return 0;

  return 1;
}

static int
process_request(NKE_Instance inst)
{
  int next_protocol = NEXT_PROTOCOL_NONE, aead_algorithm = AEAD_NONE, error = ERROR_NONE;
  int has_next_protocol = 0, i, critical, type, length;
  uint16_t data[MAX_RECORD_BODY_LENGTH / 2];

  reset_message_parsing(&inst->message);

  while (error == ERROR_NONE) {
    length = sizeof (data);
    if (!get_record(&inst->message, &critical, &type, &data, &length))
      break;

    switch (type) {
      case RECORD_NEXT_PROTOCOL:
        if (!critical || length < 2 || length % 2 != 0) {
          error = ERROR_BAD_REQUEST;
          break;
        }
        for (i = 0; i < MIN(length, sizeof (data)) / 2; i++) {
          if (ntohs(data[i]) == NEXT_PROTOCOL_NTPV4)
            next_protocol = NEXT_PROTOCOL_NTPV4;
        }
        has_next_protocol = 1;
        break;
      case RECORD_AEAD_ALGORITHM:
        if (length < 2 || length % 2 != 0) {
          error = ERROR_BAD_REQUEST;
          break;
        }
        for (i = 0; i < MIN(length, sizeof (data)) / 2; i++) {
          if (ntohs(data[i]) == AEAD_AES_SIV_CMAC_256)
            aead_algorithm = AEAD_AES_SIV_CMAC_256;
        }
        break;
      case RECORD_ERROR:
      case RECORD_WARNING:
      case RECORD_COOKIE:
        error = ERROR_BAD_REQUEST;
        break;
      case RECORD_END_OF_MESSAGE:
        break;
      default:
        if (critical)
          error = ERROR_UNRECOGNIZED_CRITICAL_RECORD;
    }
  }

  if (!has_next_protocol)
    error = ERROR_BAD_REQUEST;

  prepare_response(inst, error, next_protocol, aead_algorithm);

  return 1;
}

static int
process_response(NKE_Instance inst, NKE_Cookie *cookies, int max_cookies)
{
  int next_protocol = NEXT_PROTOCOL_NONE, aead_algorithm = AEAD_NONE, error = ERROR_NONE;
  int num_cookies = 0, critical, type, length;
  uint16_t data[NKE_MAX_COOKIE_LENGTH / sizeof (uint16_t)];

  reset_message_parsing(&inst->message);

  while (error == ERROR_NONE) {
    length = sizeof (data);
    if (!get_record(&inst->message, &critical, &type, &data, &length))
      break;

    switch (type) {
      case RECORD_NEXT_PROTOCOL:
        if (!critical || length != 2 || ntohs(data[0]) != NEXT_PROTOCOL_NTPV4) {
          DEBUG_LOG("Unexpected NTS KE next protocol");
          error = ERROR_BAD_RESPONSE;
          break;
        }
        next_protocol = NEXT_PROTOCOL_NTPV4;
        break;
      case RECORD_AEAD_ALGORITHM:
        if (length != 2 || ntohs(data[0]) != AEAD_AES_SIV_CMAC_256) {
          DEBUG_LOG("Unexpected NTS KE AEAD algorithm");
          error = ERROR_BAD_RESPONSE;
        }
        aead_algorithm = AEAD_AES_SIV_CMAC_256;
        break;
      case RECORD_ERROR:
        if (length == 2)
          DEBUG_LOG("NTS KE error %d", ntohs(data[0]));
        error = ERROR_BAD_RESPONSE;
        break;
      case RECORD_WARNING:
        if (length == 2)
          DEBUG_LOG("NTS KE warning %d", ntohs(data[0]));
        error = ERROR_BAD_RESPONSE;
        break;
      case RECORD_COOKIE:
        DEBUG_LOG("NTS KE cookie length=%d", length);
        assert(NKE_MAX_COOKIE_LENGTH == sizeof (cookies[num_cookies].cookie));
        if (length <= NKE_MAX_COOKIE_LENGTH && num_cookies < max_cookies) {
          cookies[num_cookies].length = length;
          memcpy(cookies[num_cookies].cookie, data, length);
          num_cookies++;
        }
        break;
      case RECORD_END_OF_MESSAGE:
        break;
      case RECORD_NTPV4_SERVER_NEGOTIATION:
      case RECORD_NTPV4_PORT_NEGOTIATION:
        /* TODO */
      default:
        if (critical)
          error = 1;
    }
  }

  DEBUG_LOG("NTS KE response: error=%d next=%d aead=%d",
            error, next_protocol, aead_algorithm);

  if (next_protocol != NEXT_PROTOCOL_NTPV4 ||
      aead_algorithm != AEAD_AES_SIV_CMAC_256 ||
      error != ERROR_NONE)
    return 0;

  return num_cookies;
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
              break;
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

  uint8_t key[32];
  UTI_GetRandomBytesUrandom(key, sizeof (key));
  siv_aes128_cmac_set_key(&server_keys[0].siv, key);
  while (server_keys[0].id == 0)
    UTI_GetRandomBytes(&server_keys[0].id, sizeof (server_keys[0].id));
  current_server_key = 0;
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
NKE_GetCookies(NKE_Instance inst, NKE_Cookie *cookies, int max_cookies)
{
  if (inst->mode != KE_CLIENT && inst->state != KE_CLOSED)
    return 0;

  return process_response(inst, cookies, max_cookies);
}

int
NKE_GetKeys(NKE_Instance inst, NKE_Key *c2s, NKE_Key *s2c)
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

  return 1;
}

void NKE_Disconnect(NKE_Instance inst)
{
  close_connection(inst);
}

void
NKE_DestroyInstance(NKE_Instance inst)
{
  close_connection(inst);

  if (inst->mode != KE_UNKNOWN)
    gnutls_deinit(inst->session);

  Free(inst);
}

int
NKE_GenerateCookie(NKE_Key *c2s, NKE_Key *s2c, NKE_Cookie *nke_cookie)
{
  ServerCookie *cookie;
  ServerKey *key;
  uint8_t plaintext[64];

  key = &server_keys[current_server_key];

  assert(sizeof (nke_cookie->cookie) >= sizeof (cookie));

  nke_cookie->length = sizeof (*cookie);

  //TODO: alignment
  cookie = (ServerCookie *)nke_cookie->cookie;
  cookie->key_id = key->id;
  UTI_GetRandomBytes(cookie->nonce, sizeof (cookie->nonce));

  assert(c2s->length == 32);
  assert(s2c->length == 32);

  memcpy(plaintext, c2s->key, 32);
  memcpy(plaintext + 32, s2c->key, 32);

  assert(sizeof (cookie->ciphertext) == sizeof (plaintext) + SIV_DIGEST_SIZE);
  siv_aes128_cmac_encrypt_message(&key->siv, sizeof (cookie->nonce), cookie->nonce,
                                  0, NULL,
                                  SIV_DIGEST_SIZE, sizeof (plaintext),
                                  cookie->ciphertext, plaintext);

  return 1;
}

int
NKE_DecodeCookie(NKE_Cookie *nke_cookie, NKE_Key *c2s, NKE_Key *s2c)
{
  ServerCookie *cookie;
  ServerKey *key;
  struct {
    uint8_t c2s[32];
    uint8_t s2c[32];
  } plaintext;

  if (nke_cookie->length != sizeof (*cookie))
    return 0;

  //TODO: alignment
  cookie = (ServerCookie *)nke_cookie->cookie;

  key = &server_keys[current_server_key];
  if (cookie->key_id != key->id) {
    DEBUG_LOG("Unknown key ID");
    return 0;
  }

  assert(sizeof (plaintext) + SIV_DIGEST_SIZE == sizeof (cookie->ciphertext));
  if (!siv_aes128_cmac_decrypt_message(&key->siv, sizeof (cookie->nonce), cookie->nonce,
                                       0, NULL,
                                       SIV_DIGEST_SIZE, sizeof (cookie->ciphertext),
                                       (unsigned char *)&plaintext, cookie->ciphertext)) {
    DEBUG_LOG("SIV decrypt failed");
    return 0;
  }

  assert(sizeof (plaintext.c2s) <= sizeof (c2s->key));
  assert(sizeof (plaintext.s2c) <= sizeof (s2c->key));
  c2s->length = sizeof (plaintext.c2s);
  s2c->length = sizeof (plaintext.s2c);
  memcpy(c2s->key, plaintext.c2s, sizeof (plaintext.c2s));
  memcpy(s2c->key, plaintext.s2c, sizeof (plaintext.s2c));

  return 1;
}
