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
#include "util.h"

#include <gnutls/gnutls.h>

#define ALPN_NAME "ntske/1"
#define EXPORT_LABEL "EXPORTER-network-time-security/1"
#define EXPORT_CONTEXT_C2S "\x0\x0\x0\xf\x0"
#define EXPORT_CONTEXT_S2C "\x0\x0\x0\xf\x1"

static int
get_client_socket(void)
{
  struct sockaddr_in sin;
  IPAddr ip;
  int sock_fd;

  if (!UTI_StringToIP("127.0.0.1", &ip))
    return -1;

  if (!UTI_IPAndPortToSockaddr(&ip, 11443, (struct sockaddr *)&sin))
    return -1;

  if ((sock_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    return -1;

  if (connect(sock_fd, &sin, sizeof (sin)) < 0) {
    close(sock_fd);
    return -1;
  }

  return sock_fd;
}

static int
test_client(void)
{
  gnutls_session_t session;
  gnutls_certificate_credentials_t xcred;
  int sock_fd;

  if (gnutls_certificate_allocate_credentials(&xcred) < 0)
    return 0;

  if (gnutls_certificate_set_x509_system_trust(xcred) < 0)
    return 0;

  if ((sock_fd = get_client_socket()) < 0)
    return 0;

  if (gnutls_init(&session, GNUTLS_CLIENT /* | GNUTLS_NONBLOCK */) < 0)
    return 0;

  if (gnutls_server_name_set(session, GNUTLS_NAME_DNS, "localhost", strlen("localhost")) < 0)
    return 0;

  if (gnutls_set_default_priority(session) < 0)
    return 0;

  if (gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, xcred) < 0)
    return 0;

  //if (gnutls_session_set_verify_cert(session, "my_host_name", 0);

  //TODO: disable TLS < 1.2, disable RC4!

  gnutls_datum_t alpn;
  alpn.data = (unsigned char *)ALPN_NAME; //TODO: is this safe?
  alpn.size = sizeof (ALPN_NAME) - 1;

  if (gnutls_alpn_set_protocols(session, &alpn, 1, 0) < 0)
    return 0;

  gnutls_transport_set_int(session, sock_fd);
  int r;

  while ((r = gnutls_handshake(session)) < 0) {
    DEBUG_LOG("handshake: %s", gnutls_strerror(r));
    if (gnutls_error_is_fatal(r)) {
      DEBUG_LOG("fatal");
      return 0;
    }
  }

  if (gnutls_alpn_get_selected_protocol(session, &alpn) < 0)
    return 0;

  if (alpn.size != sizeof (ALPN_NAME) - 1 ||
      strncmp((const char *)alpn.data, ALPN_NAME, sizeof (ALPN_NAME) - 1))
    return 0;

  char c2s[32], s2c[32];
  if (gnutls_prf_rfc5705(session, sizeof (EXPORT_LABEL) - 1, EXPORT_LABEL,
                         sizeof (EXPORT_CONTEXT_C2S) - 1, EXPORT_CONTEXT_C2S,
                         sizeof (c2s), c2s) < 0)
    return 0;
  if (gnutls_prf_rfc5705(session, sizeof (EXPORT_LABEL) - 1, EXPORT_LABEL,
                         sizeof (EXPORT_CONTEXT_S2C) - 1, EXPORT_CONTEXT_S2C,
                         sizeof (s2c), s2c) < 0)
    return 0;

#if 0
  CHECK(gnutls_record_send(session, MSG, strlen(MSG)));

  r = gnutls_record_recv(session, buffer, MAX_BUF);

#endif

  if (gnutls_bye(session, GNUTLS_SHUT_RDWR) < 0)
    return 0;

  close(sock_fd);
  gnutls_deinit(session);

  return 1;
}

void
NKE_test(void)
{
  /* Must be closed after closing unknown file descriptors */
  gnutls_global_init();

  test_client();
}
