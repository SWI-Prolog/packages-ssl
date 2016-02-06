/*  Part of SWI-Prolog

    Author:        Jan van der Steen and Jan Wielemaker
    E-mail:        J.van.der.Steen@diff.nl and jan@swi.psy.uva.nl
    WWW:           http://www.swi-prolog.org
    Copyright (c)  2004-2011, SWI-Prolog Foundation
    All rights reserved.

    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions
    are met:

    1. Redistributions of source code must retain the above copyright
       notice, this list of conditions and the following disclaimer.

    2. Redistributions in binary form must reproduce the above copyright
       notice, this list of conditions and the following disclaimer in
       the documentation and/or other materials provided with the
       distribution.

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
    "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
    LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
    FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
    COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
    INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
    BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
    LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
    CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
    LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
    ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
    POSSIBILITY OF SUCH DAMAGE.
*/

/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
 * Purpose:     SSL utilities used by the PL-SSL library
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */

#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#if defined (__STDC__)
#include <stdarg.h>
#else
#include <varargs.h>
#endif

#include "ssllib.h"
#include "util.h"

char *
util_cb_pem_passwd(PL_SSL *config, char *buf, int size)
/*
 * Example of a pem_passwd callback function.
 *
 * We fill the supplied buffer with the certificate password.
 * Return NULL if we fail for some reason.
 */
{
    char *passwd = NULL;
    int   len    = 0;

    ssl_deb("pem_passwd() handler called\n");

    if ((passwd = config->pl_ssl_password) != NULL) {
        if ((len = strlen(passwd)) < size) {
            ssl_msg("util_cb_pem_passwd: returned password\n");
            return strcpy(buf, passwd);
        }
    }
    return NULL;
}

BOOL
util_cb_cert_verify( PL_SSL *config
                   , const char *certificate
                   , long n
                   , const char *error
                   )
/*
 * Example of a cert_verify callback function.
 *
 * We're called since something is wrong with the certificate
 * passed to us by the peer. It's up to us how to deal with
 * such an event.
 *
 * return TRUE  if you want to proceed anyway
 * return FALSE to request immediate exit
 */
{
    ssl_deb("cert_verify() handler called\n");

    ssl_msg("util_cb_cert_verify: verification error: '%s'\n", error);
    ssl_msg("util_cb_cert_verify: %s", certificate);
    ssl_msg("util_cb_cert_verify: we accept it anyway\n");

    return TRUE;
}

int
util_run_server(PL_SSL_INSTANCE *instance)
/*
 * Handle a message from the client
 */
{
    char buf[4096];
    int rbytes = 0;
    int wbytes = 0;
    const char *ack = "yes, I hear you...";

    if ((rbytes = ssl_read(instance, buf, sizeof(buf)-1)) < 0) {
        ssl_deb("ssl_read failed\n");
        return -1;
    }
    buf[rbytes] = '\0';
    ssl_msg("Got %d chars:'%s'\n", rbytes, buf);

    if ((wbytes = ssl_write(instance, ack, strlen(ack))) < 0) {
        ssl_deb("ssl_write failed\n");
        return -1;
    }

    ssl_deb("util_run_server ran successfully\n");

    return 0;
}

int
util_run_client(PL_SSL_INSTANCE *instance)
/*
 * Send a message to the server.
 */
{
    char buf[4096];
    int rbytes = 0;
    int wbytes = 0;

    sprintf(buf, "Hello");
    if ((wbytes = ssl_write(instance, buf, strlen(buf))) < 0) {
        ssl_deb("ssl_write failed\n");
        return -1;
    }

    if ((rbytes = ssl_read(instance, buf, sizeof(buf)-1)) < 0) {
        ssl_deb("ssl_read failed\n");
        return -1;
    }
    buf[rbytes] = '\0';
    ssl_msg("Got %d chars:'%s'\n", rbytes, buf);

    ssl_deb("util_run_client ran successfully\n");

    return 0;
}

static void
util_run_server_test(PL_SSL_INSTANCE *instance)
/*
 * Respond to messages from our peer.
 */
{
    char buf[4096];
    int rbytes = 0;
    int wbytes = 0;

    do {
        const char *ack = "yes, I hear you...";

        if ((rbytes = ssl_read(instance, buf, sizeof(buf)-1)) < 0) {
            ssl_deb("ssl_read failed\n");
            exit(EXIT_FAILURE);
        }
        buf[rbytes] = '\0';
        ssl_msg("Got %d chars:'%s'\n", rbytes, buf);

        if ((wbytes = ssl_write(instance, ack, strlen(ack))) < 0) {
            ssl_deb("ssl_write failed\n");
            exit(EXIT_FAILURE);
        }
    } while (rbytes > 0 && wbytes > 0);
}

static void
util_run_client_test(PL_SSL_INSTANCE *instance)
/*
 * Send some messages to our peer.
 */
{
    char buf[4096];
    int rbytes = 0;
    int wbytes = 0;
    int n;

    for (n = 0; n < 10; n++) {
        sprintf(buf, "Hello %02d\n", n+1);
        if ((wbytes = ssl_write(instance, buf, strlen(buf))) < 0) {
            ssl_deb("ssl_write failed\n");
            exit(EXIT_FAILURE);
        }
        if ((rbytes = ssl_read(instance, buf, sizeof(buf)-1)) < 0) {
            ssl_deb("ssl_read failed\n");
            exit(EXIT_FAILURE);
        }
        buf[rbytes] = '\0';
        ssl_msg("Got %d chars:'%s'", rbytes, buf);
    }
}

void
util_run_test(PL_SSL_INSTANCE *instance)
/*
 * Run a test depending on whether we're server or client
 */
{
    switch (instance->config->pl_ssl_role) {
        case PL_SSL_SERVER:
            util_run_server_test(instance);
            break;
        case PL_SSL_NONE:
        case PL_SSL_CLIENT:
            util_run_client_test(instance);
            break;
    }
    ssl_deb("SSL socket test finished\n");
}
