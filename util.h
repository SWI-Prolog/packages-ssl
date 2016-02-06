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

#ifndef UTILH__
#define UTILH__

#include <openssl/ssl.h>
#include <openssl/x509.h>

#if 0
#define TEST_HOST "10.0.2.100"  /* james */
#define TEST_HOST "10.0.2.18"   /* shuwa */
#endif
#define TEST_HOST "127.0.0.1"   /* localhost */
#define TEST_PORT 1111

/*
 * Location of server and client certificates, key's and authority
 */
#define HOME            "./"
#define CACERT          HOME "etc/demoCA/cacert.pem"
#define SERVER_CERTF    HOME "etc/server/server-cert.pem"
#define SERVER_KEYF     HOME "etc/server/server-key.pem"
#define SERVER_PASSWD   "apenoot1"
#define CLIENT_CERTF    HOME "etc/client/client-sign.pem"
#define CLIENT_KEYF     HOME "etc/client/client-sign-key.pem"
#define CLIENT_PASSWD   "apenoot2"

char *          util_cb_pem_passwd   ( PL_SSL *config
                                     , char *buf
                                     , int size
                                     ) ;
BOOL            util_cb_cert_verify  ( PL_SSL *config
                                     , const char *certificate
                                     , long nbytes
                                     , const char *error
                                     ) ;

void            util_run_test        (PL_SSL_INSTANCE *instance);
int             util_run_server      (PL_SSL_INSTANCE *instance);
int             util_run_client      (PL_SSL_INSTANCE *instance);

#endif
