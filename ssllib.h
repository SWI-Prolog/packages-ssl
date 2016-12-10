/*  Part of SWI-Prolog

    Author:        Jan van der Steen and Jan Wielemaker
    E-mail:        J.van.der.Steen@diff.nl and jan@swi.psy.uva.nl
    WWW:           http://www.swi-prolog.org
    Copyright (c)  2004-2016, SWI-Prolog Foundation
                              VU University Amsterdam
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

#ifndef SSLLIBH__
#define SSLLIBH__
#include "../clib/nonblockio.h"

#define SSL_CONFIG_MAGIC 0x539dbe3a
#ifndef SYSTEM_CACERT_FILENAME
#define SYSTEM_CACERT_FILENAME "/etc/ssl/certs/ca-certificates.crt"
#endif

typedef int BOOL;
#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

typedef enum
{ PL_SSL_NONE
, PL_SSL_SERVER
, PL_SSL_CLIENT
} PL_SSL_ROLE;

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/dh.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/x509.h>

typedef struct X509_list
{ struct X509_list *next;
  X509 *cert;
} X509_list;

typedef struct X509_crl_list
{ struct X509_crl_list *next;
  X509_CRL *crl;
} X509_crl_list;

int list_add_X509_crl(X509_CRL *crl, X509_crl_list **head, X509_crl_list **tail);


typedef struct pl_ssl {
    long	        magic;
    /*
     * Are we server or client
     */
    PL_SSL_ROLE         pl_ssl_role;

    int			sock;		/* the listening/connected socket */
    int                 closeparent;
    atom_t              atom;
    BOOL                close_notify;

    /*
     * Context, Certificate, SSL info
     */
    SSL_CTX *           pl_ssl_ctx;
    int                 pl_ssl_idx;
    X509 *              pl_ssl_peer_cert;

    /*
     * In case of the client the host we're connecting to.
     */
    char *              pl_ssl_host;

    /*
     * Various parameters affecting the SSL layer
     */
    int                 use_system_cacert;
    char *              pl_ssl_cacert;
    char *              pl_ssl_certf;
    char *              pl_ssl_certificate;
    X509 *              pl_ssl_certificate_X509;
    char *              pl_ssl_keyf;
    char *              pl_ssl_key;
    char *              pl_ssl_cipher_list;
    char *              pl_ssl_ecdh_curve;
    X509_crl_list *     pl_ssl_crl_list;
    char *              pl_ssl_password;
    BOOL                pl_ssl_cert_required;
    BOOL                pl_ssl_crl_required;
    BOOL                pl_ssl_peer_cert_required;

    /*
     * Application defined handlers
     */
    BOOL                (*pl_ssl_cb_cert_verify)( struct pl_ssl *config
                                                , X509*
                                                , X509_STORE_CTX*
                                                , const char *error
                                                , int error_unknown
                                                ) ;
    void *              pl_ssl_cb_cert_verify_data;
    char *              (*pl_ssl_cb_pem_passwd) ( struct pl_ssl *
                                                , char *
                                                , int
                                                ) ;
    void *              pl_ssl_cb_pem_passwd_data;
    struct pl_ssl *     (*pl_ssl_cb_sni)(struct pl_ssl *, const char*);
    void *              pl_ssl_cb_sni_data;
#ifndef HAVE_X509_CHECK_HOST
    int                 hostname_check_status;
#endif
} PL_SSL;

typedef struct ssl_instance {
    PL_SSL              *config;
    SSL                 *ssl;
    nbio_sock_t          sock;
    IOSTREAM            *sread;		/* wire streams */
    IOSTREAM            *swrite;
    IOSTREAM		*dread;		/* data streams */
    IOSTREAM		*dwrite;
    int                  close_needed;
    BOOL                 fatal_alert;
} PL_SSL_INSTANCE;



/*
 * The PL-SSL API
 */
int              ssl_lib_init    (void);
int              ssl_lib_exit    (void);
PL_SSL *         ssl_init        (PL_SSL_ROLE role, const SSL_METHOD *method);
int              ssl_config      (PL_SSL *config, term_t source);
int              ssl_socket      (PL_SSL *config);
int              ssl_ssl_bio	 (PL_SSL *config, IOSTREAM* sread, IOSTREAM* swrite, PL_SSL_INSTANCE ** instance);
PL_SSL_INSTANCE *ssl_ssl         (PL_SSL *config, int sock);
void             ssl_exit        (PL_SSL *config);
int              ssl_close       (PL_SSL_INSTANCE *instance);
X509 *		ssl_peer_certificate(PL_SSL_INSTANCE *instance);
int             ssl_accept       (PL_SSL *config, void *addr, socklen_t *addrlen);
int             ssl_connect      (PL_SSL *config);
ssize_t         ssl_read         (void *handle, char *buf, size_t size);
ssize_t         ssl_write        (void *handle, char *buf, size_t size);
int		ssl_thread_setup (void);

char *          ssl_set_host     (PL_SSL *config, const char *host);
int             ssl_set_port     (PL_SSL *config, int port);

char *          ssl_set_cacert   (PL_SSL *config, const char *cacert);
int             ssl_set_use_system_cacert(PL_SSL *config, int use_system_cacert);
char *          ssl_set_certf    (PL_SSL *config, const char *certf);
char *          ssl_set_certificate(PL_SSL *config, const char *cert);
char *          ssl_set_keyf     (PL_SSL *config, const char *keyf);
char *          ssl_set_key      (PL_SSL *config, const char *key);
char *          ssl_set_password (PL_SSL *config, const char *password);
BOOL            ssl_set_cert     (PL_SSL *config, BOOL required);
BOOL            ssl_set_crl_required(PL_SSL *config, BOOL required);
X509_crl_list*  ssl_set_crl_list (PL_SSL *config, X509_crl_list *list);
char *          ssl_set_cipher_list(PL_SSL *config, const char *cipher_list);
char *          ssl_set_ecdh_curve(PL_SSL *config, const char *ecdh_curve);
int             ssl_set_min_protocol_version(PL_SSL *config, int version);
int             ssl_set_max_protocol_version(PL_SSL *config, int version);
BOOL            ssl_set_peer_cert(PL_SSL *config, BOOL required);
BOOL            ssl_set_close_parent(PL_SSL *config, int closeparent);
BOOL            ssl_set_close_notify(PL_SSL *config, BOOL close_notify);
void            ssl_set_method_options(PL_SSL *config, int options);
int		raise_ssl_error(long e);
X509_list *	system_root_certificates(void);

BOOL            ssl_set_cb_cert_verify
                                 ( PL_SSL *config
                                 , BOOL (*callback)( PL_SSL *
                                                   , X509*
                                                   , X509_STORE_CTX*
                                                   , const char *
                                                   , int
                                                   )
                                 , void *
                                 ) ;

BOOL            ssl_set_cb_pem_passwd
                                 ( PL_SSL *config
                                 , char * (*callback)( PL_SSL *
                                                     , char *
                                                     , int
                                                     )
                                 , void *
                                 ) ;
BOOL            ssl_set_cb_sni
                                 (PL_SSL *config,
                                  PL_SSL * (*callback)( PL_SSL *,
                                                        const char *),
                                  void *
                                  );

void            ssl_msg          (char *fmt, ...);
void            ssl_err          (char *fmt, ...);
int		ssl_set_debug	 (int level);
void            ssl_deb          (int level, char *fmt, ...);

extern BIO_METHOD *bio_read_method();
extern BIO_METHOD *bio_write_method();

#endif

