/*  Part of SWI-Prolog

    Author:        Jan van der Steen and Jan Wielemaker
    E-mail:        J.van.der.Steen@diff.nl and jan@swi.psy.uva.nl
    WWW:           http://www.swi-prolog.org
    Copyright (C): 1985-2015, SWI-Prolog Foundation
			      VU University Amsterdam

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License as published by the Free Software Foundation; either
    version 2.1 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/

#ifndef SSLLIBH__
#define SSLLIBH__
#include "../clib/nonblockio.h"

#define SSL_CONFIG_MAGIC 0x539dbe3a
#define SYSTEM_CACERT_FILENAME "/etc/ssl/certs/ca-certificates.crt"
#define CA_SYSTEM_ROOT_CERTIFICATES "system://root certificates"

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

typedef struct pl_ssl {
    long	        magic;
    /*
     * Are we server or client
     */
    PL_SSL_ROLE         pl_ssl_role;

    int			sock;		/* the listening/connected socket */
    int                 closeparent;
    atom_t              atom;
    /*
     * Context, Certificate, SSL info
     */
    SSL_CTX *           pl_ssl_ctx;
    int                 pl_ssl_idx;
    X509 *              pl_ssl_peer_cert;

    /*
     * Various parameters affecting the SSL layer
     */
    int                 use_system_cacert;
    char *              pl_ssl_cacert;
    char *              pl_ssl_certf;
    char *              pl_ssl_keyf;
    char *              pl_ssl_password;
    BOOL                pl_ssl_cert_required;
    BOOL                pl_ssl_peer_cert_required;

    /*
     * Application defined handlers
     */
    BOOL                (*pl_ssl_cb_cert_verify)( struct pl_ssl *config
                                                , X509*
                                                , X509_STORE_CTX*
                                                , const char *error
                                                ) ;
    void *              pl_ssl_cb_cert_verify_data;
    char *              (*pl_ssl_cb_pem_passwd) ( struct pl_ssl *
                                                , char *
                                                , int
                                                ) ;
    void *              pl_ssl_cb_pem_passwd_data;
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

char *          ssl_set_cacert   (PL_SSL *config, const char *cacert);
int             ssl_set_use_system_cacert(PL_SSL *config, int use_system_cacert);
char *          ssl_set_certf    (PL_SSL *config, const char *certf);
char *          ssl_set_keyf     (PL_SSL *config, const char *keyf);
char *          ssl_set_password (PL_SSL *config, const char *password);
BOOL            ssl_set_cert     (PL_SSL *config, BOOL required);
BOOL            ssl_set_peer_cert(PL_SSL *config, BOOL required);
BOOL		ssl_set_close_parent(PL_SSL *config, int closeparent);
void            ssl_set_method_options(PL_SSL *config, int options);
int		raise_ssl_error(long e);
X509_STORE *	system_root_certificates(void);

BOOL            ssl_set_cb_cert_verify
                                 ( PL_SSL *config
                                 , BOOL (*callback)( PL_SSL *
                                                   , X509*
                                                   , X509_STORE_CTX*
                                                   , const char *
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

void            ssl_msg          (char *fmt, ...);
void            ssl_err          (char *fmt, ...);
int		ssl_set_debug	 (int level);
void            ssl_deb          (int level, char *fmt, ...);

extern BIO_METHOD bio_read_functions;
extern BIO_METHOD bio_write_functions;

#endif

