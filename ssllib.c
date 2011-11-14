/*  $Id$

    Part of SWI-Prolog

    Author:        Jan van der Steen and Jan Wielemaker
    E-mail:        J.van.der.Steen@diff.nl and jan@swi.psy.uva.nl
    WWW:           http://www.swi-prolog.org
    Copyright (C): 1985-2002, SWI-Prolog Foundation

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

#include <string.h>
#include <assert.h>
#include <stdarg.h>
#include "ssllib.h"
#include <openssl/rand.h>

#ifdef __SWI_PROLOG__
#include <SWI-Stream.h>
#include <SWI-Prolog.h>

#define perror(x) Sdprintf("%s: %s\n", x, strerror(errno));

/*
 * Remap socket related calls to nonblockio library
 */
#include "../clib/nonblockio.h"
#define closesocket     nbio_closesocket
#else   /* __SWI_PROLOG__ */
#define Soutput         stdout
#define Serror          stderr
#define Svfprintf       vfprintf
static int PL_handle_signals(void) { return 0; }
#ifndef __WINDOWS__
#define closesocket	close
#endif
#endif  /* __SWI_PROLOG__ */

#include <openssl/rsa.h>

typedef enum
{ SSL_PL_OK
, SSL_PL_RETRY
, SSL_PL_ERROR
} SSL_PL_STATUS;

#define SSL_CERT_VERIFY_MORE 0
#define SSL_WAIT_CHILD       1
#define SSL_TCP_QUEUE_MAX    5

#ifndef DEBUG
#define DEBUG 1
#endif

/*
 * Index of our config data in the SSL data
 */
static int ssl_idx;
static int ctx_idx;


static void
ssl_error(SSL *ssl, int ssl_ret, int code)
/*
 * Report about errors occuring in the SSL layer
 */
{
    char  buf[256];
    char *component[5];
    char *colon;
    int   error = ERR_get_error();
    int   n;

    ssl_deb(1, "ssl_error() ret=%d, code=%d, err=%d\n", ssl_ret, code, error);

    if ( code == SSL_ERROR_SYSCALL && error == 0 )
    { if ( ssl_ret == 0 )
      {	/* normal if peer just hangs up the line */
	ssl_deb(1, "SSL error report: unexpected end-of-file\n");
	return;
      } else if ( ssl_ret == -1 )
      { ssl_deb(0, "SSL error report: syscall error: %s\n", strerror(errno));
	return;
      }
    }

    (void) ERR_error_string(error, buf);

    /*
     * Disect the following error string:
     *
     * error:[error code]:[library name]:[function name]:[reason string]
     */
    for (colon = buf, n = 0; n < 5; n++) {
        component[n] = colon;
        if ((colon = strchr(colon, ':')) == NULL) break;
        *colon++ = 0;
    }

    ssl_deb(0,
	    "SSL error report:\n\t%8s: %s\n\t%8s: %s\n\t%8s: %s\n\t%8s: %s\n"
	   ,     "code", component[1]
	   ,  "library", component[2]
	   , "function", component[3]
	   ,   "reason", component[4]
	   );
}

static SSL_PL_STATUS
ssl_inspect_status(SSL *ssl, int ssl_ret)
{   int code;

    if (ssl_ret > 0) {
        return SSL_PL_OK;
    }

    code=SSL_get_error(ssl, ssl_ret);

    switch (code) {
       /* I am not sure what to do here - specifically, I am not sure if our underlying BIO
          will block if there is not enough data to complete a handshake. If it will, we should
          never get these return values. If it wont, then we presumably need to simply try again
          which is why I am returning SSL_PL_RETRY
       */
	case SSL_ERROR_WANT_READ:
           return SSL_PL_RETRY;

	case SSL_ERROR_WANT_WRITE:
           return SSL_PL_RETRY;

#ifdef SSL_ERROR_WANT_CONNECT
	case SSL_ERROR_WANT_CONNECT:
           return SSL_PL_RETRY;
#endif

#ifdef SSL_ERROR_WANT_ACCEPT
	case SSL_ERROR_WANT_ACCEPT:
           return SSL_PL_RETRY;
#endif

	case SSL_ERROR_ZERO_RETURN:
	    return SSL_PL_OK;

	default:
	    break;
    }

    ssl_error(ssl, ssl_ret, code);
    return SSL_PL_ERROR;
}

static char *
ssl_strdup(const char *s)
{
    char *new = NULL;

    if (s != NULL && (new = malloc(strlen(s)+1)) != NULL) {
        strcpy(new, s);
    }
    return new;
}

#if SSL_CERT_VERIFY_MORE

static void
ssl_cert_print(X509 *cert, const char *role)
{
#if DEBUG
    char * str = NULL;
    int i;

    ssl_deb(1, "%s certificate:\n", role);
    str = X509_NAME_oneline(X509_get_subject_name (cert), NULL, 0);
    if (str) {
        ssl_deb(1, "\t subject: %s\n", str);
        OPENSSL_free(str);
    }

    str = X509_NAME_oneline(X509_get_issuer_name  (cert), NULL, 0);
    if (str) {
        ssl_deb(1, "\t issuer: %s\n", str);
        OPENSSL_free(str);
    }

    i = X509_get_signature_type(cert);
    ssl_deb(1, "\t signature type: %d\n", i);
#endif /* DEBUG */
}

#endif /* SSL_CERT_VERIFY_MORE */

#if SSL_CERT_VERIFY_MORE

static void
ssl_verify_cert(PL_SSL *config)
/*
 * Verify certificate
 */
{
    SSL        * ssl  = config->pl_ssl_ssl;
    X509       * cert = config->pl_ssl_peer_cert;
    const char * role = (config->pl_ssl_role == PL_SSL_SERVER)
                        ? "Client"
                        : "Server"
                        ;

    if (cert != NULL) {
        if (SSL_get_verify_result(ssl) != X509_V_OK) {
            ssl_err("%s certificate didn't verify, continue anyway\n", role);
        } else {
            ssl_deb(1, "%s certificate verified ok\n", role);
        }

        ssl_cert_print(cert, role);

        /*
         * Do additional certificate verification stuff here.
         */
        X509_free (cert);
    } else {
        ssl_err("%s does not have certificate.\n", role);
    }
}

#endif /* SSL_CERT_VERIFY_MORE */

static PL_SSL *
ssl_new(void)
/*
 * Allocate new state and configuration storage for an SSL session from PL
 */
{
    PL_SSL *new = NULL;

    if ((new = malloc(sizeof(*new))) != NULL) {
        new->pl_ssl_role                = PL_SSL_NONE;

	new->sock			= -1;
        new->closeparent		= 0;

        new->pl_ssl_peer_cert           = NULL;
        new->pl_ssl_ctx                 = NULL;
        new->pl_ssl_idx                 = -1;
        new->pl_ssl_password            = NULL;

        new->pl_ssl_host                = NULL;
        new->pl_ssl_port                = -1;
	new->pl_ssl_reuseaddr		= TRUE;

        new->pl_ssl_cacert              = NULL;
        new->pl_ssl_cert_required       = FALSE;
        new->pl_ssl_certf               = NULL;
        new->pl_ssl_keyf                = NULL;
        new->pl_ssl_peer_cert_required  = FALSE;
        new->pl_ssl_cb_cert_verify      = NULL;
        new->pl_ssl_cb_cert_verify_data = NULL;
        new->pl_ssl_cb_pem_passwd       = NULL;
        new->pl_ssl_cb_pem_passwd_data  = NULL;
	new->magic		        = SSL_CONFIG_MAGIC;
    }
    ssl_deb(1, "Allocated config structure\n");

    return new;
}

static void
ssl_free(PL_SSL *config)
/*
 * Free resources allocated to store the state and config parameters.
 */
{
    if (config) {
        if ( config->magic == SSL_CONFIG_MAGIC ) {
	    config->magic = 0;
	    free(config->pl_ssl_host);
	    free(config->pl_ssl_cacert);
	    free(config->pl_ssl_certf);
	    free(config->pl_ssl_keyf);
	    free(config->pl_ssl_password);
	    free(config);
	    ssl_deb(1, "Released config structure\n");
	} else {
	    assert(0);
	}
    } else {
	ssl_deb(1, "No config structure to release\n");
    }
}

static int
ssl_config_new  ( void *            ctx
                , void *            pl_ssl
                , CRYPTO_EX_DATA *  parent_ctx
                , int               parent_ctx_idx
                , long  argl
                , void *argp
                )
/*
 * Called when a new CTX is allocated
 */
{
    PL_SSL *config = NULL;

    if ((config = ssl_new()) != NULL) {
        if (SSL_CTX_set_ex_data( ctx
                               , ctx_idx
                               , config) == 0) {
            ssl_err("Cannot save application data\n");
            ssl_free(config);
            config = NULL;
        }
    }

    /*
     * 1 = success
     * 0 = failure
     */
    return (config != NULL);
}

static int
ssl_config_dup  ( CRYPTO_EX_DATA *  to
                , CRYPTO_EX_DATA *  from
                , void *            pl_ssl
                , int               parent_ctx_idx
                , long  argl
                , void *argp
                )
{
    return 1;
}

static void
ssl_config_free( void *            ctx
               , void *            pl_ssl
               , CRYPTO_EX_DATA *  parent_ctx
               , int               parent_ctx_idx
               , long  argl
               , void *argp
               )
{
    PL_SSL *config = NULL;

    ssl_deb(1, "calling ssl_config_free()\n");
    if ((config = SSL_CTX_get_ex_data(ctx, ctx_idx)) != NULL) {
        assert(config->magic == SSL_CONFIG_MAGIC);
        ssl_free(config);
    }
}

char *
ssl_set_cacert(PL_SSL *config, const char *cacert)
/*
 * Store certificate authority location in config storage
 */
{
    if (cacert) {
        if (config->pl_ssl_cacert) free(config->pl_ssl_cacert);
        config->pl_ssl_cacert = ssl_strdup(cacert);
    }
    return config->pl_ssl_cacert;
}

char *
ssl_set_certf(PL_SSL *config, const char *certf)
/*
 * Store certificate file location in config storage
 */
{
    if (certf) {
        if (config->pl_ssl_certf) free(config->pl_ssl_certf);
        config->pl_ssl_certf = ssl_strdup(certf);
    }
    return config->pl_ssl_certf;
}

char *
ssl_set_keyf(PL_SSL *config, const char *keyf)
/*
 * Store private key location in config storage
 */
{
    if (keyf) {
        if (config->pl_ssl_keyf) free(config->pl_ssl_keyf);
        config->pl_ssl_keyf = ssl_strdup(keyf);
    }
    return config->pl_ssl_keyf;
}

char *
ssl_set_password(PL_SSL *config, const char *password)
/*
 * Store supplied private key password in config storage
 */
{
    if (password) {
        if (config->pl_ssl_password) free(config->pl_ssl_password);
        config->pl_ssl_password = ssl_strdup(password);
    }
    return config->pl_ssl_password;
}

char *
ssl_set_host(PL_SSL *config, const char *host)
/*
 * Store supplied host in config storage
 */
{
    if (host) {
        if (config->pl_ssl_host) free(config->pl_ssl_host);
        config->pl_ssl_host = ssl_strdup(host);
    }
    return config->pl_ssl_host;
}

int
ssl_set_port(PL_SSL *config, int port)
/*
 * Store supplied port in config storage
 */
{
    return config->pl_ssl_port = port;
}

BOOL
ssl_set_cert(PL_SSL *config, BOOL required)
/*
 * Do we require our certificate
 */
{
    return config->pl_ssl_cert_required = required;
}

BOOL
ssl_set_reuseaddr(PL_SSL *config, BOOL reuse)
{ return config->pl_ssl_reuseaddr = reuse;
}


BOOL
ssl_set_peer_cert(PL_SSL *config, BOOL required)
/*
 * Do we require peer certificate
 */
{
    return config->pl_ssl_peer_cert_required = required;
}

BOOL
ssl_set_cb_pem_passwd( PL_SSL *config
                     , char * (*callback)( PL_SSL *
                                         , char *
                                         , int
                                         )
                     , void *data
                     )
/*
 * Install handler which is called when a certificate is password protected.
 */
{
    config->pl_ssl_cb_pem_passwd      = callback;
    config->pl_ssl_cb_pem_passwd_data = data;

    return TRUE;
}

BOOL
ssl_set_cb_cert_verify( PL_SSL *config
                      , BOOL (*callback)( PL_SSL *
                                        , X509 *
                                        , X509_STORE_CTX *
                                        , const char *
                                        )
                      , void *data
                      )
/*
 * Install handler which is called when certificate verification fails.
 */
{
    config->pl_ssl_cb_cert_verify      = callback;
    config->pl_ssl_cb_cert_verify_data = data;

    return TRUE;
}

static int
ssl_cb_cert_verify(int preverify_ok, X509_STORE_CTX *ctx)
/*
 * Function handling certificate verification
 */
{
    SSL    * ssl    = NULL;
    PL_SSL * config = NULL;
    /*
     * Get our config data
     */
    ssl = X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
    config = SSL_get_ex_data(ssl, ssl_idx);



    ssl_deb(1, " ---- INIT Handling certificate verification\n");
    if (!preverify_ok) {
        X509 *cert = NULL;
        int   err;
        const char *error;

        /*
         * Get certificate
         */
        cert = X509_STORE_CTX_get_current_cert(ctx);


        /*
         * Get error specification
         */
        err   = X509_STORE_CTX_get_error(ctx);
        error = X509_verify_cert_error_string(err);

        if (config->pl_ssl_cb_cert_verify) {
           preverify_ok = ((config->pl_ssl_cb_cert_verify)(config, cert, ctx, error) != 0);
        } else {
            char  subject[256];
            char  issuer [256];
            int   depth;

            depth = X509_STORE_CTX_get_error_depth (ctx);
            X509_NAME_oneline( X509_get_subject_name(cert)
                             , subject, sizeof(subject));
            X509_NAME_oneline( X509_get_issuer_name (cert)
                             , issuer, sizeof(issuer));
            ssl_deb(1,  "error:%s\n", error);
            ssl_deb(1, "subject:%s\n", subject);
            ssl_deb(1, "issuer:%s\n", issuer);
        }
        ssl_deb(1, "Certificate preverified not ok\n");
    } else {
        ssl_deb(1, "Certificate preverified ok\n");
    }
    ssl_deb(1, " ---- EXIT Handling certificate verification\n");

    return preverify_ok;
}

static int
ssl_cb_pem_passwd(char *buf, int size, int rwflag, void *userdata)
/*
 * We're called since the OpenSSL library needs a password to access
 * the private key. The method to require the password is defined in
 * this function. Either interactive or automated.
 * Fill the supplied buffer with the password and return its length
 * or 0 on failure.
 */
{
    PL_SSL *config = (PL_SSL *) userdata;
    char   *passwd = NULL;
    int     len    = 0;

    if (config->pl_ssl_cb_pem_passwd) {
        /*
         * Callback installed
         */
        passwd = (config->pl_ssl_cb_pem_passwd)(config, buf, size);
    } else
    if (config->pl_ssl_password) {
        /*
         * Password defined
         */
        passwd = config->pl_ssl_password;
    }

    if (passwd) {
        if ((len = (int)strlen(passwd)) < size) {
            strcpy(buf, passwd);
        } else {
            len = 0;
        }
    }

    return len;
}

BOOL
ssl_set_close_parent(PL_SSL *config, int closeparent)
/*
 * Should we close the parent streams?
 */
{
    return config->closeparent = closeparent;
}


int
ssl_close(PL_SSL_INSTANCE *instance)
/*
 * Clean up TCP and SSL connection resources
 */
{
    int ret = 0;
    if (instance) {
        if (instance->config->pl_ssl_role != PL_SSL_SERVER) {
            /*
             * Send SSL/TLS close_notify
             */
            SSL_shutdown(instance->ssl);
        }

        if (instance->ssl) {
            SSL_free(instance->ssl);
        }

        if (instance->sock >= 0) {
           /* If the socket has been stored, then we ought to close it if the SSL is being closed */
           ret = closesocket(instance->sock);
           instance->sock = -1;
        }

        if (instance->sread != NULL) {
           /* Indicate we are no longer filtering the stream */
           Sset_filter(instance->sread, NULL);
           /* Close the stream if requested */
           if (instance->config->closeparent)
              Sclose(instance->sread);
        }

        if (instance->swrite != NULL) {
           /* Indicate we are no longer filtering the stream */
           Sset_filter(instance->swrite, NULL);
           /* Close the stream if requested */
           if (instance->config->closeparent)
              Sclose(instance->swrite);
        }

        free(instance);
    }
    ERR_free_strings();

    ssl_deb(1, "Controlled close\n");

    return ret;
}

void
ssl_exit(PL_SSL *config)
/*
 * Clean up all allocated resources.
 */
{
    if (config)
    { if ( config->pl_ssl_role == PL_SSL_SERVER && config->sock >= 0 )
      { /* If the socket has been stored, then we ought to close it if the SSL is being closed */
        closesocket(config->sock);
	config->sock = -1;
      }

      if (config->pl_ssl_ctx)
      { ssl_deb(1, "Calling SSL_CTX_free()\n");
	SSL_CTX_free(config->pl_ssl_ctx);	/* doesn't call free hook? */
      }
      else
      { ssl_deb(1, "config without CTX encountered\n");
      }
    }

    ssl_deb(1, "Controlled exit\n");
}


/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
ERR_print_errors_pl() is like  ERR_print_errors_fp(stderr),   but  deals
with the fact that on Windows stderr is generally lost, so we use Prolog
I/O for portability.
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */

static void
ERR_print_errors_pl()
{ char errmsg[1024];

  ERR_error_string_n(ERR_get_error(), errmsg, sizeof(errmsg));

  Sdprintf("%s\n", errmsg);
}


PL_SSL *
ssl_init(PL_SSL_ROLE role)
/*
 * Allocate the holder for our parameters which will specify the
 * configuration parameters and any other statefull parameter.
 * Load the OpenSSL error_strings for error reporting.
 * Define method for SSL layer depending on whether we're server or client.
 * Create SSL context.
 */
{
    PL_SSL      * config     = NULL;
    SSL_METHOD  * ssl_method = NULL;
    SSL_CTX     * ssl_ctx    = NULL;

#if 0
    switch (role) {
        case PL_SSL_SERVER:
            ssl_method = SSLv23_server_method();
            break;
        case PL_SSL_NONE:
        case PL_SSL_CLIENT:
            /*
             * Either v2 or v3, we choose v3 to make the shutdown more
             * controlled and clean (see util.c)
             */
            ssl_method = SSLv3_client_method();
            break;
    }
#else
    ssl_method = SSLv23_method();
#endif
    ssl_ctx = SSL_CTX_new(ssl_method);

    if (!ssl_ctx) {
        ERR_print_errors_pl();
    } else {
        long ctx_mode = 0L;

        if ((config = SSL_CTX_get_ex_data(ssl_ctx, ctx_idx)) == NULL) {
            ssl_err("Cannot read back application data\n");
            SSL_CTX_free(ssl_ctx);
            return NULL;
        }
        assert(config->magic == SSL_CONFIG_MAGIC);
        config->pl_ssl_ctx  = ssl_ctx;
        config->pl_ssl_role = role;
        ssl_set_cert     (config, (role == PL_SSL_SERVER));
        ssl_set_peer_cert(config, (role != PL_SSL_SERVER));

        /*
         * Set SSL_{read,write} behaviour when a renegotiation takes place
         * in a blocking transport layer.
         */
        ctx_mode  = SSL_CTX_get_mode(ssl_ctx);
        ctx_mode |= SSL_MODE_AUTO_RETRY;
        ctx_mode  = SSL_CTX_set_mode(ssl_ctx, ctx_mode);
    }

    ssl_deb(1, "Initialized\n");

    return config;
}

int
ssl_debug(PL_SSL *config)
/*
 * Get some extra info once the SSL negotiation is completed
 */
{
#if DEBUG
    /*
     * Get the cipher
     */
    ssl_deb(1,  "SSL connection using %s\n"
           , SSL_get_cipher(config->pl_ssl_ssl)
           ) ;
#endif

#if SSL_CERT_VERIFY_MORE
    if (config->pl_ssl_peer_cert_required) {
        /*
         * Get peer's certificate
         */
        config->pl_ssl_peer_cert = SSL_get_peer_certificate(config->pl_ssl_ssl);
        if (config->pl_ssl_peer_cert == NULL) {
            return -8;
        }
        ssl_deb(1, "got peer certificate\n");

        ssl_verify_cert(config);
        ssl_deb(1, "verified peer certificate\n");
    }
#endif

    ssl_deb(1, "inspected ssl peer details\n");

    return 0;
}

static int
ssl_config(PL_SSL *config)
/*
 * Initialize various SSL layer parameters using the supplied
 * config parameters.
 */
{
    SSL_CTX_load_verify_locations( config->pl_ssl_ctx
                                 , config->pl_ssl_cacert
                                 , NULL
                                 ) ;
    ssl_deb(1, "certificate authority(s) installed (public keys loaded)\n");

    SSL_CTX_set_default_passwd_cb_userdata( config->pl_ssl_ctx
                                          , config
                                          ) ;
    SSL_CTX_set_default_passwd_cb( config->pl_ssl_ctx
                                 , ssl_cb_pem_passwd
                                 ) ;
    ssl_deb(1, "password handler installed\n");

    if (config->pl_ssl_cert_required) {
        if (config->pl_ssl_certf == NULL ||
            config->pl_ssl_keyf  == NULL) {
            ssl_err("certificate and private key required but not set\n");
            return -1;
        }
        if (SSL_CTX_use_certificate_file( config->pl_ssl_ctx
                                        , config->pl_ssl_certf
                                        , SSL_FILETYPE_PEM) <= 0) {
            ERR_print_errors_pl();
            return -2;
        }
        if (SSL_CTX_use_PrivateKey_file( config->pl_ssl_ctx
                                       , config->pl_ssl_keyf
                                       , SSL_FILETYPE_PEM) <= 0) {
            ERR_print_errors_pl();
            return -3;
        }
        if (SSL_CTX_check_private_key(config->pl_ssl_ctx) <= 0) {
            ERR_print_errors_pl();
            ssl_err("Private key does not match certificate public key\n");
            return -4;
        }
        ssl_deb(1, "certificate installed successfully\n");
    }
    (void) SSL_CTX_set_verify( config->pl_ssl_ctx
                             , (config->pl_ssl_peer_cert_required)
                               ? SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT
                               : SSL_VERIFY_NONE
                             , ssl_cb_cert_verify
                             ) ;
    ssl_deb(1, "installed certificate verification handler\n");

    return 0;
}

PL_SSL_INSTANCE *
ssl_instance_new(PL_SSL *config, IOSTREAM* sread, IOSTREAM* swrite)
{
    PL_SSL_INSTANCE *new = NULL;

    if ((new = malloc(sizeof(PL_SSL_INSTANCE))) != NULL) {
        new->config       = config;
        new->sock         = -1;
        new->sread        = sread;
        new->swrite       = swrite;
        new->close_needed = 0;
    }
    return new;
}

int
ssl_lib_init(void)
/*
 * One-time library initialization code
 */
{
    SSL_load_error_strings();
    /* This call will ensure we only end up calling RAND_poll() once
       - preventing an ugly synchronization issue in OpenSSL */
    RAND_status();
    (void) SSL_library_init();

    if ((ctx_idx = SSL_CTX_get_ex_new_index( 0
                                       , NULL
                                       , ssl_config_new
                                       , ssl_config_dup
                                       , ssl_config_free
                                       )) < 0) {
        ssl_err("Cannot register application data\n");
        return -1;
    }

    /*
     * Index used to store our config data in the SSL data structure
     */
    ssl_idx = SSL_get_ex_new_index(0, "config", NULL, NULL, NULL);

#ifdef __SWI_PROLOG__
    /*
     * Initialize the nonblockio library
     */
    if ( !nbio_init("ssl4pl") )		/* DLL name */
    { ssl_err("Could not initialise nbio module\n");
      return -1;
    }
#endif

#ifdef _REENTRANT
    ssl_thread_setup();
#endif

    return 0;
}


/*
 * BIO routines for SSL over streams
 */

/*
 * Read function.  To allow for setting a timeout on the SSL stream, we
 * use the timeout of this stream if we do not have a timeout ourselves.
 *
 * Note that if the underlying stream received a timeout, we lift this
 * error to the ssl stream and clear the error on the underlying stream.
 * This way, the normal timeout-reset in pl-stream.c correctly resets
 * a possible timeout.  See also test_ssl.c.  Patch and analysis by
 * Keri Harris.
 */

int bio_read(BIO* bio, char* buf, int len)
{
   IOSTREAM *stream = BIO_get_ex_data(bio, 0);
   IOSTREAM *ssl_stream = stream->upstream;
   int rc;

   if ( ssl_stream &&
	stream->timeout < 0 &&
	ssl_stream->timeout > 0 )
   { stream->timeout = ssl_stream->timeout;
     rc = (int)Sfread(buf, sizeof(char), len, stream);
     stream->timeout = -1;
   } else
   { rc = (int)Sfread(buf, sizeof(char), len, stream);
   }

   if ( ssl_stream && (stream->flags & SIO_TIMEOUT) )
   { ssl_stream->flags |= (SIO_FERR|SIO_TIMEOUT);
     Sclearerr(stream);
   }

   return rc;
}

/*
 * Gets function. If only OpenSSL actually had usable documentation, I might know
 * what this was actually meant to do....
 */

int bio_gets(BIO* bio, char* buf, int len)
{
   IOSTREAM* stream;
   int r = 0;
   stream = BIO_get_app_data(bio);
   for (r = 0; r < len; r++)
   {
      int c = Sgetc(stream);
      if (c == EOF)
         return r-1;
      buf[r] = (char)c;
      if (buf[r] == '\n')
         break;
   }
   return r;
}

/*
 * Write function
 */

int bio_write(BIO* bio, const char* buf, int len)
{
   IOSTREAM* stream = BIO_get_ex_data(bio, 0);
   IOSTREAM* ssl_stream = stream->upstream;
   int r;

   if ( ssl_stream &&
	stream->timeout < 0 &&
	ssl_stream->timeout > 0 )
   { stream->timeout = ssl_stream->timeout;
     r = (int)Sfwrite(buf, sizeof(char), len, stream);
     /* OpenSSL expects there to be no buffering when it writes. Flush here */
     Sflush(stream);
     stream->timeout = -1;
   } else
   { r = (int)Sfwrite(buf, sizeof(char), len, stream);
     Sflush(stream);
   }

   if ( ssl_stream && (stream->flags & SIO_TIMEOUT) )
   { ssl_stream->flags |= (SIO_FERR|SIO_TIMEOUT);
     Sclearerr(stream);
   }

   return r;
}

/*
 * Control function
 * (Currently only supports flush. There are several mandatory, but as-yet unsupported functions...)
 */

long bio_control(BIO* bio, int cmd, long num, void* ptr)
{
   IOSTREAM* stream;
   stream  = BIO_get_ex_data(bio, 0);
   switch(cmd)
   {
     case BIO_CTRL_FLUSH:
        Sflush(stream);
        return 1;
   }
   return 0;
}

/*
 * Create function. Called when a new BIO is created
 * It is our responsibility to set init to 1 here
 */

int bio_create(BIO* bio)
{
   bio->shutdown = 1;
   bio->init = 1;
   bio->num = -1;
   bio->ptr = NULL;
   return 1;
}

/*
 * Destroy function. Called when a BIO is freed
 */

int bio_destroy(BIO* bio)
{
   if (bio == NULL)
   {
      return 0;
   }
   return 1;
}

/*
 * Specify the BIO read and write function structures
 */

BIO_METHOD bio_read_functions = {BIO_TYPE_MEM,
                                 "read",
                                 NULL,
                                 &bio_read,
                                 NULL,
                                 &bio_gets,
                                 &bio_control,
                                 &bio_create,
                                 &bio_destroy};

BIO_METHOD bio_write_functions = {BIO_TYPE_MEM,
                                  "write",
                                  &bio_write,
                                  NULL,
                                  NULL,
                                  NULL,
                                  &bio_control,
                                  &bio_create,
                                  &bio_destroy};

/*
 * Establish an SSL session using the given read and write streams and the role
 */

PL_SSL_INSTANCE *
ssl_ssl_bio(PL_SSL *config, IOSTREAM* sread, IOSTREAM* swrite)
/*
 * Establish the SSL layer using the supplied streams
 */
{
    PL_SSL_INSTANCE * instance = NULL;
    BIO* rbio = NULL;
    BIO* wbio = NULL;

    if ((instance = ssl_instance_new(config, sread, swrite)) == NULL) {
        ssl_deb(1, "ssl instance malloc failed\n");
        return NULL;
    }
    /*
     * Configure SSL behaviour with install configuration parameters
     */
    if (ssl_config(config) < 0) {
        return NULL;
    }

    /*
     * Create BIOs
     */
    rbio = BIO_new(&bio_read_functions);
    BIO_set_ex_data(rbio, 0, sread);
    wbio = BIO_new(&bio_write_functions);
    BIO_set_ex_data(wbio, 0, swrite);
    /*
     * Prepare SSL layer
     */
    if ((instance->ssl = SSL_new(config->pl_ssl_ctx)) == NULL) {
        return NULL;
    }
    ssl_deb(1, "allocated ssl layer\n");

    /*
     * Store reference to our config data in SSL
     */
    SSL_set_ex_data(instance->ssl, ssl_idx, config);
    SSL_set_bio(instance->ssl, rbio, wbio); /* No return value */
    ssl_deb(1, "allocated ssl fd\n");
    switch (config->pl_ssl_role) {
        case PL_SSL_SERVER:
            ssl_deb(1, "setting up SSL server side\n");
            do {
                int ssl_ret = SSL_accept(instance->ssl);
                switch(ssl_inspect_status(instance->ssl, ssl_ret)) {
                    case SSL_PL_OK:
                        /* success */
                        ssl_deb(1, "established ssl server side\n");
                        return instance;

                    case SSL_PL_RETRY:
                        continue;

                    case SSL_PL_ERROR:
                       return NULL;
                }
            } while (1);
            break;

	case PL_SSL_NONE:
	case PL_SSL_CLIENT:
	   ssl_deb(1, "setting up SSL client side\n");
	   do {
	      int ssl_ret = SSL_connect(instance->ssl);
	      switch(ssl_inspect_status(instance->ssl, ssl_ret)) {
	         case SSL_PL_OK:
	            /* success */
	            ssl_deb(1, "established ssl client side\n");
	            return instance;

	         case SSL_PL_RETRY:
	            continue;

	         case SSL_PL_ERROR:
                    Sdprintf("Unrecoverable error: %d\n", SSL_get_error(instance->ssl, ssl_ret));
                    Sdprintf("Additionally, get_error returned %d\n", ERR_get_error());
                    return NULL;
                    }
	   } while (1);
	   break;
    }
    return NULL;
}

ssize_t
ssl_read(PL_SSL_INSTANCE *instance, char *buf, int size)
/*
 * Perform read on SSL session
 */
{
    SSL *ssl = instance->ssl;

    assert(ssl != NULL);

    do {
        int rbytes = SSL_read(ssl, buf, size);
        if (rbytes == 0) /* EOF - error, but we handle in prolog */
          return 0;
        switch(ssl_inspect_status(ssl, rbytes)) {
            case SSL_PL_OK:
                /* success */
                return rbytes;

            case SSL_PL_RETRY:
                continue;

            case SSL_PL_ERROR:
               return -1;
       }
    } while (1);
}

ssize_t
ssl_write(PL_SSL_INSTANCE *instance, const char *buf, int size)
/*
 * Perform write on SSL session
 */
{
    SSL *ssl = instance->ssl;

    assert(ssl != NULL);

    do {
        int wbytes = SSL_write(ssl, buf, size);
        if (wbytes == 0) /* EOF - error, but we handle in prolog */
          return 0;
        switch(ssl_inspect_status(ssl, wbytes)) {
            case SSL_PL_OK:
                /* success */
                return wbytes;

            case SSL_PL_RETRY:
                continue;

            case SSL_PL_ERROR:
               return -1;
        }
    } while (1);
}


		 /*******************************
		 *	      THREADING		*
		 *******************************/

/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
OpenSSL is not thread-safe, unless  you   install  the hooks below. This
code is based on mttest.c distributed with the OpenSSL library.
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */

#ifdef _REENTRANT

#include <pthread.h>

static pthread_mutex_t *lock_cs;
static long *lock_count;
static void (*old_locking_callback)(int, int, const char*, int) = NULL;
static unsigned long (*old_id_callback)(void) = NULL;

static void
pthreads_locking_callback(int mode, int type, const char *file, int line)
{ if (mode & CRYPTO_LOCK)
  { pthread_mutex_lock(&(lock_cs[type]));
    lock_count[type]++;
  } else
  { pthread_mutex_unlock(&(lock_cs[type]));
  }
}


/*  From OpenSSL manual:

    id_function(void) is a function that returns a thread ID. It is not
    needed on Windows nor on platforms where getpid() returns a different
    ID for each thread (most notably Linux).

    As for pthreads_win32 version 2, the thread identifier is no longer
    integral, we are going to test this claim from the manual
*/

#ifndef __WINDOWS__
static unsigned long
pthreads_thread_id(void)
{ unsigned long ret;

  ret=(unsigned long)pthread_self();
  return(ret);
}
#endif


int
ssl_thread_setup(void)
{ int i;

  lock_cs = OPENSSL_malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
  lock_count = OPENSSL_malloc(CRYPTO_num_locks() * sizeof(long));
  for (i=0; i<CRYPTO_num_locks(); i++)
  { lock_count[i]=0;
    pthread_mutex_init(&(lock_cs[i]), NULL);
  }

  old_id_callback = CRYPTO_get_id_callback();
  old_locking_callback = CRYPTO_get_locking_callback();
#ifndef __WINDOWS__
  CRYPTO_set_id_callback(pthreads_thread_id);
#endif
  CRYPTO_set_locking_callback(pthreads_locking_callback);

  return TRUE;
}

#else /*_REENTRANT*/

int
ssl_thread_init(void)
{ return FALSE;
}

#endif /*_REENTRANT*/


int
ssl_lib_exit(void)
/*
 * One-time library exit calls
 */
{
#ifdef __SWI_PROLOG__
    nbio_cleanup();
#endif

/*
 * If the module is being unloaded, we should remove callbacks pointing to
 * our address space
 */
#ifdef _REENTRANT
#ifndef __WINDOWS__
  CRYPTO_set_id_callback(old_id_callback);
#endif
  CRYPTO_set_locking_callback(old_locking_callback);
#endif
    return 0;
}


/***********************************************************************
 * Warning, error and debug reporting
 ***********************************************************************/

void
ssl_msg(char *fmt, ...)
{
    va_list argpoint;

    va_start(argpoint, fmt);
	Svfprintf(Soutput, fmt, argpoint);
    va_end(argpoint);
}


void
ssl_err(char *fmt, ...)
{
    va_list argpoint;

    va_start(argpoint, fmt);
	Svfprintf(Serror, fmt, argpoint);
    va_end(argpoint);
}


int
ssl_set_debug(int level)
{ return nbio_debug(level);
}


void
ssl_deb(int level, char *fmt, ...)
{
#if DEBUG
    if ( nbio_debug(-1) >= level )
    { va_list argpoint;

      fprintf(stderr, "Debug: ");
      va_start(argpoint, fmt);
      Svfprintf(Serror, fmt, argpoint);
      va_end(argpoint);
    }
#endif
}

