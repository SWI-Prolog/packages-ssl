/*  Part of SWI-Prolog

    Author:        Jan van der Steen and Jan Wielemaker
    E-mail:        J.van.der.Steen@diff.nl and jan@swi-prolog.org
    WWW:           http://www.swi-prolog.org
    Copyright (c)  2004-2016, SWI-Prolog Foundation
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

#include <config.h>
#include <string.h>
#include <assert.h>
#include <stdarg.h>
#ifdef _REENTRANT
#include <pthread.h>
#endif

#include "ssllib.h"
#include <openssl/rand.h>

#ifdef __SWI_PROLOG__
#include <SWI-Stream.h>
#include <SWI-Prolog.h>

#ifdef __WINDOWS__
#include <windows.h>
#include <wincrypt.h>
#endif
#if defined(HAVE_SECURITY_SECURITY_H) && defined(HAVE_KSECCLASS) /*__APPLE__*/
#include <Security/Security.h>
#else
#undef HAVE_SECURITY_SECURITY_H
#endif
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


extern functor_t FUNCTOR_error2;
extern functor_t FUNCTOR_ssl_error4;


#include <openssl/rsa.h>

typedef enum
{ SSL_PL_OK
, SSL_PL_RETRY
, SSL_PL_ERROR
} SSL_PL_STATUS;

#define SSL_CERT_VERIFY_MORE 0

#ifndef DEBUG
#define DEBUG 1
#endif

static void free_X509_crl_list(X509_crl_list *list);
static X509_list *system_root_store = NULL;
static int system_root_store_fetched = FALSE;
static pthread_mutex_t root_store_lock = PTHREAD_MUTEX_INITIALIZER;

/*
 * Index of our config data in the SSL data
 */
static int ssl_idx;
static int ctx_idx;

/**
 * ssl_error_term(long ex) returns a Prolog term representing the SSL
 * error.  If there is already a pending exception, this is returned.
 *
 */
static int
ssl_error_term(long e)
{ term_t ex;
  char buffer[256];
  char* colon;
  char *component[5] = {NULL, "unknown", "unknown", "unknown", "unknown"};
  int n = 0;

  if ( (ex=PL_exception(0)) )
    return ex;					/* already pending exception */

  ERR_error_string_n(e, buffer, 256);

  /*
   * Disect the following error string:
   *
   * error:[error code]:[library name]:[function name]:[reason string]
   */
  if ( (ex=PL_new_term_ref()) )
  { for (colon = buffer, n = 0; n < 5 && colon != NULL; n++)
    { component[n] = colon;
      if ((colon = strchr(colon, ':')) == NULL) break;
      *colon++ = 0;
    }
    if ( PL_unify_term(ex,
		       PL_FUNCTOR, FUNCTOR_error2,
		       PL_FUNCTOR, FUNCTOR_ssl_error4,
		       PL_CHARS, component[1],
		       PL_CHARS, component[2],
		       PL_CHARS, component[3],
		       PL_CHARS, component[4],
		       PL_VARIABLE) )
    { return ex;
    }
  }

  return PL_exception(0);
}


int
raise_ssl_error(long e)
{ term_t ex;

  if ( (ex = ssl_error_term(e)) )
    return PL_raise_exception(ex);

  return FALSE;
}


/**
 * Raise syscall_error(id, string)
 * This should move to the kernel error system
 */
static term_t
syscall_error(const char *op, int e)
{ term_t ex;

  if ( (ex = PL_new_term_ref()) &&
       PL_unify_term(ex,
		     PL_FUNCTOR, FUNCTOR_error2,
		       PL_FUNCTOR, FUNCTOR_ssl_error4,
		         PL_CHARS, "syscall",
		         PL_CHARS, op,
		         PL_INT, e,
		         PL_CHARS, strerror(e),
		     PL_VARIABLE) )
    return ex;

  return PL_exception(0);
}

static term_t
unexpected_eof(PL_SSL_INSTANCE *instance)
{ term_t ex;

  if ( (ex = PL_new_term_ref()) &&
       PL_unify_term(ex,
		     PL_FUNCTOR, FUNCTOR_error2,
		       PL_FUNCTOR, FUNCTOR_ssl_error4,
		         PL_CHARS, "SSL_eof",
		         PL_CHARS, "ssl",
		         PL_CHARS, "negotiate",
		         PL_CHARS, "Unexpected end-of-file",
		     PL_VARIABLE) )

    return ex;

  return PL_exception(0);
}


/**
 * Inspect the error status.  If an error occurs we want to pass this to
 * the Prolog layer.  This is called from
 *
 *   - ssl_ssl_bio(), which is called from ssl_negotiate/5.  If an error
 *     occurs we must call PL_raise_exception() or another exception
 *     raising function.
 *   - ssl_read() and ssl_write().  If an error occurs, we must set this
 *     error on the filtered streams using Sseterr() or Sset_exception()
 */

typedef enum
{ STAT_NEGOTIATE,
  STAT_READ,
  STAT_WRITE
} status_role;

static SSL_PL_STATUS
ssl_inspect_status(PL_SSL_INSTANCE *instance, int ssl_ret, status_role role)
{ int code;
  int error;

  if ( ssl_ret > 0 )
    return SSL_PL_OK;

  code = SSL_get_error(instance->ssl, ssl_ret);

  switch (code)
  { /* I am not sure what to do here - specifically, I am not sure if our
       underlying BIO will block if there is not enough data to complete
       a handshake. If it will, we should never get these return values.
       If it wont, then we presumably need to simply try again which is
       why I am returning SSL_PL_RETRY
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

  error = ERR_get_error();

  if ( code == SSL_ERROR_SYSCALL && error == 0 )
  { if ( ssl_ret == 0 )
    { switch(role)
      { case STAT_NEGOTIATE:
	  PL_raise_exception(unexpected_eof(instance));
	  break;
	case STAT_READ:
	  Sseterr(instance->dread, SIO_FERR, "SSL: unexpected end-of-file");
	  break;
	case STAT_WRITE:
	  Sseterr(instance->dwrite, SIO_FERR, "SSL: unexpected end-of-file");
	  break;
      }
      return SSL_PL_ERROR;
    } else if ( ssl_ret == -1 )
    { if ( role == STAT_NEGOTIATE )
	PL_raise_exception(syscall_error("ssl_negotiate", errno));
      return SSL_PL_ERROR;
    }
  }

  switch(role)
  { case STAT_NEGOTIATE:
      raise_ssl_error(error);
      break;
    case STAT_READ:
      Sset_exception(instance->dread, ssl_error_term(error));
      break;
    case STAT_WRITE:
      Sset_exception(instance->dwrite, ssl_error_term(error));
      break;
  }

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

static RSA *
ssl_rsadup(const RSA *rsa)
{
    RSA *c = RSA_new();

    if ( c != NULL ) {
      if ( !(c->n    = BN_dup(rsa->n)) ||
	   !(c->e    = BN_dup(rsa->e)) ||
	   !(c->d    = BN_dup(rsa->d)) ||
	   !(c->p    = BN_dup(rsa->p)) ||
	   !(c->q    = BN_dup(rsa->q)) ||
	   !(c->dmp1 = BN_dup(rsa->dmp1)) ||
	   !(c->dmq1 = BN_dup(rsa->dmq1)) ||
	   !(c->iqmp = BN_dup(rsa->iqmp)) ) {
	RSA_free(c);	/* assumes RSA_free() will not call BN_free() */
	c = NULL;	/* for NULL components or BN_free(NULL) is valid */
      }
    }

    return c;
}

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
        new->closeparent		= FALSE;
        new->atom		        = 0;

        new->pl_ssl_peer_cert           = NULL;
        new->pl_ssl_ctx                 = NULL;
        new->pl_ssl_idx                 = -1;
        new->pl_ssl_password            = NULL;

        new->use_system_cacert          = FALSE;
        new->pl_ssl_host                = NULL;

        new->pl_ssl_cacert              = NULL;
        new->pl_ssl_cert_required       = FALSE;
        new->pl_ssl_certf               = NULL;
        new->pl_ssl_certificate         = NULL;
        new->pl_ssl_keyf                = NULL;
        new->pl_ssl_key                 = NULL;
        new->pl_ssl_cipher_list         = NULL;
        new->pl_ssl_ecdh_curve          = NULL;
        new->pl_ssl_crl_list            = NULL;
        new->pl_ssl_peer_cert_required  = FALSE;
        new->pl_ssl_crl_required        = FALSE;
        new->pl_ssl_cb_cert_verify      = NULL;
        new->pl_ssl_cb_cert_verify_data = NULL;
        new->pl_ssl_cb_pem_passwd       = NULL;
        new->pl_ssl_cb_pem_passwd_data  = NULL;
#ifndef HAVE_X509_CHECK_HOST
        new->hostname_check_status      = 0;
#endif
	new->magic		        = SSL_CONFIG_MAGIC;
    }
    ssl_deb(1, "Allocated config structure\n");

    return new;
}

/*
 * Free resources allocated to store the state and config parameters.
 */
static void
ssl_free(PL_SSL *config)
{ if ( config )
  { assert(config->magic == SSL_CONFIG_MAGIC);
    config->magic = 0;
    free(config->pl_ssl_host);
    free(config->pl_ssl_cacert);
    free(config->pl_ssl_certf);
    free(config->pl_ssl_certificate);
    free(config->pl_ssl_keyf);
    free(config->pl_ssl_cipher_list);
    free(config->pl_ssl_ecdh_curve);
    free_X509_crl_list(config->pl_ssl_crl_list);
    free(config->pl_ssl_password);
    if ( config->pl_ssl_peer_cert )
      X509_free(config->pl_ssl_peer_cert);
    free(config);
    ssl_deb(1, "Released config structure\n");
  } else
  { ssl_deb(1, "No config structure to release\n");
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

int
ssl_set_use_system_cacert(PL_SSL *config, int use_system_cacert)
/*
 * Store that we want to use the system certificate authority in config storage
 */
{
  config->use_system_cacert = use_system_cacert;
  return config->use_system_cacert;
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
ssl_set_certificate(PL_SSL *config, const char *cert)
/*
 * Store certificate in config storage
 */
{
    if (cert) {
        if (config->pl_ssl_certificate) free(config->pl_ssl_certificate);
        config->pl_ssl_certificate = ssl_strdup(cert);
    }
    return config->pl_ssl_certificate;
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

RSA  *
ssl_set_key(PL_SSL *config, const RSA *key)
/*
 * Store private key in config storage
 */
{
    if (key) {
        if (config->pl_ssl_key) RSA_free(config->pl_ssl_key);
        config->pl_ssl_key = ssl_rsadup(key);
    }
    return config->pl_ssl_key;
}

X509_crl_list *
ssl_set_crl_list(PL_SSL *config, X509_crl_list *crl)
/*
 * Store CRL location in config storage
 */
{
    if (crl)
    { if (config->pl_ssl_crl_list)
      { free_X509_crl_list(config->pl_ssl_crl_list);
      }
      config->pl_ssl_crl_list = crl;
    }
    return config->pl_ssl_crl_list;
}

char *
ssl_set_cipher_list(PL_SSL *config, const char *cipher_list)
{ if ( cipher_list )
  { if ( config->pl_ssl_cipher_list )
      free(config->pl_ssl_cipher_list);
    config->pl_ssl_cipher_list = ssl_strdup(cipher_list);
  }

  return config->pl_ssl_cipher_list;
}

char *
ssl_set_ecdh_curve(PL_SSL *config, const char *ecdh_curve)
{ if ( ecdh_curve )
  { if ( config->pl_ssl_ecdh_curve )
      free(config->pl_ssl_ecdh_curve);
    config->pl_ssl_ecdh_curve = ssl_strdup(ecdh_curve);
  }

  return config->pl_ssl_ecdh_curve;
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

BOOL
ssl_set_cert(PL_SSL *config, BOOL required)
/*
 * Do we require our certificate
 */
{
    return config->pl_ssl_cert_required = required;
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
ssl_set_crl_required(PL_SSL *config, BOOL required)
/*
 * Do we require the CRL to be checked if listed on the certificate
 */
{
    return config->pl_ssl_crl_required = required;
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
                                        , int
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
    ssl_deb(1, "      Certificate preverified %sok\n",
	    preverify_ok ? "" : "NOT ");
#ifndef HAVE_X509_CHECK_HOST
    /* If OpenSSL does not have X509_check_host() then the hostname has not yet been verified.
       Note that we only want to check the hostname of the FIRST certificate. There appears to be no easy way of
       telling which certificate we are up to. To try and manage this, state about hostname verification is stored
       in the PL_SSL object if X509_check_host() is not available.

       We want to call the hook (if present - if not, we want to reject the whole certificate chain!) with this error
       and then proceed to the next error (if there is one). This means that behaviour will be consistent after
       upgrading to OpenSSL 1.0.2
    */
    if ( config->hostname_check_status == 0 && config->pl_ssl_role == PL_SSL_CLIENT ) /* Not yet checked, and is a client - do not check for server */
    {
      /* This is a vastly simplified version. All we do is:
         1) For each alt subject name: If it is the same length as the hostname and strcmp() matches, then PASS
         2)                          : If it begins "*." and the hostname contains at least one ., and strcmp()
                                       matches from the first . in both expressions, AND the SAN contains no embedded
                                       NULLs, then PASS.
         3) Get the subject name. If it is the same length as the hostname and strcmp() matches, then PASS
         4) Otherwise, FAIL.
      */
      int i;
      X509 *cert = ctx->cert;
      STACK_OF(GENERAL_NAME) *alt_names = X509_get_ext_d2i((X509 *)cert, NID_subject_alt_name, NULL, NULL);
      int alt_names_count = 0;

      /* First, set status to 1 (invalid) */
      config->hostname_check_status = 1;
      if ( config->pl_ssl_host != NULL)
      { if (alt_names != NULL)
        { alt_names_count = sk_GENERAL_NAME_num(alt_names);
          for (i = 0; i < alt_names_count && config->hostname_check_status != 2; i++)
          { const GENERAL_NAME *name = sk_GENERAL_NAME_value(alt_names, i);
            /* We are only interested in DNS names. We may also want to do IP addresses in future, by extending
               the type of config->pl_ssl_host
            */
            if (name->type == GEN_DNS)
            { const char* hostname = (const char*)ASN1_STRING_data(name->d.dNSName);
              size_t hostlen = ASN1_STRING_length(name->d.dNSName);
              if (hostlen == strlen(config->pl_ssl_host) &&
                  strcmp(config->pl_ssl_host, hostname) == 0)
              { config->hostname_check_status = 2;
                ssl_deb(3, "Host that matches found in SAN %d: %s\n", i, ASN1_STRING_data(name->d.dNSName));
              } else if (hostlen > 2 && hostname[0] == '*' && hostname[1] == '.' && strlen(hostname) == hostlen)
              { char* subdomain = strchr(config->pl_ssl_host, '.');
                if (subdomain != NULL && strcmp(&hostname[1], subdomain) == 0)
                { config->hostname_check_status = 2;
                  ssl_deb(3, "Host that matches with wildcard found in SAN %d: %s\n", i, hostname);
                }
              }
              else
                ssl_deb(3, "Host does not match SAN %d: %s\n", i, ASN1_STRING_data(name->d.dNSName));
            }
          }
        }
        else
          ssl_deb(3, "Certificate has no SANs\n");


        /* If that didnt work, try the subject name itself. Naturally this has a completely different API */
        if ( config->hostname_check_status == 1 )
        { X509_NAME_ENTRY *common_name_entry;
          X509_NAME* subject_name = X509_get_subject_name((X509 *)cert);
          int common_name_index = X509_NAME_get_index_by_NID(subject_name, NID_commonName, -1);
          if (common_name_index != -1)
          { common_name_entry = X509_NAME_get_entry(subject_name, common_name_index);
            if (common_name_entry != NULL)
            { ASN1_STRING *common_name_asn1 = X509_NAME_ENTRY_get_data(common_name_entry);
              if (common_name_asn1 != NULL)
              { if (ASN1_STRING_length(common_name_asn1) == strlen(config->pl_ssl_host) &&
                    strcmp(config->pl_ssl_host, (const char*)ASN1_STRING_data(common_name_asn1)) == 0)
                { config->hostname_check_status = 2;
                  ssl_deb(3, "Hostname in SN matches: %s\n", ASN1_STRING_data(common_name_asn1));
                }
                else
                  ssl_deb(3, "Hostname in SN does not match: %s vs %s\n", ASN1_STRING_data(common_name_asn1), config->pl_ssl_host);
              }
            }
          }
        }
      }
      if ( config->hostname_check_status == 1 )
      { ssl_deb(3, "Hostname could not be verified!\n");
        if ( config->pl_ssl_cb_cert_verify_data != NULL )
        { X509 *cert = X509_STORE_CTX_get_current_cert(ctx);
          preverify_ok = ((config->pl_ssl_cb_cert_verify)(config, cert, ctx, "hostname_mismatch", 0) != 0);
        }
        else
          /* Reject the whole chain if the hostname verification fails and there is no hook to override it */
          preverify_ok = 0;
      }
    }
#endif

    if ( !preverify_ok || config->pl_ssl_cb_cert_verify_data != NULL ) {
        X509 *cert = NULL;
        const char *error;
        int err;
        int error_unknown = 0;
        /*
         * Get certificate
         */
        cert = X509_STORE_CTX_get_current_cert(ctx);


        /*
         * Get error specification
         */
	if ( preverify_ok )
	{ error = "verified";
	} else
	{ err   = X509_STORE_CTX_get_error(ctx);
          switch(err)
          {
          case X509_V_ERR_CERT_UNTRUSTED:
            error = "not_trusted";
            break;
          case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
          case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
          case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
            error = "unknown_issuer";
            break;
          case X509_V_ERR_UNABLE_TO_GET_CRL:
            error = "unknown_crl";
            break;
          case X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE:
          case X509_V_ERR_CRL_SIGNATURE_FAILURE:
            error = "bad_crl_signature";
            break;
          case X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY:
            error = "bad_issuer_key";
            break;
          case X509_V_ERR_CERT_SIGNATURE_FAILURE:
          case X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE:
            error = "bad_signature";
            break;
          case X509_V_ERR_CERT_NOT_YET_VALID:
            error = "not_yet_valid";
            break;
          case X509_V_ERR_CERT_HAS_EXPIRED:
            error = "expired";
            break;
          case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
          case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
          case X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD:
          case X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD:
            error = "bad_time";
            break;
          case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
          case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
            error = "self_signed_cert";
            break;
          case X509_V_ERR_CERT_REVOKED:
            error = "revoked";
            break;
          case X509_V_ERR_INVALID_CA:
            error = "invalid_ca";
            break;
          case X509_V_ERR_KEYUSAGE_NO_CRL_SIGN:
          case X509_V_ERR_INVALID_PURPOSE:
            error = "bad_certificate_use";
            break;
#ifdef X509_V_ERR_HOSTNAME_MISMATCH
          case X509_V_ERR_HOSTNAME_MISMATCH:
            error = "hostname_mismatch";
            break;
#endif
          default:
            error_unknown = 1;
            error = X509_verify_cert_error_string(err);
          }
	}

        if (config->pl_ssl_cb_cert_verify) {
          preverify_ok = ((config->pl_ssl_cb_cert_verify)(config, cert, ctx, error, error_unknown) != 0);
        } else {
            char  subject[256];
            char  issuer [256];
            int   depth;

            depth = X509_STORE_CTX_get_error_depth(ctx);
            X509_NAME_oneline(X509_get_subject_name(cert),
			      subject, sizeof(subject));
            X509_NAME_oneline(X509_get_issuer_name (cert),
			      issuer, sizeof(issuer));
            ssl_deb(1,   "depth:%d\n", depth);
            ssl_deb(1,   "error:%s\n", error);
            ssl_deb(1, "subject:%s\n", subject);
            ssl_deb(1,  "issuer:%s\n", issuer);
        }
    }
    ssl_deb(1, " ---- EXIT Handling certificate verification (%saccepted)\n",
	    preverify_ok ? "" : "NOT ");

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

void
ssl_set_method_options(PL_SSL *config, int options)
/*
 * Disable the given options
 */
{   SSL_CTX_set_options(config->pl_ssl_ctx, options);
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

        if (instance->swrite != NULL) {
           /* Indicate we are no longer filtering the stream */
           Sset_filter(instance->swrite, NULL);
           /* Close the stream if requested */
	   if (instance->config->closeparent)
	     Sclose(instance->swrite);
        }

        if (instance->sread != NULL) {
           /* Indicate we are no longer filtering the stream */
           Sset_filter(instance->sread, NULL);
           /* Close the stream if requested */
	   if (instance->config->closeparent)
	     Sclose(instance->sread);
        }
        /* Decrease reference count on the context */
        ssl_deb(4, "Decreasing atom count on %d\n", instance->config->atom);
        PL_unregister_atom(instance->config->atom);

        free(instance);
    }
    ERR_free_strings();

    ssl_deb(1, "Controlled close\n");
    return ret;
}

/*
 * Clean up all allocated resources.
 */
void
ssl_exit(PL_SSL *config)
{ if ( config )
  { if ( config->pl_ssl_role == PL_SSL_SERVER && config->sock >= 0 )
    { /* If the socket has been stored, then we ought to close it
         if the SSL is being closed
         FIXME: this beast is owned by Prolog now, no?
      */
      closesocket(config->sock);
      config->sock = -1;
    }

    if (config->pl_ssl_ctx)
    { ssl_deb(1, "Calling SSL_CTX_free()\n");
      SSL_CTX_free(config->pl_ssl_ctx);	/* doesn't call free hook? */
    } else
    { ssl_deb(1, "config without CTX encountered\n");
    }
  }

  ssl_deb(1, "Controlled exit\n");
}


X509 *
ssl_peer_certificate(PL_SSL_INSTANCE *instance)
{ if ( !instance->config->pl_ssl_peer_cert )
    instance->config->pl_ssl_peer_cert = SSL_get_peer_certificate(instance->ssl);

  return instance->config->pl_ssl_peer_cert;
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
ssl_init(PL_SSL_ROLE role, const SSL_METHOD *ssl_method)
/*
 * Allocate the holder for our parameters which will specify the
 * configuration parameters and any other statefull parameter.
 * Load the OpenSSL error_strings for error reporting.
 * Define method for SSL layer depending on whether we're server or client.
 * Create SSL context.
 */
{
    PL_SSL           * config    = NULL;
    SSL_CTX          *ssl_ctx    = NULL;


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


/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
ssl_system_verify_locations() adds trusted  root   certificates  from OS
dependent locations if cacert_file(system(root_certificates)) is passed.

The code is written after this StackOverflow message
http://stackoverflow.com/questions/10095676/openssl-reasonable-default-for-trusted-ca-certificates
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */

static void
free_509_list(X509_list *list)
{ X509_list *next;

  for(; list; list=next)
  { next = list->next;
    X509_free(list->cert);
    free(list);
  }
}


static int
list_add_X509(X509 *cert, X509_list **head, X509_list **tail)
{ X509_list *cell = malloc(sizeof(*cell));

  if ( cell )
  { cell->cert = cert;
    cell->next = NULL;
    if ( *head )
    { (*tail)->next = cell;
      (*tail) = cell;
    } else
    { *head = *tail = cell;
    }

    return TRUE;
  }

  return FALSE;
}

int
list_add_X509_crl(X509_CRL *crl, X509_crl_list **head, X509_crl_list **tail)
{ X509_crl_list *cell = malloc(sizeof(*cell));

  if ( cell )
  { cell->crl = crl;
    cell->next = NULL;
    if ( *head )
    { (*tail)->next = cell;
      (*tail) = cell;
    } else
    { *head = *tail = cell;
    }

    return TRUE;
  }

  return FALSE;
}

static void
free_X509_crl_list(X509_crl_list *list)
{ X509_crl_list *next;

  for(; list; list=next)
  { next = list->next;
    X509_CRL_free(list->crl);
    free(list);
  }
}


/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
Extract   the   system   certificate   file   from   the   Prolog   flag
system_cacert_filename
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */

static const char *
system_cacert_filename(void)
{ fid_t fid;
  static char *cacert_filename = NULL;

  if ( !cacert_filename )
  { if ( (fid = PL_open_foreign_frame()) )
    { term_t av = PL_new_term_refs(2);
      PL_put_atom_chars(av+0, "system_cacert_filename");

      if ( PL_call_predicate(NULL, PL_Q_NORMAL,
			     PL_predicate("current_prolog_flag", 2, "system"),
			     av) )
      { char *s;

	if ( PL_get_atom_chars(av+1, &s) )
	{ char *old = cacert_filename;
	  cacert_filename = strdup(s);
	  free(old);
	}
      }

      PL_close_foreign_frame(fid);
    }
  }

  return cacert_filename;
}



static X509_list *
ssl_system_verify_locations(void)
{ X509_list *head=NULL, *tail=NULL;
  int ok = TRUE;

#ifdef __WINDOWS__
  HCERTSTORE hSystemStore;

  if ( (hSystemStore = CertOpenSystemStore(0, "ROOT")) )
  { PCCERT_CONTEXT pCertCtx = NULL;

    while( (pCertCtx=CertEnumCertificatesInStore(hSystemStore, pCertCtx)) )
    { const unsigned char *ce = (unsigned char*)pCertCtx->pbCertEncoded;

      X509 *cert = d2i_X509(NULL, &ce, (int)pCertCtx->cbCertEncoded);
      if ( cert )
      { if ( !list_add_X509(cert, &head, &tail) )
	{ ok = FALSE;
	  break;
	}
      }
    }

    CertCloseStore(hSystemStore, 0);
  }
#elif defined(HAVE_SECURITY_SECURITY_H)	/* __APPLE__ */
  SecKeychainRef keychain = NULL;
  OSStatus status;
  status = SecKeychainOpen("/System/Library/Keychains/SystemRootCertificates.keychain", &keychain);
  if ( status == errSecSuccess )
  { CFDictionaryRef query = NULL;
    CFArrayRef certs = NULL;
    CFArrayRef keychainSingleton = CFArrayCreate(NULL, (const void **)&keychain, 1, &kCFTypeArrayCallBacks);
    const void *keys[] =   {kSecClass,            kSecMatchSearchList,  kSecMatchTrustedOnly, kSecReturnRef,  kSecMatchLimit,    kSecMatchValidOnDate};
    const void *values[] = {kSecClassCertificate, keychainSingleton,    kCFBooleanTrue,       kCFBooleanTrue, kSecMatchLimitAll, kCFNull};
    CFIndex i;
    CFIndex count;
    query = CFDictionaryCreate(NULL,
                               keys,
                               values,
                               6,
                               &kCFTypeDictionaryKeyCallBacks,
                               &kCFTypeDictionaryValueCallBacks);
    status = SecItemCopyMatching(query, (CFTypeRef *)&certs);
    if (status == errSecSuccess)
    { count = CFArrayGetCount(certs);
      for (i = 0; i < count; i++)
      { const void *cert = CFArrayGetValueAtIndex(certs, i);
        CFDataRef cert_data = NULL;
        const unsigned char *der;
        unsigned long cert_data_length;
        X509 *x509 = NULL;

        cert_data = SecCertificateCopyData((SecCertificateRef)cert);
        der = CFDataGetBytePtr(cert_data);
        cert_data_length = CFDataGetLength(cert_data);
        x509 = d2i_X509(NULL, &der, cert_data_length);
        CFRelease(cert_data);
        if ( x509 )
        { if ( !list_add_X509(x509, &head, &tail) )
	  { ok = FALSE;
	    break;
	  }
        }
      }
      CFRelease(certs);
    }
    CFRelease(query);
    CFRelease(keychainSingleton);
    CFRelease(keychain);
  }
#else
{ const	char *cacert_filename;
  if ( (cacert_filename = system_cacert_filename()) )
  { X509 *cert = NULL;
    FILE *cafile = fopen(cacert_filename, "rb");

    ssl_deb(1, "cacert_filename = %s\n", cacert_filename);

    if ( cafile != NULL )
    { while ((cert = PEM_read_X509(cafile, NULL, NULL, NULL)) != NULL)
      { if ( !list_add_X509(cert, &head, &tail) )
	{ ok = FALSE;
	  break;
	}
      }
      fclose(cafile);
    }
  }
}
#endif

  if ( ok )
  { return head;
  } else
  { free_509_list(head);
    return NULL;				/* no memory */
  }
}


X509_list *
system_root_certificates(void)
{ pthread_mutex_lock(&root_store_lock);
  if ( !system_root_store_fetched )
  { system_root_store_fetched = TRUE;
    system_root_store = ssl_system_verify_locations();
  }
  pthread_mutex_unlock(&root_store_lock);

  return system_root_store;
}


static void
ssl_init_verify_locations(PL_SSL *config)
{ if ( config->use_system_cacert )
  { X509_list *certs = system_root_certificates();

    if ( certs )
    { X509_STORE *store = X509_STORE_new();

      if ( store )
      { X509_list *head;

	for(head = certs; head; head=head->next)
	{ X509_STORE_add_cert(store, head->cert);
	}
	SSL_CTX_set_cert_store(config->pl_ssl_ctx, store);
      }
    }
    ssl_deb(1, "System certificate authority(s) installed\n");
  } else if ( config->pl_ssl_cacert )
  { SSL_CTX_load_verify_locations(config->pl_ssl_ctx,
                                  config->pl_ssl_cacert,
                                  NULL);
    ssl_deb(1, "certificate authority(s) installed\n");
  }
  if ( config->pl_ssl_crl_list )
  { X509_STORE *store = SSL_CTX_get_cert_store(config->pl_ssl_ctx);
    X509_crl_list* head;
    for (head = config->pl_ssl_crl_list; head; head=head->next)
    { X509_STORE_add_crl(store, head->crl);
    /*
      Sdprintf("Added a CRL...\n");
      BIO * bio = BIO_new_fp(stdout, BIO_NOCLOSE);
      X509_CRL_print(bio, head->crl);
      BIO_free(bio);
    */
    }
  }

}

/* The following keys were generated with:
   $  openssl dhparam -C 2048
   (OpenSSL 1.0.1k 8 Jan 2015)
*/

#ifndef HEADER_DH_H
#include <openssl/dh.h>
#endif
DH *get_dh2048()
	{
	static unsigned char dh2048_p[]={
		0xF9,0xE7,0xCF,0x81,0x2D,0xA6,0xA8,0x54,0x72,0xB3,0x6E,0x79,
		0x71,0x10,0x3C,0x46,0x8F,0xFF,0x79,0xDE,0xEA,0x2D,0xFD,0xD8,
		0x89,0xEB,0x17,0x0A,0x36,0x60,0x36,0x5C,0xB8,0xD7,0x57,0xB6,
		0x32,0x8C,0x05,0x35,0x29,0x66,0x11,0x74,0x57,0xFB,0x94,0xD9,
		0xF0,0x5E,0x7C,0x52,0xE5,0x15,0x88,0x41,0x80,0x3C,0x57,0x54,
		0x62,0xF3,0x5B,0x28,0x1C,0x3B,0x84,0x24,0x12,0xC7,0x9F,0x9B,
		0x07,0xE1,0xE8,0x42,0x00,0x28,0xD5,0x00,0xD7,0x59,0xC2,0x4B,
		0x4D,0xE9,0xAD,0xB2,0xBE,0x58,0xC2,0x95,0xB4,0xD0,0x27,0x80,
		0x9A,0x45,0x85,0xF2,0x6C,0xB1,0x99,0x40,0xB1,0x2E,0x57,0xB7,
		0xAF,0xAB,0xC2,0x47,0xC1,0xD1,0xA6,0x1D,0x98,0x0C,0x99,0x7C,
		0x13,0xDD,0x95,0xA4,0x8C,0xB0,0xBA,0x28,0xF3,0x2C,0xA7,0xAE,
		0x41,0x58,0x34,0x99,0xD7,0x2D,0x4C,0xB4,0x0B,0xC0,0xDE,0xAC,
		0x34,0xDD,0x63,0x8A,0x7E,0x51,0x0A,0x4A,0xB8,0x95,0xF2,0x0E,
		0xC9,0xF9,0xF5,0x23,0x99,0xF7,0xE0,0xC1,0x6B,0xE6,0xBD,0x8A,
		0xD5,0x3E,0xF8,0x87,0x56,0x9B,0xD0,0x00,0x5A,0x9C,0x60,0x56,
		0xFE,0x74,0x8D,0x42,0x4A,0x9E,0x6A,0xAC,0x74,0xE6,0x7D,0x12,
		0x66,0xCC,0x36,0x30,0x1B,0xC4,0xD7,0xBC,0x19,0xE0,0xAF,0x2B,
		0xE3,0x72,0x13,0x18,0xE7,0x29,0x89,0x82,0xC9,0xE4,0x30,0x1E,
		0x4F,0xE8,0xB0,0xBE,0x22,0x73,0x69,0x94,0x44,0x86,0x96,0xF7,
		0x77,0xD8,0xDB,0x68,0xB2,0x4E,0xFF,0xBA,0x35,0x69,0xD4,0x65,
		0xF3,0xAE,0xAB,0x88,0x2F,0x7A,0xD7,0x5E,0x98,0xFC,0xF5,0xCA,
		0xD4,0x43,0xB4,0xAB,
		};
	static unsigned char dh2048_g[]={
		0x02,
		};
	DH *dh;

	if ((dh=DH_new()) == NULL) return(NULL);
	dh->p=BN_bin2bn(dh2048_p,sizeof(dh2048_p),NULL);
	dh->g=BN_bin2bn(dh2048_g,sizeof(dh2048_g),NULL);
	if ((dh->p == NULL) || (dh->g == NULL))
		{ DH_free(dh); return(NULL); }
	return(dh);
	}

int
ssl_config(PL_SSL *config, term_t options)
/*
 * Initialize various SSL layer parameters using the supplied
 * config parameters.
 */
{ static DH *dh_2048 = NULL;

#ifndef OPENSSL_NO_EC
  EC_KEY *ecdh;
  int nid;
#endif

  ssl_init_verify_locations(config);

  SSL_CTX_set_default_passwd_cb_userdata(config->pl_ssl_ctx, config);
  SSL_CTX_set_default_passwd_cb(config->pl_ssl_ctx, ssl_cb_pem_passwd);
  ssl_deb(1, "password handler installed\n");

  if ( config->pl_ssl_cert_required ||
       ( ( config->pl_ssl_certf || config->pl_ssl_certificate ) &&
         ( config->pl_ssl_keyf || config->pl_ssl_key ) ) )
  { if ( config->pl_ssl_certf == NULL &&
         config->pl_ssl_certificate == NULL )
      return PL_existence_error("certificate", options);
    if ( config->pl_ssl_keyf  == NULL &&
         config->pl_ssl_key   == NULL )
      return PL_existence_error("key_file", options);

    if ( config->pl_ssl_certf &&
         SSL_CTX_use_certificate_chain_file(config->pl_ssl_ctx,
                                            config->pl_ssl_certf) <= 0 )
      return raise_ssl_error(ERR_get_error());

    if ( config->pl_ssl_certificate )
    { char* cert = config->pl_ssl_certificate;
      X509* certX509;

      BIO* bio = BIO_new(BIO_s_mem());

      if ( !bio )
        return PL_resource_error("memory");

      BIO_write(bio, cert, strlen(cert));
      certX509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);
      if ( !certX509 )
        return raise_ssl_error(ERR_get_error());

      if ( SSL_CTX_use_certificate(config->pl_ssl_ctx, certX509) <= 0 )
        return raise_ssl_error(ERR_get_error());
      X509_free(certX509);

      while ( (certX509 = PEM_read_bio_X509(bio, NULL, NULL, NULL)) != NULL )
      { if ( SSL_CTX_add_extra_chain_cert(config->pl_ssl_ctx, certX509) <= 0 )
          return raise_ssl_error(ERR_get_error());
        X509_free(certX509);
      }

      BIO_free(bio);
    }

    if ( config->pl_ssl_keyf &&
         SSL_CTX_use_PrivateKey_file(config->pl_ssl_ctx,
				     config->pl_ssl_keyf,
				     SSL_FILETYPE_PEM) <= 0 )
      return raise_ssl_error(ERR_get_error());

    if ( config->pl_ssl_key &&
         SSL_CTX_use_RSAPrivateKey(config->pl_ssl_ctx, config->pl_ssl_key) <= 0 )
      return raise_ssl_error(ERR_get_error());

    if ( SSL_CTX_check_private_key(config->pl_ssl_ctx) <= 0 )
    { ssl_deb(1, "Private key does not match certificate public key\n");
      return raise_ssl_error(ERR_get_error());
    }
    ssl_deb(1, "certificate installed successfully\n");
  }

  if ( !dh_2048 ) dh_2048 = get_dh2048();
  SSL_CTX_set_tmp_dh(config->pl_ssl_ctx, dh_2048);

#ifndef OPENSSL_NO_EC
  nid = OBJ_sn2nid(config->pl_ssl_ecdh_curve ? config->pl_ssl_ecdh_curve
					     : "prime256v1");
  if ( !(ecdh = EC_KEY_new_by_curve_name(nid)) )
    return raise_ssl_error(ERR_get_error());
  if ( !SSL_CTX_set_tmp_ecdh(config->pl_ssl_ctx, ecdh) )
    return raise_ssl_error(ERR_get_error());
  EC_KEY_free(ecdh);		/* Safe because of reference counts */
#endif

  if ( config->pl_ssl_cipher_list &&
       !SSL_CTX_set_cipher_list(config->pl_ssl_ctx, config->pl_ssl_cipher_list))
    return raise_ssl_error(ERR_get_error());

  (void) SSL_CTX_set_verify(config->pl_ssl_ctx,
			    config->pl_ssl_peer_cert_required ?
				SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT :
				SSL_VERIFY_NONE,
			    ssl_cb_cert_verify);
  ssl_deb(1, "installed certificate verification handler\n");

  return TRUE;
}


PL_SSL_INSTANCE *
ssl_instance_new(PL_SSL *config, IOSTREAM* sread, IOSTREAM* swrite)
{ PL_SSL_INSTANCE *new = NULL;

  if ((new = malloc(sizeof(PL_SSL_INSTANCE))) != NULL)
  { memset(new, 0, sizeof(*new));
    new->config = config;
    new->sock   = -1;
    new->sread  = sread;
    new->swrite	= swrite;
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
 * Establish an SSL session using the given read and write streams
 * and the role
 */
int
ssl_ssl_bio(PL_SSL *config, IOSTREAM* sread, IOSTREAM* swrite,
	    PL_SSL_INSTANCE** instancep)
{ BIO* rbio = NULL;
  BIO* wbio = NULL;
  PL_SSL_INSTANCE *instance;

  if ( !(instance=ssl_instance_new(config, sread, swrite)) )
    return PL_resource_error("memory");

  rbio = BIO_new(&bio_read_functions);
  BIO_set_ex_data(rbio, 0, sread);
  wbio = BIO_new(&bio_write_functions);
  BIO_set_ex_data(wbio, 0, swrite);

  if ( config->pl_ssl_crl_required )
  { X509_STORE_set_flags(SSL_CTX_get_cert_store(config->pl_ssl_ctx),
			 X509_V_FLAG_CRL_CHECK|X509_V_FLAG_CRL_CHECK_ALL);
  }


  if ( !(instance->ssl = SSL_new(config->pl_ssl_ctx)) )
  { free(instance);
    return raise_ssl_error(ERR_get_error());
  }

  if ( config->pl_ssl_role == PL_SSL_CLIENT )
  { if ( config->pl_ssl_host )
      SSL_set_tlsext_host_name(instance->ssl, config->pl_ssl_host);
#ifdef HAVE_X509_CHECK_HOST
    X509_VERIFY_PARAM *param = SSL_get0_param(instance->ssl);
    /* This could in theory be user-configurable. The documentation at
       https://wiki.openssl.org/index.php/Manual:X509_check_host(3)
       says that the flag is 'usually 0', however
    */
 /* X509_VERIFY_PARAM_set_hostflags(param,
				    X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
 */
    X509_VERIFY_PARAM_set_hostflags(param, 0);
    X509_VERIFY_PARAM_set1_host(param, config->pl_ssl_host, 0);
#endif
  }

  SSL_set_session_id_context(instance->ssl, (unsigned char*)"SWI-Prolog", 10);
  ssl_deb(1, "allocated ssl layer\n");

  SSL_set_ex_data(instance->ssl, ssl_idx, config);
  SSL_set_bio(instance->ssl, rbio, wbio); /* No return value */
  ssl_deb(1, "allocated ssl fd\n");

  for(;;)
  { int ssl_ret;

    ssl_deb(1, "Negotiating %s ...\n",
	    config->pl_ssl_role == PL_SSL_SERVER ? "server" : "client");
    ssl_ret = (config->pl_ssl_role == PL_SSL_SERVER ?
		 SSL_accept(instance->ssl) :
		 SSL_connect(instance->ssl));

    switch( ssl_inspect_status(instance, ssl_ret, STAT_NEGOTIATE) )
    { case SSL_PL_OK:
	ssl_deb(1, "established ssl connection\n");
        *instancep = instance;
        return TRUE;
      case SSL_PL_RETRY:
	ssl_deb(1, "retry ssl connection\n");
	continue;
      case SSL_PL_ERROR:
	ssl_deb(1, "failed ssl connection\n");
	SSL_free(instance->ssl);
        free(instance);
	return FALSE;
    }
  }
}

/*
 * Perform read on SSL session
 */
ssize_t
ssl_read(void *handle, char *buf, size_t size)
{ PL_SSL_INSTANCE *instance = handle;
  SSL *ssl = instance->ssl;

  assert(ssl != NULL);

  for(;;)
  { int rbytes = SSL_read(ssl, buf, size);

    if ( rbytes == 0 ) /* EOF - error, but we handle in prolog */
      return 0;

    switch(ssl_inspect_status(instance, rbytes, STAT_READ))
    { case SSL_PL_OK:
	return rbytes;
      case SSL_PL_RETRY:
	continue;
      case SSL_PL_ERROR:
	return -1;
    }
  }
}

/*
 * Perform write on SSL session
 */
ssize_t
ssl_write(void *handle, char *buf, size_t size)
{ PL_SSL_INSTANCE *instance = handle;
  SSL *ssl = instance->ssl;

  assert(ssl != NULL);

  for(;;)
  { int wbytes = SSL_write(ssl, buf, size);

    if ( wbytes == 0 ) /* EOF - error, but we handle in prolog */
      return 0;

    switch(ssl_inspect_status(instance, wbytes, STAT_WRITE))
    { case SSL_PL_OK:
	return wbytes;
      case SSL_PL_RETRY:
	continue;
      case SSL_PL_ERROR:
	return -1;
    }
  }
}


		 /*******************************
		 *	      THREADING		*
		 *******************************/

/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
OpenSSL is not thread-safe, unless  you   install  the hooks below. This
code is based on mttest.c distributed with the OpenSSL library.
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */

#ifdef _REENTRANT

static pthread_mutex_t *lock_cs;
static long *lock_count;
static void (*old_locking_callback)(int, int, const char*, int) = NULL;
#ifdef HAVE_CRYPTO_THREADID_GET_CALLBACK
static void (*old_id_callback)(CRYPTO_THREADID*) = NULL;
#else
static unsigned long (*old_id_callback)(void) = NULL;
#endif

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

    JW: I don't think getpid() returns different thread ids on Linux any
    longer, nor on many other Unix systems. Maybe we should use
    PL_thread_self()?
*/

#ifndef __WINDOWS__
#ifdef HAVE_CRYPTO_THREADID_SET_CALLBACK
static void
pthreads_thread_id(CRYPTO_THREADID* id)
{ CRYPTO_THREADID_set_numeric(id, (unsigned long)pthread_self());
}
#else
static unsigned long
pthreads_thread_id(void)
{ unsigned long ret;

  ret=(unsigned long)pthread_self();
  return(ret);
}
#endif /* OpenSSL 1.0.0 */
#endif /* WINDOWS */

void
ssl_thread_exit(void* ignored)
{
#ifdef HAVE_ERR_REMOVE_THREAD_STATE
  ERR_remove_thread_state(0);
#elif defined(HAVE_ERR_REMOVE_STATE)
  ERR_remove_state(0);
#else
#error "Do not know how to remove SSL error state"
#endif
}

int
ssl_thread_setup(void)
{ int i;

  lock_cs = OPENSSL_malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
  lock_count = OPENSSL_malloc(CRYPTO_num_locks() * sizeof(long));
  for (i=0; i<CRYPTO_num_locks(); i++)
  { lock_count[i]=0;
    pthread_mutex_init(&(lock_cs[i]), NULL);
  }
#ifdef HAVE_CRYPTO_THREADID_GET_CALLBACK
  old_id_callback = CRYPTO_THREADID_get_callback();
#else
  old_id_callback = CRYPTO_get_id_callback();
#endif
  old_locking_callback = CRYPTO_get_locking_callback();
#ifndef __WINDOWS__
#ifdef HAVE_CRYPTO_THREADID_SET_CALLBACK
  CRYPTO_THREADID_set_callback(pthreads_thread_id);
#else
  CRYPTO_set_id_callback(pthreads_thread_id);
#endif
#endif
  CRYPTO_set_locking_callback(pthreads_locking_callback);
  PL_thread_at_exit(ssl_thread_exit, NULL, TRUE);
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
#ifdef HAVE_CRYPTO_THREADID_SET_CALLBACK
    CRYPTO_THREADID_set_callback(old_id_callback);
#else
    CRYPTO_set_id_callback(old_id_callback);
#endif
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

