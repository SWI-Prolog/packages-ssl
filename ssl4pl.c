/*  Part of SWI-Prolog

    Author:        Jan van der Steen, Jan Wielemaker, Matt Lilley,
		   Markus Triska and James Cash
    E-mail:        J.Wielemaker@vu.nl
    WWW:           http://www.swi-prolog.org
    Copyright (c)  2004-2018, SWI-Prolog Foundation
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

#include <config.h>
#include <SWI-Stream.h>
#include <SWI-Prolog.h>
#include <assert.h>
#include <string.h>
#include <openssl/rand.h>
#ifdef _REENTRANT
#include <pthread.h>
#endif

#include <openssl/x509v3.h>
#include <openssl/ssl.h>
#include <openssl/bn.h>
#include <openssl/dh.h>
#define NEED_BIO 1
#define NEED_SSL_ERR 1
#include "cryptolib.c"

#ifdef LIBRESSL_VERSION_NUMBER
#undef HAVE_X509_CHECK_HOST		/* seems broken. must investigate */
#endif

#define SSL_CONFIG_MAGIC 0x539dbe3a
#ifndef SYSTEM_CACERT_FILENAME
#define SYSTEM_CACERT_FILENAME "/etc/ssl/certs/ca-certificates.crt"
#endif

#define SSL_MAX_CERT_KEY_PAIRS 12

typedef int BOOL;
#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

static atom_t ATOM_server;
static atom_t ATOM_client;
static atom_t ATOM_password;
static atom_t ATOM_host;
static atom_t ATOM_peer_cert;
static atom_t ATOM_cacerts;
static atom_t ATOM_require_crl;
static atom_t ATOM_crl;
static atom_t ATOM_certificate_file;
static atom_t ATOM_certificate_key_pairs;
static atom_t ATOM_key_file;
static atom_t ATOM_pem_password_hook;
static atom_t ATOM_cert_verify_hook;
static atom_t ATOM_close_parent;
static atom_t ATOM_close_notify;
static atom_t ATOM_disable_ssl_methods;
static atom_t ATOM_min_protocol_version;
static atom_t ATOM_max_protocol_version;
static atom_t ATOM_cipher_list;
static atom_t ATOM_ecdh_curve;
static atom_t ATOM_root_certificates;
static atom_t ATOM_sni_hook;
static atom_t ATOM_alpn_protocols;
static atom_t ATOM_alpn_protocol_hook;

static atom_t ATOM_sslv2;
static atom_t ATOM_sslv23;
static atom_t ATOM_sslv3;
static atom_t ATOM_tlsv1;
static atom_t ATOM_tlsv1_1;
static atom_t ATOM_tlsv1_2;
static atom_t ATOM_tlsv1_3;
static atom_t ATOM_minus;			/* "-" */

static functor_t FUNCTOR_unsupported_hash_algorithm1;
static functor_t FUNCTOR_system1;
static functor_t FUNCTOR_error2;
static functor_t FUNCTOR_ssl_error4;
static functor_t FUNCTOR_permission_error3;
static functor_t FUNCTOR_version1;
static functor_t FUNCTOR_notbefore1;
static functor_t FUNCTOR_notafter1;
static functor_t FUNCTOR_subject1;
static functor_t FUNCTOR_issuername1;
static functor_t FUNCTOR_serial1;
static functor_t FUNCTOR_public_key1;
static functor_t FUNCTOR_private_key1;
static functor_t FUNCTOR_rsa8;
static functor_t FUNCTOR_ec3;
static functor_t FUNCTOR_key1;
static functor_t FUNCTOR_hash1;
static functor_t FUNCTOR_next_update1;
static functor_t FUNCTOR_signature1;
static functor_t FUNCTOR_signature_algorithm1;
static functor_t FUNCTOR_to_be_signed1;
static functor_t FUNCTOR_equals2;
static functor_t FUNCTOR_crl1;
static functor_t FUNCTOR_revocations1;
static functor_t FUNCTOR_revoked2;
#ifndef OPENSSL_NO_SSL2
static functor_t FUNCTOR_session_key1;
#endif
static functor_t FUNCTOR_cipher1;
static functor_t FUNCTOR_master_key1;
static functor_t FUNCTOR_session_id1;
static functor_t FUNCTOR_client_random1;
static functor_t FUNCTOR_server_random1;
static functor_t FUNCTOR_system1;
static functor_t FUNCTOR_unknown1;
static functor_t FUNCTOR_alpn_protocol1;
static functor_t FUNCTOR_file1;
static functor_t FUNCTOR_certificate1;

typedef enum
{ PL_SSL_NONE
, PL_SSL_SERVER
, PL_SSL_CLIENT
} PL_SSL_ROLE;

typedef enum
{ SSL_PL_OK
, SSL_PL_RETRY
, SSL_PL_ERROR
} SSL_PL_STATUS;

#define SSL_CERT_VERIFY_MORE 0

static STACK_OF(X509) *system_root_store = NULL;
static int system_root_store_fetched = FALSE;
static pthread_mutex_t root_store_lock = PTHREAD_MUTEX_INITIALIZER;

/*
 * Index of our config data in the SSL data
 */
static int ssl_idx;
static int ctx_idx;

typedef struct pl_cert_key_pair {
    X509                *certificate_X509;
    char                *key;
    char                *certificate;
} PL_CERT_KEY_PAIR;

typedef struct pl_ssl_callback {
    record_t goal;
    module_t module;
} PL_SSL_CALLBACK;

typedef struct pl_ssl_protocol {
    BOOL is_set;
    int version;
} PL_SSL_PROTOCOL;

typedef struct pl_ssl {
    long                 magic;
    /*
     * Are we server or client
     */
    PL_SSL_ROLE          role;

    int                  close_parent;
    atom_t               atom;
    BOOL                 close_notify;

    /*
     * Context, Certificate, SSL info
     */
    SSL_CTX             *ctx;
    int                  idx;
    X509                *peer_cert;

    /*
     * In case of the client the host we're connecting to.
     */
    char                *host;

    /*
     * Various parameters affecting the SSL layer
     */
    STACK_OF(X509)      *cacerts;

    char                *certificate_file;
    char                *key_file;
    PL_CERT_KEY_PAIR     cert_key_pairs[SSL_MAX_CERT_KEY_PAIRS];
    int                  num_cert_key_pairs;

    char                *cipher_list;
    char                *ecdh_curve;
    STACK_OF(X509_CRL)  *crl_list;
    char                *password;
    BOOL                 crl_required;
    BOOL                 peer_cert_required;

    PL_SSL_PROTOCOL      min_protocol;
    PL_SSL_PROTOCOL      max_protocol;

    /*
     * Application defined handlers
     */
    PL_SSL_CALLBACK      cb_cert_verify;
    PL_SSL_CALLBACK      cb_pem_passwd;
    PL_SSL_CALLBACK      cb_sni;
    PL_SSL_CALLBACK      cb_alpn_proto;
#ifndef HAVE_X509_CHECK_HOST
    int                  hostname_check_status;
#endif
    unsigned char       *alpn_protos;
    size_t               alpn_protos_len;
} PL_SSL;

typedef struct ssl_instance {
    PL_SSL              *config;
    SSL                 *ssl;
    IOSTREAM            *sread;         /* wire streams */
    IOSTREAM            *swrite;
    IOSTREAM            *dread;         /* data streams */
    IOSTREAM            *dwrite;
    int                  close_needed;
    BOOL                 fatal_alert;
} PL_SSL_INSTANCE;


typedef enum
{ RSA_MODE, EVP_MODE
} crypt_mode_t;

static int
get_char_arg(int a, term_t t, char **s)
{ term_t t2 = PL_new_term_ref();

  _PL_get_arg(a, t, t2);
  if ( !PL_get_chars(t2, s, CVT_ATOM|CVT_STRING|CVT_EXCEPTION) )
    return FALSE;

  return TRUE;
}


static int
get_bool_arg(int a, term_t t, int *i)
{ term_t t2 = PL_new_term_ref();

  _PL_get_arg(a, t, t2);
  if ( !PL_get_bool_ex(t2, i) )
    return FALSE;

  return TRUE;
}


static int
get_file_arg(int a, term_t t, char **f)
{ term_t t2 = PL_new_term_ref();

  _PL_get_arg(a, t, t2);
  if ( !PL_get_file_name(t2, f, PL_FILE_EXIST) )
    return FALSE;

  return TRUE;
}


static int
unify_bignum(term_t t, const BIGNUM *bn)
{
  int rc;
  if ( bn )
  { char *hex = BN_bn2hex(bn);

    rc = PL_unify_chars(t, PL_STRING|REP_ISO_LATIN_1, (size_t)-1, hex);
    OPENSSL_free(hex);
  } else
    rc = PL_unify_atom(t, ATOM_minus);

  return rc;
}


static int
unify_bignum_arg(int a, term_t t, const BIGNUM *bn)
{ term_t arg;

  if ( (arg = PL_new_term_ref()) &&
       PL_get_arg(a, t, arg) )
  { int rc = unify_bignum(arg, bn);

    PL_reset_term_refs(arg);
    return rc;
  }

  return FALSE;
}


/* Note that while this might seem incredibly hacky, it is
   essentially the same algorithm used by X509_cmp_time to
   parse the date. Some
   Fractional seconds are ignored. This is also largely untested - there
   may be a lot of edge cases that dont work!
*/
static int
unify_asn1_time(term_t term, const ASN1_TIME *time)
{ time_t result = 0;
  char buffer[24];
  char* pbuffer = buffer;
  size_t length = time->length;
  char * source = (char *)time->data;
  struct tm time_tm;
  time_t lSecondsFromUTC;

  if (time->type == V_ASN1_UTCTIME)
  {  if ((length < 11) || (length > 17))
     {  ssl_deb(2, "Unable to parse time - expected either 11 or 17 chars, not %d", length);
        return FALSE;
     }
     /* Otherwise just get the first 10 chars - ignore seconds */
     memcpy(pbuffer, source, 10);
     pbuffer += 10;
     source += 10;
     length -= 10;
  } else
  { if (length < 13)
     {  ssl_deb(2, "Unable to parse time - expected at least 13 chars, not %d", length);
        return FALSE;
     }
     /* Otherwise just get the first 12 chars - ignore seconds */
     memcpy(pbuffer, source, 12);
     pbuffer += 12;
     source += 12;
     length -= 12;
  }
  /* Next find end of string */
  if ((*source == 'Z') || (*source == '-') || (*source == '+'))
  { *(pbuffer++) = '0';
    *(pbuffer++) = '0';
  } else
  { *(pbuffer++) = *(source++);
    *(pbuffer++) = *(source++);
    if (*source == '.')
    { source++;
      while ((*source >= '0') && (*source <= '9'))
         source++;
    }
  }
  *(pbuffer++) = 'Z';
  *(pbuffer++) = '\0';

  /* If not UTC, calculate offset */
  if (*source == 'Z')
     lSecondsFromUTC = 0;
  else
  { if ( length < 6 || (*source != '+' && source[5] != '-') )
     {  ssl_deb(2, "Unable to parse time. Missing UTC offset");
        return FALSE;
     }
     lSecondsFromUTC = ((source[1]-'0') * 10 + (source[2]-'0')) * 60;
     lSecondsFromUTC += (source[3]-'0') * 10 + (source[4]-'0');
     if (*source == '-')
        lSecondsFromUTC = -lSecondsFromUTC;
  }
  /* Parse date */
  time_tm.tm_sec  = ((buffer[10] - '0') * 10) + (buffer[11] - '0');
  time_tm.tm_min  = ((buffer[8] - '0') * 10) + (buffer[9] - '0');
  time_tm.tm_hour = ((buffer[6] - '0') * 10) + (buffer[7] - '0');
  time_tm.tm_mday = ((buffer[4] - '0') * 10) + (buffer[5] - '0');
  time_tm.tm_mon  = (((buffer[2] - '0') * 10) + (buffer[3] - '0')) - 1;
  time_tm.tm_year = ((buffer[0] - '0') * 10) + (buffer[1] - '0');
  if (time_tm.tm_year < 50)
     time_tm.tm_year += 100; /* according to RFC 2459 */
  time_tm.tm_wday = 0;
  time_tm.tm_yday = 0;
  time_tm.tm_isdst = 0;  /* No DST adjustment requested, though mktime might do it anyway */

#ifdef HAVE_TIMEGM
  result = timegm(&time_tm);
  if ((time_t)-1 != result)
  { result += lSecondsFromUTC;
  } else
  { ssl_deb(2, "timegm() failed");
    return FALSE;
  }
#else
  result = mktime(&time_tm);
  /* mktime assumes that the time_tm contains information for localtime. Convert back to UTC: */
  if ((time_t)-1 != result)
  { result += lSecondsFromUTC; /* Add in the UTC offset of the original value */
    result -= timezone; /* Adjust for localtime */
  } else
  { ssl_deb(2, "mktime() failed");
    return FALSE;
  }
#endif

  return PL_unify_int64(term, result);
}

static const EVP_MD *
algorithm_to_type(const ASN1_OBJECT* algorithm, int *nid)
{ *nid = OBJ_obj2nid(algorithm);
  /* Annoyingly, EVP_get_digestbynid doesnt work for some of these algorithms. Instead check for
     them explicitly and set the digest manually
  */
  switch (*nid)
  { case NID_ecdsa_with_SHA1:
      return EVP_sha1();
    case NID_ecdsa_with_SHA256:
      return EVP_sha256();
    case NID_ecdsa_with_SHA384:
      return EVP_sha384();
#ifdef HAVE_OPENSSL_MD2_H
    case NID_md2WithRSAEncryption:
      return EVP_md2();
#endif
  }

  return EVP_get_digestbynid(*nid);
}

#if defined(HAVE_X509_DIGEST) && defined(HAVE_X509_CRL_DIGEST)

static int
hash_X509_digest_wrapper(const void *data, const EVP_MD *type, unsigned char* md, unsigned int *l)
{
  return X509_digest((X509 *) data, type, md, l);
}

static int
hash_X509_crl_digest_wrapper(const void *data, const EVP_MD *type, unsigned char* md, unsigned int *l)
{
  return X509_CRL_digest((X509_CRL *) data, type, md, l);
}

static int
unify_hash(term_t hash, const ASN1_OBJECT* algorithm,
           int (*data_to_digest)(const void*, const EVP_MD *, unsigned char*, unsigned int*),
           void *data)
{
  int nid;
  const EVP_MD *type = algorithm_to_type(algorithm, &nid);
  unsigned char digest[EVP_MAX_MD_SIZE];
  unsigned int digest_length;

  if (type == NULL)
    return PL_unify_term(hash,
                         PL_FUNCTOR, FUNCTOR_unsupported_hash_algorithm1,
                         PL_INT, nid);

  if (!data_to_digest(data, type, digest, &digest_length))
    return FALSE;

  return unify_bytes_hex(hash, digest_length, digest);
}

#else

static int i2d_X509_CRL_INFO_wrapper(void* i, unsigned char** d)
{
   return i2d_X509_CRL_INFO(i, d);
}

static int i2d_X509_CINF_wrapper(void* i, unsigned char** d)
{
   return i2d_X509_CINF(i, d);
}


static int
unify_hash(term_t hash, const ASN1_OBJECT* algorithm,
	   int (*i2d)(void*, unsigned char**), void * data)
{ int nid;
  const EVP_MD *type = algorithm_to_type(algorithm, &nid);
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  int digestible_length;
  unsigned char* digest_buffer;
  unsigned char digest[EVP_MAX_MD_SIZE];
  unsigned int digest_length;
  unsigned char* p;
  /* Generate hash */

  if (type == NULL)
    return PL_unify_term(hash,
                         PL_FUNCTOR, FUNCTOR_unsupported_hash_algorithm1,
                         PL_INT, nid);

  digestible_length=i2d(data,NULL);
  digest_buffer = PL_malloc(digestible_length);
  if (digest_buffer == NULL)
    return PL_resource_error("memory");

  /* i2d_X509_CINF will change the value of p. We need to pass in a copy */
  p = digest_buffer;
  i2d(data,&p);
  if (!EVP_DigestInit(ctx, type))
  { EVP_MD_CTX_free(ctx);
    PL_free(digest_buffer);
    return raise_ssl_error(ERR_get_error());
  }
  if (!EVP_DigestUpdate(ctx, digest_buffer, digestible_length))
  { EVP_MD_CTX_free(ctx);
    PL_free(digest_buffer);
    return raise_ssl_error(ERR_get_error());
  }
  if (!EVP_DigestFinal(ctx, digest, &digest_length))
  { EVP_MD_CTX_free(ctx);
    PL_free(digest_buffer);
    return raise_ssl_error(ERR_get_error());
  }
  EVP_MD_CTX_free(ctx);
  PL_free(digest_buffer);
  return unify_bytes_hex(hash, digest_length, digest);
}

#endif


static int
unify_name(term_t term, X509_NAME* name)
{ int ni;
  term_t list = PL_copy_term_ref(term);
  term_t item = PL_new_term_ref();

  if (name == NULL)
     return PL_unify_term(term,
                          PL_CHARS, "<null>");
  for (ni = 0; ni < X509_NAME_entry_count(name); ni++)
  { X509_NAME_ENTRY* e = X509_NAME_get_entry(name, ni);
    ASN1_STRING* entry_data = X509_NAME_ENTRY_get_data(e);
    unsigned char *utf8_data;
    int rc;

    if ( ASN1_STRING_to_UTF8(&utf8_data, entry_data) < 0 )
      return PL_resource_error("memory");

    rc = ( PL_unify_list(list, item, list) &&
	   PL_unify_term(item,
			 PL_FUNCTOR, FUNCTOR_equals2,
			 PL_CHARS, OBJ_nid2sn(OBJ_obj2nid(X509_NAME_ENTRY_get_object(e))),
			 PL_UTF8_CHARS, utf8_data)
	 );
    OPENSSL_free(utf8_data);
    if ( !rc )
      return FALSE;
  }
  return PL_unify_nil(list);
}

#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
#define X509_REVOKED_get0_serialNumber(R) ((R)->serialNumber)
#define X509_REVOKED_get0_revocationDate(R) ((R)->revocationDate)
#define EVP_PKEY_base_id(key) ((key)->type)
#define X509_CRL_get0_nextUpdate(C) X509_CRL_get_nextUpdate(C)
#ifndef HAVE_X509_CRL_GET0_SIGNATURE
/* Avoid conflict if the prototype is there, but the function is not */
#define X509_CRL_get0_signature my_X509_CRL_get0_signature
static void
X509_CRL_get0_signature(const X509_CRL *crl, const ASN1_BIT_STRING **psig, const X509_ALGOR **palg)
{
  *psig = crl->signature;
  *palg = crl->sig_alg;
}
#endif

#ifndef HAVE_X509_GET0_SIGNATURE
/* Avoid conflict if the prototype is there, but the function is not */
#define X509_get0_signature my_X509_get0_signature
static void
X509_get0_signature(const ASN1_BIT_STRING **psig, const X509_ALGOR **palg, const X509 *data)
{
  *psig = data->signature;
  *palg = data->sig_alg;
}
#endif
#endif

static int
unify_crl(term_t term, X509_CRL* crl)
{
  const ASN1_BIT_STRING *psig;
  const X509_ALGOR *palg;
  STACK_OF(X509_REVOKED) *revoked = X509_CRL_get_REVOKED(crl);
  int i;
  term_t item = PL_new_term_ref();
  term_t hash = PL_new_term_ref();
  term_t issuer = PL_new_term_ref();
  term_t revocations = PL_new_term_ref();
  term_t list = PL_copy_term_ref(revocations);
  term_t next_update = PL_new_term_ref();
  term_t signature = PL_new_term_ref();

  int result = 1;
  long n;
  unsigned char* p;
  term_t revocation_date;
  BIO* mem;

  mem = BIO_new(BIO_s_mem());
  if (mem == NULL)
    return PL_resource_error("memory");

  X509_CRL_get0_signature(crl, &psig, &palg);
  i2a_ASN1_INTEGER(mem, (ASN1_BIT_STRING *) psig);
  if (!(unify_name(issuer, X509_CRL_get_issuer(crl)) &&
#ifdef HAVE_X509_CRL_DIGEST
        unify_hash(hash, palg->algorithm, hash_X509_crl_digest_wrapper, crl) &&
#else
        unify_hash(hash, palg->algorithm, i2d_X509_CRL_INFO_wrapper, crl->crl) &&
#endif
        unify_asn1_time(next_update, X509_CRL_get0_nextUpdate(crl)) &&
        unify_bytes_hex(signature, psig->length, psig->data) &&
        PL_unify_term(term,
                      PL_LIST, 5,
                      PL_FUNCTOR, FUNCTOR_issuername1,
                      PL_TERM, issuer,
                      PL_FUNCTOR, FUNCTOR_signature1,
                      PL_TERM, signature,
                      PL_FUNCTOR, FUNCTOR_hash1,
                      PL_TERM, hash,
                      PL_FUNCTOR, FUNCTOR_next_update1,
                      PL_TERM, next_update,
                      PL_FUNCTOR, FUNCTOR_revocations1,
                      PL_TERM, revocations)))
  {
     return FALSE;
  }
  for (i = 0; i < sk_X509_REVOKED_num(revoked); i++)
  {  X509_REVOKED *r = sk_X509_REVOKED_value(revoked, i);
     (void)BIO_reset(mem);
     i2a_ASN1_INTEGER(mem, X509_REVOKED_get0_serialNumber(r));
     result &= (((n = BIO_get_mem_data(mem, &p)) > 0) &&
                PL_unify_list(list, item, list) &&
                (revocation_date = PL_new_term_ref()) &&
                unify_asn1_time(revocation_date, X509_REVOKED_get0_revocationDate(r)) &&
                PL_unify_term(item,
                              PL_FUNCTOR, FUNCTOR_revoked2,
                              PL_NCHARS, (size_t)n, p,
                              PL_TERM, revocation_date));
     if (BIO_reset(mem) != 1)
     {
        BIO_free(mem);
        // The only reason I can imagine this would fail is out of memory
        return PL_resource_error("memory");
     }
  }
  BIO_free(mem);
  return result && PL_unify_nil(list);
}


static int
unify_rsa(term_t item, RSA* rsa)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
  return ( PL_unify_functor(item, FUNCTOR_rsa8) &&
	   unify_bignum_arg(1, item, rsa->n) &&
	   unify_bignum_arg(2, item, rsa->e) &&
	   unify_bignum_arg(3, item, rsa->d) &&
	   unify_bignum_arg(4, item, rsa->p) &&
	   unify_bignum_arg(5, item, rsa->q) &&
	   unify_bignum_arg(6, item, rsa->dmp1) &&
	   unify_bignum_arg(7, item, rsa->dmq1) &&
	   unify_bignum_arg(8, item, rsa->iqmp)
	 );
#else
  const BIGNUM *n = NULL, *e = NULL, *d = NULL,
    *p = NULL, *q = NULL,
    *dmp1 = NULL, *dmq1 = NULL, *iqmp = NULL;
  RSA_get0_key(rsa, &n, &e, &d);
  RSA_get0_factors(rsa, &p, &q);
  RSA_get0_crt_params(rsa, &dmp1, &dmq1, &iqmp);
  return ( PL_unify_functor(item, FUNCTOR_rsa8) &&
	   unify_bignum_arg(1, item, n) &&
	   unify_bignum_arg(2, item, e) &&
	   unify_bignum_arg(3, item, d) &&
	   unify_bignum_arg(4, item, p) &&
	   unify_bignum_arg(5, item, q) &&
	   unify_bignum_arg(6, item, dmp1) &&
	   unify_bignum_arg(7, item, dmq1) &&
	   unify_bignum_arg(8, item, iqmp)
	 );
#endif
}

#ifndef OPENSSL_NO_EC
static int
unify_ec(term_t item, EC_KEY *key)
{
  unsigned char *buf = NULL;
  int rc, publen;
  term_t privkey, pubkey;

  publen = i2o_ECPublicKey(key, &buf);

  if ( publen < 0 )
    return raise_ssl_error(ERR_get_error());

  rc = ( (pubkey = PL_new_term_ref()) &&
         (privkey = PL_new_term_ref()) &&
         unify_bignum(privkey, EC_KEY_get0_private_key(key)) &&
         unify_bytes_hex(pubkey, publen, buf) &&
         PL_unify_term(item,
                       PL_FUNCTOR, FUNCTOR_ec3,
                       PL_TERM, privkey,
                       PL_TERM, pubkey,
                       PL_CHARS, OBJ_nid2sn(EC_GROUP_get_curve_name(EC_KEY_get0_group(key)))) );

  OPENSSL_free(buf);
  return rc;
}
#endif


static int
unify_key(EVP_PKEY* key, functor_t type, term_t item)
{ if ( !PL_unify_functor(item, type) ||
       !PL_get_arg(1, item, item) )
    return FALSE;

 /* EVP_PKEY_get1_* returns a copy of the existing key */
  switch (EVP_PKEY_base_id(key))
  { int rc;
#ifndef OPENSSL_NO_RSA
    case EVP_PKEY_RSA:
    { RSA* rsa = EVP_PKEY_get1_RSA(key);
      rc = unify_rsa(item, rsa);
      RSA_free(rsa);
      return rc;
    }
#endif
#ifndef OPENSSL_NO_EC
    case EVP_PKEY_EC:
    { EC_KEY* ec = EVP_PKEY_get1_EC_KEY(key);
      rc = unify_ec(item, ec);
      EC_KEY_free(ec);
      return rc;
    }
#endif
#ifndef OPENSSL_NO_DH
    case EVP_PKEY_DH:
    { DH* dh = EVP_PKEY_get1_DH(key);
      rc = PL_unify_atom_chars(item, "dh_key");
      DH_free(dh);
      return rc;
    }
#endif
#ifndef OPENSSL_NO_DSA
    case EVP_PKEY_DSA:
    { DSA* dsa = EVP_PKEY_get1_DSA(key);
      rc = PL_unify_atom_chars(item, "dsa_key");
      DSA_free(dsa);
      return rc;
    }
#endif
  default:
    /* Unknown key type */
    return PL_representation_error("ssl_key");
  }
  return TRUE;
}

static int
unify_public_key(EVP_PKEY* key, term_t item)
{ return unify_key(key, FUNCTOR_public_key1, item);
}

static int
unify_private_key(EVP_PKEY* key, term_t item)
{ return unify_key(key, FUNCTOR_private_key1, item);
}

#ifndef HAVE_X509_GET0_NOTBEFORE
#define X509_get0_notBefore(C) X509_get_notBefore(C)
#endif
#ifndef HAVE_X509_GET0_NOTAFTER
#define X509_get0_notAfter(C) X509_get_notAfter(C)
#endif

#ifndef GET0SIG_CONST_T
#define GET0SIG_CONST_T
#endif


static int
release_cert(atom_t atom)
{ X509 *cert = PL_blob_data(atom, NULL, NULL);
  X509_free(cert);
  return TRUE;
}

static int
write_cert(IOSTREAM *s, atom_t symbol, int flags)
{ X509 *cert = PL_blob_data(symbol, NULL, NULL);
  Sfprintf(s, "<ssl_certificate>(%p)", cert);
  return TRUE;
}

static PL_blob_t certificate_type =
{ PL_BLOB_MAGIC,
  PL_BLOB_UNIQUE | PL_BLOB_NOCOPY,
  "ssl_certificate",
  release_cert,
  NULL,
  write_cert,
  NULL
};

static int
unify_certificate_blob(term_t Cert, X509* cert)
{ term_t blob = PL_new_term_ref();
  PL_put_blob(blob, cert, sizeof(void*), &certificate_type);
  return PL_unify(Cert, blob);
}

static int
unify_certificate_blob_copy(term_t Cert, X509* cert)
{ term_t blob = PL_new_term_ref();
  PL_put_blob(blob, X509_dup(cert), sizeof(void*), &certificate_type);
  return PL_unify(Cert, blob);
}


static int
get_certificate_blob(term_t Cert, X509** cert)
{ PL_blob_t* type;
  if (PL_get_blob(Cert, (void**)cert, NULL, &type) && type == &certificate_type)
    return TRUE;
  return PL_type_error("ssl_certificate", Cert);
}


static int
unify_certificate_copies(term_t certs, term_t tail, STACK_OF(X509)* stack)
{ term_t item = PL_new_term_ref();
  term_t list = PL_copy_term_ref(certs);
  STACK_OF(X509) *copy = stack ? sk_X509_dup(stack) : NULL;
  X509* cert = sk_X509_pop(copy);
  int retval = 1;

  while (cert != NULL && retval == 1)
  { retval &= PL_unify_list(list, item, list);
    retval &= unify_certificate_blob_copy(item, cert);
    cert = sk_X509_pop(copy);
    if (cert == NULL)
    { sk_X509_free(copy);
      return PL_unify(tail, item) && PL_unify_nil(list);
    }
  }
  sk_X509_free(copy);
  return retval && PL_unify_nil(list);
}

static int
unify_certificate_copies_inorder(term_t certs, STACK_OF(X509)* stack)
{ term_t item = PL_new_term_ref();
  term_t list = PL_copy_term_ref(certs);
  STACK_OF(X509) *copy = stack ? sk_X509_dup(stack) : NULL;
  X509* cert = sk_X509_shift(copy);
  int retval = 1;

  while (cert != NULL && retval == 1)
  { retval &= PL_unify_list(list, item, list);
    retval &= unify_certificate_blob_copy(item, cert);
    cert = sk_X509_shift(copy);
  }
  sk_X509_free(copy);
  return retval && PL_unify_nil(list);
}

static int
get_certificate_blobs(term_t Certs, STACK_OF(X509) **certs)
{ term_t tail = PL_copy_term_ref(Certs);
  term_t head = PL_new_term_ref();
  *certs = sk_X509_new_null();
  int rc = 1;

  while( rc && PL_get_list_ex(tail, head, tail) )
  {
    X509* cert;
    rc &= get_certificate_blob(head, &cert);
    rc &= sk_X509_push(*certs, cert);
  }
  rc &= PL_get_nil_ex(tail);
  if (!rc)
  { sk_X509_free(*certs);
    *certs = NULL;
  }
  return rc;
}


static foreign_t
pl_load_public_key(term_t source, term_t key_t)
{ EVP_PKEY* key;
  BIO* bio;
  IOSTREAM* stream;
  int c;

  if ( !PL_get_stream_handle(source, &stream) )
    return FALSE;
  bio = BIO_new(bio_read_method());
  BIO_set_ex_data(bio, 0, stream);

  /* Determine format */
  c = Speekcode(stream);
  if (c == 0x30)  /* ASN.1 sequence, so assume DER */
     key = d2i_PUBKEY_bio(bio, NULL);
  else
     key = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
  BIO_free(bio);
  PL_release_stream(stream);
  if (key == NULL)
     return PL_permission_error("read", "key", source);
  if (!unify_public_key(key, key_t))
  { EVP_PKEY_free(key);
    PL_fail;
  }
  EVP_PKEY_free(key);
  PL_succeed;
}


static foreign_t
pl_load_private_key(term_t source, term_t password, term_t key_t)
{ EVP_PKEY* key;
  BIO* bio;
  IOSTREAM* stream;
  char* password_chars;
  int c, rc;

  if ( !PL_get_chars(password, &password_chars,
		     CVT_ATOM|CVT_STRING|CVT_LIST|CVT_EXCEPTION) )
    return FALSE;
  if ( !PL_get_stream_handle(source, &stream) )
    return FALSE;
  bio = BIO_new(bio_read_method());
  BIO_set_ex_data(bio, 0, stream);

  /* Determine format */
  c = Speekcode(stream);
  if (c == 0x30)  /* ASN.1 sequence, so assume DER */
    key = d2i_PrivateKey_bio(bio, NULL); /* TBD: Password! */
  else
    key = PEM_read_bio_PrivateKey(bio, NULL, NULL, (void*)password_chars);
  BIO_free(bio);
  PL_release_stream(stream);

  if ( key == NULL )
    return PL_permission_error("read", "key", source);

  rc = (unify_private_key(key, key_t) != 0);
  EVP_PKEY_free(key);

  return rc;
}

static foreign_t
pl_load_crl(term_t source, term_t list)
{ X509_CRL* crl;
  BIO* bio;
  IOSTREAM* stream;
  int result;
  int c;

  if ( !PL_get_stream_handle(source, &stream) )
    return FALSE;

  bio = BIO_new(bio_read_method());
  BIO_set_ex_data(bio, 0, stream);
  /* Determine the format of the CRL */
  c = Speekcode(stream);
  if (c == 0x30)  /* ASN.1 sequence, so assume DER */
     crl = d2i_X509_CRL_bio(bio, NULL);
  else
     crl = PEM_read_bio_X509_CRL(bio, NULL, NULL, NULL);
  BIO_free(bio);
  PL_release_stream(stream);
  if (crl == NULL)
  { ssl_deb(2, "Failed to load CRL");
    PL_fail;
  }
  result = unify_crl(list, crl);
  X509_CRL_free(crl);
  return result;
}

static foreign_t
pl_load_certificate(term_t source, term_t cert)
{ X509* x509;
  BIO* bio;
  IOSTREAM* stream;
  int c = 0;

  if ( !PL_get_stream_handle(source, &stream) )
    return FALSE;
  bio = BIO_new(bio_read_method());
  BIO_set_ex_data(bio, 0, stream);
  /* Determine format */
  c = Speekcode(stream);
  if (c == 0x30)  /* ASN.1 sequence, so assume DER */
     x509 = d2i_X509_bio(bio, NULL);
  else
     x509 = PEM_read_bio_X509(bio, NULL, 0, NULL);
  BIO_free(bio);
  PL_release_stream(stream);
  if (x509 == NULL)
    return raise_ssl_error(ERR_get_error());
  return unify_certificate_blob(cert, x509);
}

static foreign_t
load_certificates_from_file(char *filename, STACK_OF(X509)* certs)
{ X509* cert;
  int count = 0;
  FILE* fp = fopen(filename, "r");
  if (fp == NULL)
    return PL_existence_error("file", PL_new_atom(filename));
  while ((cert = PEM_read_X509(fp, NULL, NULL, NULL)) != NULL)
  { sk_X509_push(certs, cert);
    count++;
  }
  fclose(fp);
  return count > 0;
}


typedef struct
{
   int index;
   int deterministic;
   X509* cert;
   term_t current_field;
} field_enum;

static foreign_t
fetch_subject(term_t Field, X509* cert)
{ return unify_name(Field, X509_get_subject_name(cert));
}

static foreign_t
fetch_issuer(term_t Field, X509* cert)
{ return unify_name(Field, X509_get_issuer_name(cert));
}


static foreign_t
fetch_version(term_t Field, X509* cert)
{ return PL_unify_integer(Field, X509_get_version(cert));
}

static foreign_t
fetch_serial(term_t Field, X509* cert)
{ BIO * mem = NULL;
  long n;
  int rc = 0;
  unsigned char *p;

  if ((mem = BIO_new(BIO_s_mem())) != NULL)
  { i2a_ASN1_INTEGER(mem, X509_get_serialNumber(cert));
    if ((n = BIO_get_mem_data(mem, &p)) > 0)
      rc = PL_unify_atom_nchars(Field, (size_t)n, (char*)p);
    BIO_vfree(mem);
    return rc;
  }
  return FALSE;
}


static foreign_t
fetch_not_before(term_t Field, X509* cert)
{ return unify_asn1_time(Field, X509_get0_notBefore(cert));
}

static foreign_t
fetch_not_after(term_t Field, X509* cert)
{ return unify_asn1_time(Field, X509_get0_notAfter(cert));
}


static foreign_t
fetch_public_key(term_t Field, X509* cert)
{ EVP_PKEY *key;
  int rc;
  term_t arg = PL_new_term_ref();
  key = X509_get_pubkey(cert);
  rc = unify_public_key(key, arg);
  EVP_PKEY_free(key);
  /* Most existing code expects to be able to call memberchk(key(Key), Cert)
     and then pass Key to the rsa_* routines. This is a problem for this new
     interface, since calling certificate_field(Cert, public_key(Key)) will
     bind Key to an rsa/8. This means we have the slightly awkward result
     that calling certificate_field(Cert, public_key(Key)) will exit with
     binding certificate_field(Cert, public_key(public_key(rsa(....))))
     ie with two public_key/1 functors
  */
  return rc && PL_unify_term(Field, PL_FUNCTOR, FUNCTOR_public_key1, PL_TERM, arg);
}

static foreign_t
fetch_crls(term_t Field, X509* cert)
{ unsigned int crl_ext_id;
  X509_EXTENSION * crl_ext = NULL;

  crl_ext_id = X509_get_ext_by_NID(cert, NID_crl_distribution_points, -1);
  crl_ext = X509_get_ext(cert, crl_ext_id);
  if (crl_ext != NULL)
  { STACK_OF(DIST_POINT) * distpoints;
    int i, j;
    term_t crl;
    term_t crl_list;
    term_t crl_item;

    distpoints = X509_get_ext_d2i(cert, NID_crl_distribution_points, NULL, NULL);
    /* Loop through the CRL points, putting them into a list */
    crl = PL_new_term_ref();
    crl_list = PL_copy_term_ref(crl);
    crl_item = PL_new_term_ref();

    for (i = 0; i < sk_DIST_POINT_num(distpoints); i++)
    { DIST_POINT *point;
      GENERAL_NAME *name;
      point = sk_DIST_POINT_value(distpoints, i);
      if (point->distpoint != NULL)
      { /* Each point may have several names? May as well put them all in */
        for (j = 0; j < sk_GENERAL_NAME_num(point->distpoint->name.fullname); j++)
        { name = sk_GENERAL_NAME_value(point->distpoint->name.fullname, j);
          if (name != NULL && name->type == GEN_URI)
          { if (!(PL_unify_list(crl_list, crl_item, crl_list) &&
                  PL_unify_atom_chars(crl_item, (const char *)name->d.ia5->data)))
            {
              CRL_DIST_POINTS_free(distpoints);
              return FALSE;
            }
          }
        }
      }
    }
    CRL_DIST_POINTS_free(distpoints);
    return PL_unify_nil(crl_list) && PL_unify(Field, crl);
  }
  else
  { /* No CRL */
    return PL_unify_nil(Field);
  }
}

#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
#define ASN1_STRING_get0_data(D) ASN1_STRING_data(D)
#define X509_STORE_CTX_get0_cert(C) ((C)->cert)
#endif


static foreign_t
fetch_sans(term_t Field, X509* cert)
{ unsigned int san_ext_id;
  X509_EXTENSION * san_ext = NULL;

  san_ext_id = X509_get_ext_by_NID(cert, NID_subject_alt_name, -1);
  san_ext = X509_get_ext(cert, san_ext_id);
  if (san_ext != NULL)
  { STACK_OF(GENERAL_NAME) *san_names = NULL;
    GENERAL_NAME *name;
    term_t san, san_list, san_item;
    int i;

    san_names = X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
    /* Loop through the SANs, putting them into a list */
    san = PL_new_term_ref();
    san_list = PL_copy_term_ref(san);
    san_item = PL_new_term_ref();
    for (i = 0; i < sk_GENERAL_NAME_num(san_names); i++)
    { name = sk_GENERAL_NAME_value(san_names, i);
      if (name != NULL && name->type == GEN_DNS)
      { if (!(PL_unify_list(san_list, san_item, san_list) &&
              PL_unify_atom_chars(san_item, (char*)ASN1_STRING_get0_data(name->d.dNSName))))
	{ sk_GENERAL_NAME_pop_free(san_names, GENERAL_NAME_free);
	  return FALSE;
	}
      }
    }
    sk_GENERAL_NAME_pop_free(san_names, GENERAL_NAME_free);
    return PL_unify_nil(san_list) && PL_unify(Field, san);
  }
  else
  { /* No SAN */
    return PL_unify_nil(Field);
  }
}

static foreign_t
fetch_signature(term_t Field, X509* cert)
{ GET0SIG_CONST_T ASN1_BIT_STRING *psig;
  GET0SIG_CONST_T X509_ALGOR *palg;
  X509_get0_signature(&psig, &palg, cert);
  return unify_bytes_hex(Field, psig->length, psig->data);
}


static foreign_t
fetch_signature_algorithm(term_t Field, X509* cert)
{ GET0SIG_CONST_T ASN1_BIT_STRING *psig;
  GET0SIG_CONST_T X509_ALGOR *palg;
  const char *salgorithm;
  
  X509_get0_signature(&psig, &palg, cert);
  if ((salgorithm = OBJ_nid2sn(OBJ_obj2nid(palg->algorithm))) != NULL)
  { return PL_unify_chars(Field, PL_ATOM|REP_UTF8, strlen(salgorithm), salgorithm);
  }
  return FALSE;
}

static foreign_t
fetch_hash(term_t Field, X509* cert)
{ GET0SIG_CONST_T ASN1_BIT_STRING *psig;
  GET0SIG_CONST_T X509_ALGOR *palg;
  
  X509_get0_signature(&psig, &palg, cert);
#ifdef HAVE_X509_DIGEST
  return unify_hash(Field, palg->algorithm, hash_X509_digest_wrapper, cert);
#else
  return unify_hash(Field, palg->algorithm, i2d_X509_CINF_wrapper, cert->cert_info);
#endif
}



#ifdef HAVE_I2D_RE_X509_TBS
static foreign_t
fetch_to_be_signed(term_t Field, X509* cert)
{ unsigned char *tbs = NULL;
  int tbs_len = i2d_re_X509_tbs(cert, &tbs);
  int rc = 0;
  if (tbs_len >= 0)
    rc = unify_bytes_hex(Field, tbs_len, tbs);
  OPENSSL_free(tbs);
  return rc;
}
#endif


struct
{
  const char* name;
  foreign_t (*fetch)(term_t, X509*);
} certificate_fields[] = {{"subject", fetch_subject},
			      {"issuer", fetch_issuer},
			      {"not_before", fetch_not_before},
			      {"not_after", fetch_not_after},
			      {"version", fetch_version},
			      {"serial", fetch_serial},
			      {"public_key", fetch_public_key},
			      {"crls", fetch_crls},
			      {"sans", fetch_sans},
			      {"signature", fetch_signature},
			      {"signature_algorithm", fetch_signature_algorithm},
			      {"hash", fetch_hash},
#ifdef HAVE_I2D_RE_X509_TBS			      
			      {"to_be_signed", fetch_to_be_signed},
#endif
			      {NULL, NULL}};


static int fetch_field(field_enum *state)
{ if (certificate_fields[state->index].name != 0)
  { term_t arg = PL_new_term_ref();
    int rc = certificate_fields[state->index].fetch(arg, state->cert);
    state->current_field = PL_new_term_ref();
    return rc && PL_unify_term(state->current_field,
			       PL_FUNCTOR_CHARS, certificate_fields[state->index].name, 1,
			       PL_TERM, arg);
  }
  return 0;
}

static
foreign_t pl_certificate_field(term_t Certificate, term_t Field, control_t handle)
{ field_enum *state;
  switch(PL_foreign_control(handle))
  { case PL_FIRST_CALL:
    state = PL_malloc(sizeof(field_enum));
    memset(state, 0, sizeof(field_enum));
    if ( !get_certificate_blob(Certificate, &state->cert) )
    { PL_free(state);
      return FALSE;
    }
    if (!PL_is_variable(Field)) /* deterministic case */
    { atom_t name;
      size_t arity;
      const char* namec;
      if (!PL_get_name_arity(Field, &name, &arity) || arity != 1)
      { PL_free(state);
	return PL_type_error("field", Field);
      }
      namec = PL_atom_chars(name);
      while (certificate_fields[state->index].name != NULL)
      { if (strcmp(certificate_fields[state->index].name, namec) == 0)
	{ state->deterministic = 1;
	  break;
	}
	state->index++;
      }
      if (certificate_fields[state->index].name == 0)
      { PL_free(state);
	return PL_existence_error("field", Field);
      }
    }
    if (!fetch_field(state))
    { PL_free(state);
      PL_fail;
    }
    break;
  case PL_REDO:
     state = PL_foreign_context_address(handle);
     if (!fetch_field(state))
     { PL_free(state);
       PL_fail;
     }
     break;
  case PL_CUTTED:
    state = PL_foreign_context_address(handle);
    PL_free(state);
    PL_succeed;
    break;
  default:
    return FALSE;
  }
  if (PL_unify(Field, state->current_field))
  { if (state->deterministic)
    { PL_free(state);
      PL_succeed;
    }
    else
    { state->index++;
      PL_retry_address(state);
    }
  }
  else
  { PL_free(state);
    PL_fail;
  }
}


static foreign_t
pl_verify_certificate_issuer(term_t Certificate, term_t IssuerCertificate)
{ X509* cert, *issuer_cert;
  if ( !get_certificate_blob(Certificate, &cert) )
    return FALSE;
  if ( !get_certificate_blob(IssuerCertificate, &issuer_cert) )
    return FALSE;
  return X509_check_issued(issuer_cert, cert) == X509_V_OK;
}

static foreign_t
pl_same_certificate(term_t A, term_t B)
{ X509* a, *b;
  if ( !get_certificate_blob(A, &a) )
    return FALSE;
  if ( !get_certificate_blob(B, &b) )
    return FALSE;
  return X509_cmp(a, b) == 0;
}

static foreign_t
pl_write_certificate(term_t Sink, term_t Cert, term_t Options)
{ X509* x509;
  BIO* bio;
  IOSTREAM* stream;
  int rc;

  if ( !get_certificate_blob(Cert, &x509) )
    return FALSE;
  if ( !PL_get_stream_handle(Sink, &stream) )
    return FALSE;

  bio = BIO_new(bio_write_text_method());
  BIO_set_ex_data(bio, 0, stream);
  rc = PEM_write_bio_X509(bio, x509);
  BIO_free(bio);
  PL_release_stream(stream);
  return rc;
}


static inline PL_SSL*
symbol_ssl(atom_t symbol)
{ PL_SSL **confp = PL_blob_data(symbol, NULL, NULL);
  return *confp;
}

static void
acquire_ssl(atom_t atom)
{ PL_SSL *conf = symbol_ssl(atom);
  conf->atom = atom;
}

/*
 * Clean up all allocated resources.
 */
static void
ssl_exit(PL_SSL *config)
{ if ( config )
  { if (config->ctx)
    { ssl_deb(1, "Calling SSL_CTX_free()\n");
      SSL_CTX_free(config->ctx);	/* doesn't call free hook? */
    } else
    { ssl_deb(1, "config without CTX encountered\n");
    }
  }

  ssl_deb(1, "Controlled exit\n");
}


static int
release_ssl(atom_t atom)
{ PL_SSL *conf = symbol_ssl(atom);
  ssl_exit(conf);	/* conf is freed by an internal call from OpenSSL
	                   via ssl_config_free() */
  return TRUE;
}

static int
compare_ssl(atom_t a, atom_t b)
{ PL_SSL *ssla = symbol_ssl(a);
  PL_SSL *sslb = symbol_ssl(b);

  return ( ssla > sslb ?  1 :
	   ssla < sslb ? -1 : 0
	 );
}

static int
write_ssl(IOSTREAM *s, atom_t symbol, int flags)
{ PL_SSL *ssl = symbol_ssl(symbol);

  Sfprintf(s, "<ssl_context>(%p)", ssl);

  return TRUE;
}

static PL_blob_t ssl_context_type =
{ PL_BLOB_MAGIC,
  PL_BLOB_UNIQUE,
  "ssl_context",
  release_ssl,
  compare_ssl,
  write_ssl,
  acquire_ssl
};


static int
unify_conf(term_t config, PL_SSL *conf)
{ if ( PL_unify_blob(config, &conf, sizeof(conf), &ssl_context_type) )
    return TRUE;

  ssl_exit(conf);
  if ( !PL_exception(0) )
    return PL_uninstantiation_error(config);

  return FALSE;
}


static int
get_conf(term_t config, PL_SSL **conf)
{ PL_blob_t *type;
  void *data;

  if ( PL_get_blob(config, &data, NULL, &type) && type == &ssl_context_type )
  { PL_SSL **sslp = data;
    PL_SSL  *ssl  = *sslp;

    assert(ssl->magic == SSL_CONFIG_MAGIC);
    *conf = ssl;

    return TRUE;
  }

  return PL_type_error("ssl_context", config);
}


		 /*******************************
		 *	      CALLBACK		*
		 *******************************/


static char *
pl_pem_passwd_hook(PL_SSL *config, char *buf, int size)
{ fid_t fid = PL_open_foreign_frame();
  term_t av = PL_new_term_refs(3);
  predicate_t call3 = PL_predicate("call", 3, NULL);
  char *passwd = NULL;
  size_t len;

  /*
   * call(CB, +SSL, -Passwd)
   */
  PL_recorded(config->cb_pem_passwd.goal, av+0);

  PL_put_atom(av+1, config->atom);
  if ( PL_call_predicate(config->cb_pem_passwd.module, PL_Q_PASS_EXCEPTION, call3, av) )
  { if ( PL_get_nchars(av+2, &len, &passwd, CVT_ALL) )
    { if ( len >= (unsigned int)size )
      { PL_warning("pem_passwd too long");
      } else
      { memcpy(buf, passwd, len+1);
	passwd = buf;
      }
    } else
      PL_warning("pem_passwd_hook returned wrong type");
  }

  PL_close_foreign_frame(fid);

  return passwd;
}

static PL_SSL *
pl_sni_hook(PL_SSL *config, const char *host)
{ fid_t fid = PL_open_foreign_frame();
  term_t av = PL_new_term_refs(4);

  predicate_t call4 = PL_predicate("call", 4, NULL);
  PL_SSL *new_config = NULL;

  /*
   * call(CB, +SSL0, +Hostname, -SSL)
   */
  PL_recorded(config->cb_sni.goal, av+0);
  PL_put_atom(av+1, config->atom);
  if ( PL_unify_chars(av+2, PL_ATOM|REP_UTF8, strlen(host), host)
       && PL_call_predicate(config->cb_sni.module,
                            PL_Q_PASS_EXCEPTION, call4, av) )
    if ( !get_conf(av+3, &new_config) )
      PL_warning("sni_hook returned wrong type");

  PL_close_foreign_frame(fid);
  return new_config;
}

#ifndef HAVE_X509_STORE_CTX_GET0_CHAIN
#define X509_STORE_CTX_get0_chain(c) X509_STORE_CTX_get_chain(c)
#endif

static BOOL
pl_cert_verify_hook(PL_SSL *config,
                    X509 * cert,
		    X509_STORE_CTX * ctx,
		    const char *error,
                    int error_unknown)
{ fid_t fid = PL_open_foreign_frame();
  term_t av = PL_new_term_refs(6);
  term_t error_term = PL_new_term_ref();
  predicate_t call6 = PL_predicate("call", 6, NULL);
  int val;
  STACK_OF(X509)* stack = X509_STORE_CTX_get0_chain(ctx);

  PL_recorded(config->cb_cert_verify.goal, av+0);

  /*
   * call(CB, +SSL, +ProblemCert, +AllCerts, +FirstCert, +Error)
   */

  PL_put_atom(av+1, config->atom);
  if ( error_unknown )
    val = PL_unify_term(error_term,
                        PL_FUNCTOR, FUNCTOR_unknown1,
                        PL_CHARS, error);
  else
    val = PL_unify_atom_chars(error_term, error);
  /*Sdprintf("\n---Certificate:'%s'---\n", certificate);*/
  val &= ( unify_certificate_blob_copy(av+2, cert) &&
           unify_certificate_copies(av+3, av+4, stack) &&
           PL_unify(av+5, error_term) &&
           PL_call_predicate(config->cb_cert_verify.module,
                             PL_Q_PASS_EXCEPTION, call6, av) );

  PL_close_foreign_frame(fid);

  return val;
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

    case SSL_ERROR_SSL:
      instance->fatal_alert = TRUE;
      break;

    default:
      break;
  }

  /*
     It is hard to handle all possible cases correctly across
     different OpenSSL versions and for all BIO types.

     For many releases, the OpenSSL documentation contained
     contradicting and wrong information. In OpenSSL 1.1.0c, the API
     changed (without notice) to return -1 when hitting EOF in
     SSL_read(). This change was later reverted.

     The best description was given by Matt Caswell in:

          https://github.com/openssl/openssl/issues/1903

     "I should add that you can also use SSL_get_shutdown() to
     explicitly test whether a connection has been cleanly shutdown or
     not. This actually tells you slightly different information to
     SSL_get_error(), i.e. it tells you whether a shutdown alert has
     been received (i.e. a close_notify or a fatal error alert), or
     whether we have sent a close_notify ourselves. A connection is
     only fully and cleanly closed if we have both sent and received a
     close_notify.

     "SSL_get_error() will tell you whether a close_notify has been
     received through SSL_ERROR_RETURN_ZERO. Receipt of a fatal alert
     will appear as SSL_ERROR_SSL from SSL_get_error() - although it
     could also mean some other kind of internal error has happened. A
     SSL_ERROR_SYSCALL return will tell you that some unknown error
     has occurred in a system call. This could be caused by an unclean
     shutdown.

     "So, in summary, if you get a 0 or -1 return from
     SSL_read()/SSL_write(), you should call SSL_get_error():

     "If you get back SSL_ERROR_RETURN_ZERO then you know the
     connection has been cleanly shutdown by the peer. To fully close
     the connection you may choose to call SSL_shutdown() to send a
     close_notify back.  If you get back SSL_ERROR_SSL then some kind
     of internal or protocol error has occurred. More details will be
     on the SSL error queue. You can also call SSL_get_shutdown(). If
     this indicates a state of SSL_RECEIVED_SHUTDOWN then you know a
     fatal alert has been received from the peer (if it had been a
     close_notify then SSL_get_error() would have returned
     SSL_ERROR_RETURN_ZERO). SSL_ERROR_SSL is considered fatal - you
     should not call SSL_shutdown() in this case.

     "If you get back SSL_ERROR_SYSCALL then some kind of fatal
     (i.e. non-retryable) error has occurred in a system call. You may
     be able to get more information from the SSL error queue or you
     might not. The fatal error could be because the underlying
     transport has been shutdown unexpectedly (no alert received) or
     just some other unknown system call error occurred. Calling
     BIO_eof() at this point will tell you whether the underlying
     transport has hit EOF (i.e. for a socket BIO the connection has
     been closed)."

     Other things I found out:

     -) BIO_eof() may return true even if data can still be read.
     -) How this all interacts with timeouts does not follow
        from the description above. It is not enough to check
        for EOF, even if one manages to do it correctly.
  */

  error = ERR_get_error();

  if ( code == SSL_ERROR_SYSCALL )
  { instance->fatal_alert = TRUE;

    if ( (role == STAT_READ  && Sferror(instance->dread)) ||
	 (role == STAT_WRITE && Sferror(instance->dwrite)) )
      return SSL_PL_ERROR;

    if ( role == STAT_READ && BIO_eof(SSL_get_rbio(instance->ssl)) )
    { if ( !instance->config->close_notify )
        return SSL_PL_OK;
      Sseterr(instance->dread, SIO_FERR, "SSL: unexpected end-of-file");
    } else if ( role == STAT_WRITE && BIO_eof(SSL_get_wbio(instance->ssl)) )
    { Sseterr(instance->dwrite, SIO_FERR, "SSL: unexpected end-of-file");
    } else if ( role == STAT_NEGOTIATE )
    { PL_raise_exception(error == 0 ? unexpected_eof(instance)
                                    : syscall_error("ssl_negotiate", errno));
    }

    return SSL_PL_ERROR;
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

static PL_SSL *
ssl_new(void)
/*
 * Allocate new state and configuration storage for an SSL session from PL
 */
{
    PL_SSL *new = NULL;
    int i = 0;

    if ((new = malloc(sizeof(*new))) != NULL) {
        new->role                = PL_SSL_NONE;

        new->close_parent        = FALSE;
        new->atom                = 0;
        new->close_notify        = FALSE;

        new->peer_cert           = NULL;
        new->ctx                 = NULL;
        new->idx                 = -1;
        new->password            = NULL;

        new->min_protocol.is_set = FALSE;
        new->max_protocol.is_set = FALSE;

        new->host                = NULL;

	new->cacerts             = NULL;
        new->certificate_file    = NULL;
        new->num_cert_key_pairs  = 0;
        for (i = 0; i < SSL_MAX_CERT_KEY_PAIRS; i++)
        { new->cert_key_pairs[i].certificate_X509 = NULL;
          new->cert_key_pairs[i].key              = NULL;
          new->cert_key_pairs[i].certificate      = NULL;
        }

        new->key_file            = NULL;
        new->cipher_list         = NULL;
        new->ecdh_curve          = NULL;
        new->crl_list            = NULL;
        new->peer_cert_required  = FALSE;
        new->crl_required        = FALSE;
        new->cb_sni.goal         = NULL;
        new->cb_cert_verify.goal = NULL;
        new->cb_pem_passwd.goal  = NULL;
        new->cb_alpn_proto.goal  = NULL;
#ifndef HAVE_X509_CHECK_HOST
        new->hostname_check_status = 0;
#endif
        new->alpn_protos         = NULL;
        new->alpn_protos_len     = 0;
        new->magic                 = SSL_CONFIG_MAGIC;
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
  { int i;
    assert(config->magic == SSL_CONFIG_MAGIC);
    config->magic = 0;
    free(config->host);
    if (config->cacerts)
      sk_X509_pop_free(config->cacerts, X509_free);
    free(config->certificate_file);
    free(config->key_file);
    free(config->cipher_list);
    free(config->ecdh_curve);
    if ( config->crl_list )
      sk_X509_CRL_pop_free(config->crl_list, X509_CRL_free);
    for (i = 0; i < config->num_cert_key_pairs; i++)
    { X509_free(config->cert_key_pairs[i].certificate_X509);
      free(config->cert_key_pairs[i].certificate);
      free(config->cert_key_pairs[i].key);
    }
    free(config->password);
    X509_free(config->peer_cert);

    if (config->cb_sni.goal) PL_erase(config->cb_sni.goal);
    if (config->cb_pem_passwd.goal) PL_erase(config->cb_pem_passwd.goal);
    if (config->cb_cert_verify.goal) PL_erase(config->cb_cert_verify.goal);
    if (config->cb_alpn_proto.goal) PL_erase(config->cb_alpn_proto.goal);
    if (config->alpn_protos) free(config->alpn_protos);

    free(config);
    ssl_deb(1, "Released config structure\n");
  } else
  { ssl_deb(1, "No config structure to release\n");
  }
}

#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
static int
#else
static void
#endif
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

#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
    /*
     * 1 = success
     * 0 = failure
     */
    return (config != NULL);
#endif
}

static int
ssl_config_dup  ( CRYPTO_EX_DATA *  to
                ,
#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
                  CRYPTO_EX_DATA *  from
#else
                  const CRYPTO_EX_DATA *  from
#endif
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
    if ( config->hostname_check_status == 0 && config->role == PL_SSL_CLIENT ) /* Not yet checked, and is a client - do not check for server */
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
      X509 *cert = X509_STORE_CTX_get0_cert(ctx);

      STACK_OF(GENERAL_NAME) *alt_names = X509_get_ext_d2i((X509 *)cert, NID_subject_alt_name, NULL, NULL);
      int alt_names_count = 0;

      /* First, set status to 1 (invalid) */
      config->hostname_check_status = 1;
      if ( config->host != NULL)
      { if (alt_names != NULL)
        { alt_names_count = sk_GENERAL_NAME_num(alt_names);
          for (i = 0; i < alt_names_count && config->hostname_check_status != 2; i++)
          { const GENERAL_NAME *name = sk_GENERAL_NAME_value(alt_names, i);
            /* We are only interested in DNS names. We may also want to do IP addresses in future, by extending
               the type of config->host
            */
            if (name->type == GEN_DNS)
            { const char* hostname = (const char*)ASN1_STRING_get0_data(name->d.dNSName);
              size_t hostlen = ASN1_STRING_length(name->d.dNSName);
              if (hostlen == strlen(config->host) &&
                  strcmp(config->host, hostname) == 0)
              { config->hostname_check_status = 2;
                ssl_deb(3, "Host that matches found in SAN %d: %s\n", i, ASN1_STRING_get0_data(name->d.dNSName));
              } else if (hostlen > 2 && hostname[0] == '*' && hostname[1] == '.' && strlen(hostname) == hostlen)
              { char* subdomain = strchr(config->host, '.');
                if (subdomain != NULL && strcmp(&hostname[1], subdomain) == 0)
                { config->hostname_check_status = 2;
                  ssl_deb(3, "Host that matches with wildcard found in SAN %d: %s\n", i, hostname);
                }
              }
              else
                ssl_deb(3, "Host does not match SAN %d: %s\n", i, ASN1_STRING_get0_data(name->d.dNSName));
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
              { if (ASN1_STRING_length(common_name_asn1) == strlen(config->host) &&
                    strcmp(config->host, (const char*)ASN1_STRING_get0_data(common_name_asn1)) == 0)
                { config->hostname_check_status = 2;
                  ssl_deb(3, "Hostname in SN matches: %s\n", ASN1_STRING_get0_data(common_name_asn1));
                }
                else
                  ssl_deb(3, "Hostname in SN does not match: %s vs %s\n", ASN1_STRING_get0_data(common_name_asn1), config->host);
              }
            }
          }
        }
      }
      if ( config->hostname_check_status == 1 )
      { ssl_deb(3, "Hostname could not be verified!\n");
        if ( config->cb_cert_verify.goal != NULL )
        { X509 *cert = X509_STORE_CTX_get_current_cert(ctx);
          preverify_ok = (pl_cert_verify_hook(config, cert, ctx, "hostname_mismatch", 0) != 0);
        }
        else
          /* Reject the whole chain if the hostname verification fails and there is no hook to override it */
          preverify_ok = 0;
      }
    }
#endif

    if ( !preverify_ok || config->cb_cert_verify.goal != NULL ) {
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

        if (config->cb_cert_verify.goal) {
          preverify_ok = (pl_cert_verify_hook(config, cert, ctx, error, error_unknown) != 0);
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

    if (config->cb_pem_passwd.goal) {
        /*
         * Callback installed
         */
        passwd = pl_pem_passwd_hook(config, buf, size);
    } else
    if (config->password) {
        /*
         * Password defined
         */
        passwd = config->password;
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


#ifndef OPENSSL_NO_TLSEXT
static int
ssl_cb_sni(SSL *s, int *ad, void *arg)
{
  PL_SSL *config = (PL_SSL *) arg,
         *new_config = NULL;
  const char *servername;

  if ( (servername = SSL_get_servername(s, TLSEXT_NAMETYPE_host_name)) != NULL )
    new_config = pl_sni_hook(config, servername);

  if ( new_config == NULL &&
       config->certificate_file == NULL &&
       config->num_cert_key_pairs == 0 )
    return SSL_TLSEXT_ERR_NOACK;

  SSL_set_SSL_CTX(s, new_config ? new_config->ctx : config->ctx );

  return SSL_TLSEXT_ERR_OK;
}
#endif


static int
ssl_close(PL_SSL_INSTANCE *instance)
{ int ret = 0;

  if ( instance )
  { if ( (instance->config->role != PL_SSL_SERVER) ||
	 instance->config->close_notify )
    { /* Send SSL/TLS close_notify, if no fatal alert has occurred. */
      if ( !instance->fatal_alert )
      { switch(SSL_shutdown(instance->ssl))
	{ case  1: break;		/* ok */
	  case  2: break;		/* TBD: not yet completed */
	  case  3: break;		/* TBD: undocumented */
	  case -1: ret = -1;		/* I/O error */
	}
      }
    }

      if ( instance->ssl )
        SSL_free(instance->ssl);

    if ( instance->swrite )
      Sset_filter(instance->swrite, NULL);
    if ( instance->sread )
      Sset_filter(instance->sread, NULL);

    if ( instance->config->close_parent )
    { if ( instance->swrite )
	ret += Sclose(instance->swrite);
      if ( instance->sread )
	ret += Sclose(instance->sread);
    }

    ssl_deb(4, "Decreasing atom count on %d\n", instance->config->atom);
    PL_unregister_atom(instance->config->atom);

    free(instance);
  }
#if OPENSSL_VERSION_NUMBER < 0x10100000L
  ERR_free_strings();
#endif

  ssl_deb(1, "Controlled close: %d\n", ret);
  return ret == 0 ? 0 : -1;
}



static X509 *
ssl_peer_certificate(PL_SSL_INSTANCE *instance)
{ if ( !instance->config->peer_cert )
    instance->config->peer_cert = SSL_get_peer_certificate(instance->ssl);

  return instance->config->peer_cert;
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


static PL_SSL *
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
        config->ctx  = ssl_ctx;
        config->role = role;
        config->peer_cert_required = (role != PL_SSL_SERVER);

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


#if !defined(__WINDOWS__) && !defined(HAVE_SECURITY_SECURITY_H)
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
#endif

/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
ssl_system_verify_locations() adds trusted  root   certificates  from OS
dependent locations if cacert_file(system(root_certificates)) is passed.

The code is written after this StackOverflow message
http://stackoverflow.com/questions/10095676/openssl-reasonable-default-for-trusted-ca-certificates
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */

static STACK_OF(X509) *
ssl_system_verify_locations(void)
{ STACK_OF(X509) *system_certs = sk_X509_new_null();
  int ok = TRUE;

  if (!system_certs) return NULL;

#ifdef __WINDOWS__
  HCERTSTORE hSystemStore;

  if ( (hSystemStore = CertOpenSystemStore(0, "ROOT")) )
  { PCCERT_CONTEXT pCertCtx = NULL;

    while( (pCertCtx=CertEnumCertificatesInStore(hSystemStore, pCertCtx)) )
    { const unsigned char *ce = (unsigned char*)pCertCtx->pbCertEncoded;

      X509 *cert = d2i_X509(NULL, &ce, (int)pCertCtx->cbCertEncoded);
      if ( cert )
      { if ( !sk_X509_push(system_certs, cert) )
        { ok = FALSE;
          break;
        }
      }
    }

    CertCloseStore(hSystemStore, 0);
  }
#elif defined(HAVE_SECURITY_SECURITY_H) /* __APPLE__ */
  SecKeychainRef keychain = NULL;
  OSStatus status;
  const char* keystoreLocations[] = {"/System/Library/Keychains/SystemRootCertificates.keychain",
                                     "/Library/Keychains/System.keychain",
                                     NULL};
  for (const char** keystoreLocation = keystoreLocations; *keystoreLocation; keystoreLocation++)
  { status = SecKeychainOpen(*keystoreLocation, &keychain);
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
          { if ( !sk_X509_push(system_certs, x509) )
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
  }
#else
{ const char *cacert_filename;
  if ( (cacert_filename = system_cacert_filename()) )
  { X509 *cert = NULL;
    FILE *cafile = fopen(cacert_filename, "rb");

    ssl_deb(1, "cacert_filename = %s\n", cacert_filename);

    if ( cafile != NULL )
    { while ((cert = PEM_read_X509(cafile, NULL, NULL, NULL)) != NULL)
      { if ( !sk_X509_push(system_certs, cert) )
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
  { return system_certs;
  } else
  { sk_X509_pop_free(system_certs, X509_free);
    return NULL;                                /* no memory */
  }
}


static STACK_OF(X509) *
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
{ if ( config->cacerts )
  { X509_STORE *store = X509_STORE_new();
    if ( store )
    { int index = 0;
      /* We make a duplicate of the certificate here since config->cacerts will be cleaned
         up when the context is freed, but the store will also free all the certificates it
         contains when the SSL object underlying the context is freed
      */
      while (index < sk_X509_num(config->cacerts))
      { X509_STORE_add_cert(store, X509_dup(sk_X509_value(config->cacerts, index++)));
      }
      SSL_CTX_set_cert_store(config->ctx, store);
    }
    ssl_deb(1, "certificate authority(s) installed from individual certificates\n");
  }
  if ( config->crl_list )
  { X509_STORE *store = SSL_CTX_get_cert_store(config->ctx);
    int i = 0;
    while (i < sk_X509_CRL_num(config->crl_list))
    { X509_STORE_add_crl(store, sk_X509_CRL_value(config->crl_list, i));
    /*
      Sdprintf("Added a CRL...\n");
      BIO * bio = BIO_new_fp(stdout, BIO_NOCLOSE);
      X509_CRL_print(bio, sk_X509_CRL_value(config->crl_list, i));
      BIO_free(bio);
    */
      i++;
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
static DH *
get_dh2048(void)
        {
        static unsigned char dhp_2048[]={
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
        static unsigned char dhg_2048[]={
                0x02,
                };

        DH *dh = DH_new();
        if (dh == NULL) return NULL;

#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
        dh->p=BN_bin2bn(dhp_2048,sizeof(dhp_2048),NULL);
        dh->g=BN_bin2bn(dhg_2048,sizeof(dhg_2048),NULL);
        if ((dh->p == NULL) || (dh->g == NULL))
          { DH_free(dh); return(NULL); }
#else
        BIGNUM *dhp_bn, *dhg_bn;

        dhp_bn = BN_bin2bn(dhp_2048, sizeof (dhp_2048), NULL);
        dhg_bn = BN_bin2bn(dhg_2048, sizeof (dhg_2048), NULL);
        if (dhp_bn == NULL || dhg_bn == NULL
            || !DH_set0_pqg(dh, dhp_bn, NULL, dhg_bn)) {
          DH_free(dh);
          BN_free(dhp_bn);
          BN_free(dhg_bn);
          return NULL;
        }
#endif
        return dh;
        }


#ifndef SSL_CTX_add0_chain_cert
#define SSL_CTX_add0_chain_cert(CTX, C) SSL_CTX_add_extra_chain_cert(CTX, C)
#endif

static int
ssl_use_certificate(PL_SSL *config, char *certificate, X509 **ret)
{
  X509 *certX509;

  BIO *bio = BIO_new_mem_buf(certificate, -1);

  if ( !bio )
    return PL_resource_error("memory");

  certX509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);
  if ( !certX509 )
    return raise_ssl_error(ERR_get_error());
  *ret = certX509;

  if ( SSL_CTX_use_certificate(config->ctx, certX509) <= 0 )
    return raise_ssl_error(ERR_get_error());

#ifdef SSL_CTX_clear_chain_certs
  if ( SSL_CTX_clear_chain_certs(config->ctx) <= 0 )
    return raise_ssl_error(ERR_get_error());
#endif

  while ( (certX509 = PEM_read_bio_X509(bio, NULL, NULL, NULL)) != NULL )
  { if ( SSL_CTX_add0_chain_cert(config->ctx, certX509) <= 0 )
      return raise_ssl_error(ERR_get_error());
  }
  ERR_clear_error(); /* clear error from "no further certificate" */

  BIO_free(bio);

  return TRUE;
}

static int
ssl_use_key(PL_SSL *config, char *key)
{
  BIO* bio = BIO_new_mem_buf(key, -1);
  EVP_PKEY *pkey;
  int r;

  if ( !bio )
    return PL_resource_error("memory");

  pkey = PEM_read_bio_PrivateKey(bio, NULL, ssl_cb_pem_passwd, config);
  BIO_free(bio);

  if ( !pkey )
    return raise_ssl_error(ERR_get_error());

  r = SSL_CTX_use_PrivateKey(config->ctx, pkey);
  EVP_PKEY_free(pkey);

  if ( r <= 0 )
    return raise_ssl_error(ERR_get_error());
  return TRUE;
}

/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
   Certificates and keys can be specified as files or via
   certificate_key_pairs/1.
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */

static int
ssl_use_certificates(PL_SSL *config)
{
  int cert_idx;

  if ( config->certificate_file &&
       SSL_CTX_use_certificate_chain_file(config->ctx,
                                          config->certificate_file) <= 0 )
    return raise_ssl_error(ERR_get_error());

  if ( config->key_file &&
       SSL_CTX_use_PrivateKey_file(config->ctx,
                                   config->key_file,
                                   SSL_FILETYPE_PEM) <= 0 )
    return raise_ssl_error(ERR_get_error());

  if ( ( config->key_file || config->certificate_file ) &&
       ( SSL_CTX_check_private_key(config->ctx) <= 0 ) )
  { ssl_deb(1, "Private key does not match certificate public key\n");
    return raise_ssl_error(ERR_get_error());
  }


  for (cert_idx = 0; cert_idx < config->num_cert_key_pairs; cert_idx++)
  { X509 *cert_x509;
    if ( !ssl_use_certificate(config, config->cert_key_pairs[cert_idx].certificate, &cert_x509) ||
         !ssl_use_key(config, config->cert_key_pairs[cert_idx].key) )
      return FALSE;
    config->cert_key_pairs[cert_idx].certificate_X509 = cert_x509;
  }
  return TRUE;
}

static void
ssl_init_sni(PL_SSL *config)
{
#ifndef OPENSSL_NO_TLSEXT
  if ( config->role == PL_SSL_SERVER &&
       config->cb_sni.goal ) {
    SSL_CTX_set_tlsext_servername_callback(config->ctx, ssl_cb_sni);
    SSL_CTX_set_tlsext_servername_arg(config->ctx, config);
    ssl_deb(1, "installed SNI callback\n");
  }
#endif
}

static void
ssl_init_min_max_protocol(PL_SSL *config)
{
#ifdef SSL_CTX_set_min_proto_version
  if (config->min_protocol.is_set)
    SSL_CTX_set_min_proto_version(config->ctx, config->min_protocol.version);
#endif
#ifdef SSL_CTX_set_max_proto_version
  if (config->max_protocol.is_set)
    SSL_CTX_set_max_proto_version(config->ctx, config->max_protocol.version);
#endif
}


#ifdef HAVE_SSL_CTX_SET_ALPN_PROTOS

static int
ssl_server_alpn_select_cb(SSL *ssl,
			  const unsigned char **out, unsigned char *outlen,
			  const unsigned char *in, unsigned int inlen,
			  void *arg)
{ PL_SSL *config = (PL_SSL*)arg;

  if ( config->cb_alpn_proto.goal )
  { fid_t fid;
    int ret = SSL_TLSEXT_ERR_ALERT_FATAL;

    if ( (fid = PL_open_foreign_frame()) )
    { term_t av, protos_list, protos_list_tail, head;
      unsigned int in_pos = 0;

      if ( !(av = PL_new_term_refs(5)) ||
	   !(protos_list = PL_new_term_ref()) ||
	   !(protos_list_tail = PL_copy_term_ref(protos_list)) ||\
	   !(head = PL_new_term_ref()) ||
	   !PL_put_list(protos_list) )
	goto out;

      while (in_pos < inlen)
      { unsigned char proto_len = in[in_pos];
	const unsigned char* proto = in + in_pos + 1;

	if ( !PL_unify_list_ex(protos_list_tail, head, protos_list_tail) ||
	     !PL_unify_chars(head, PL_ATOM|REP_UTF8, proto_len, (char*)proto) )
	  goto out;
	in_pos += proto_len + 1;
      }
      if ( !PL_unify_nil(protos_list_tail) )
	goto out;

      predicate_t call5 = PL_predicate("call", 5, "system");

      /*
       * call(CB, +SSL0, +ClientProtos, -SSL1, -SelectedProtocol)
       */
      if ( !PL_recorded(config->cb_alpn_proto.goal, av+0) ||
	   !PL_put_atom(av+1, config->atom) ||
	   !PL_unify(av+2, protos_list) )
	goto out;

      if ( !PL_call_predicate(config->cb_alpn_proto.module,
	                      PL_Q_PASS_EXCEPTION, call5, av) )
	goto out;

      PL_SSL *new_config = NULL;
      if ( !get_conf(av+3, &new_config) )
      { PL_warning("alpn_protocol_hook return wrong type");
	goto out;
      }
      SSL_set_SSL_CTX(ssl, new_config ? new_config->ctx : config->ctx);

      char *str;
      size_t olen;
      if ( PL_get_nchars(av+4, &olen, &str,
			 CVT_ATOM|CVT_STRING|REP_UTF8|CVT_EXCEPTION) )
      { unsigned int i = 0;

        while (i < inlen)
        { unsigned char plen = in[i];
          const unsigned char *pstr = in + i + 1;
          if ( plen == olen && strncmp(str, (const char*)pstr, plen) == 0 )
            { *out = pstr;
              *outlen = plen;
              ret = SSL_TLSEXT_ERR_OK;
              goto out;
            }
          i += plen + 1;
        }
      } else
      { PL_domain_error("alpn protocol", av+4);
      }

    out:
      PL_close_foreign_frame(fid);
    }

    return ret;
  } else
  { int ret = SSL_select_next_proto((unsigned char**)out, outlen,
				    config->alpn_protos, config->alpn_protos_len,
				    in, inlen);
    if ( ret == OPENSSL_NPN_NEGOTIATED )
      return SSL_TLSEXT_ERR_OK;
    else
      return SSL_TLSEXT_ERR_ALERT_FATAL;
  }
}

static void
ssl_init_alpn_protos(PL_SSL *config)
{
  if ( config->alpn_protos ||
       ( config->role == PL_SSL_SERVER && config->cb_alpn_proto.goal ) ) {
    if ( config->role == PL_SSL_CLIENT ) {
      SSL_CTX_set_alpn_protos(config->ctx, config->alpn_protos, config->alpn_protos_len);
    } else if ( config->role == PL_SSL_SERVER ) {
      SSL_CTX_set_alpn_select_cb(config->ctx, &ssl_server_alpn_select_cb, config);
    }
  }
}

#endif /*HAVE_SSL_CTX_SET_ALPN_PROTOS*/

static int
set_malleable_options(PL_SSL *config)
{

#ifndef OPENSSL_NO_EC
  EC_KEY *ecdh;
  int nid;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
  char *curve = "prime256v1";
#else
  /* In OpenSSL >= 1.1.0, ECDH support is always enabled.  Therefore,
   * if ecdh_curve/1 is not specified, we use the existing defaults.
   *
   * In fact, OpenSSL 1.1.0 provides the new function
   * SSL_CTX_set1_groups, which generalizes SSL_CTX_set_tmp_ecdh in
   * that it lets us specify a *set* of curves and other groups.
   * We should provide a binding for the more general function.
   */
  char *curve = NULL;
#endif

  if (config->ecdh_curve)
    curve = config->ecdh_curve;

  if (curve)
  { nid = OBJ_sn2nid(curve);
    if ( !(ecdh = EC_KEY_new_by_curve_name(nid)) )
      return raise_ssl_error(ERR_get_error());
    if ( !SSL_CTX_set_tmp_ecdh(config->ctx, ecdh) )
      return raise_ssl_error(ERR_get_error());
    EC_KEY_free(ecdh);          /* Safe because of reference counts */
  }
#endif

  if ( config->cipher_list &&
       !SSL_CTX_set_cipher_list(config->ctx, config->cipher_list))
    return raise_ssl_error(ERR_get_error());

  (void) SSL_CTX_set_verify(config->ctx,
                            config->peer_cert_required ?
                                SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT :
                                SSL_VERIFY_NONE,
                            ssl_cb_cert_verify);
  ssl_deb(1, "installed certificate verification handler\n");

  ssl_init_sni(config);
  ssl_init_min_max_protocol(config);
#ifdef HAVE_SSL_CTX_SET_ALPN_PROTOS
  ssl_init_alpn_protos(config);
#endif

  return TRUE;
}


static int
ssl_config(PL_SSL *config)
/*
 * Initialize various SSL layer parameters using the supplied
 * config parameters.
 */
{ static DH *dh_2048 = NULL;

  ssl_init_verify_locations(config);

  SSL_CTX_set_default_passwd_cb_userdata(config->ctx, config);
  SSL_CTX_set_default_passwd_cb(config->ctx, ssl_cb_pem_passwd);
  ssl_deb(1, "password handler installed\n");

  if ( config->certificate_file ||
       config->key_file ||
       ( config->num_cert_key_pairs > 0 ) )
  { if ( !ssl_use_certificates(config) )
      return FALSE;
    ssl_deb(1, "certificates installed successfully\n");
  }

  if ( !dh_2048 ) dh_2048 = get_dh2048();
  SSL_CTX_set_tmp_dh(config->ctx, dh_2048);

  return set_malleable_options(config);
}


static PL_SSL_INSTANCE *
ssl_instance_new(PL_SSL *config, IOSTREAM* sread, IOSTREAM* swrite)
{ PL_SSL_INSTANCE *new = NULL;

  if ((new = malloc(sizeof(PL_SSL_INSTANCE))) != NULL)
  { memset(new, 0, sizeof(*new));
    new->config = config;
    new->sread  = sread;
    new->swrite = swrite;
    new->fatal_alert = FALSE;
  }

  return new;
}

static int
ssl_lib_init(void)
/*
 * One-time library initialization code
 */
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
    (void) SSL_library_init();
    SSL_load_error_strings();
#endif

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
    FUNCTOR_error2     = PL_new_functor(PL_new_atom("error"),     2);
    FUNCTOR_ssl_error4 = PL_new_functor(PL_new_atom("ssl_error"), 4);
#endif

    return 0;
}

static int
ssl_lib_exit(void)
/*
 * One-time library exit calls
 */
{
    return 0;
}


/*
 * Establish an SSL session using the given read and write streams
 * and the role
 */
static int
ssl_ssl_bio(PL_SSL *config, IOSTREAM* sread, IOSTREAM* swrite,
            PL_SSL_INSTANCE** instancep)
{ PL_SSL_INSTANCE *instance;
  BIO *rbio = BIO_new(bio_read_method());
  BIO *wbio = BIO_new(bio_write_method());

  if ( rbio == NULL ||
       wbio == NULL )
    return raise_ssl_error(ERR_get_error());

  if ( !(instance=ssl_instance_new(config, sread, swrite)) )
    return PL_resource_error("memory");

  BIO_set_ex_data(rbio, 0, sread);
  BIO_set_ex_data(wbio, 0, swrite);

  if ( config->crl_required )
  { X509_STORE_set_flags(SSL_CTX_get_cert_store(config->ctx),
                         X509_V_FLAG_CRL_CHECK|X509_V_FLAG_CRL_CHECK_ALL);
  }


  if ( !(instance->ssl = SSL_new(config->ctx)) )
  { free(instance);
    return raise_ssl_error(ERR_get_error());
  }

  if ( config->role == PL_SSL_CLIENT )
  {
#ifndef OPENSSL_NO_TLSEXT
    if ( config->host )
      SSL_set_tlsext_host_name(instance->ssl, config->host);
#endif
#ifdef HAVE_X509_CHECK_HOST
#if (defined(HAVE_X509_VERIFY_PARAM_ID) || OPENSSL_VERSION_NUMBER >= 0x10100000L) && !defined(LIBRESSL_VERSION_NUMBER)
    X509_VERIFY_PARAM *param = SSL_get0_param(instance->ssl);
    /* This could in theory be user-configurable. The documentation at
       https://wiki.openssl.org/index.php/Manual:X509_check_host(3)
       says that the flag is 'usually 0', however
    */
 /* X509_VERIFY_PARAM_set_hostflags(param,
                                    X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
 */
    X509_VERIFY_PARAM_set_hostflags(param, 0);
    X509_VERIFY_PARAM_set1_host(param, config->host, 0);
#endif
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
            config->role == PL_SSL_SERVER ? "server" : "client");
    ssl_ret = (config->role == PL_SSL_SERVER ?
                 SSL_accept(instance->ssl) :
                 SSL_connect(instance->ssl));

    switch( ssl_inspect_status(instance, ssl_ret, STAT_NEGOTIATE) )
    { case SSL_PL_OK:
        ssl_deb(1, "established ssl connection\n");
        *instancep = instance;
#if defined(TLS1_3_VERSION) && defined(EPIPE)
	if ( config->role == PL_SSL_SERVER &&
	     strcmp(SSL_get_version(instance->ssl), "TLSv1.3") == 0 &&
	     SSL_get_error(instance->ssl, 0) == SSL_ERROR_SYSCALL &&
	     errno == EPIPE )
	{ Sclearerr(swrite); PL_clear_exception();
	}
#endif
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
static ssize_t
ssl_read(void *handle, char *buf, size_t size)
{ PL_SSL_INSTANCE *instance = handle;
  SSL *ssl = instance->ssl;

  assert(ssl != NULL);

  for(;;)
  { int rbytes = SSL_read(ssl, buf, size);

    switch(ssl_inspect_status(instance, rbytes, STAT_READ))
    { case SSL_PL_OK:
        if (rbytes <= 0)        /* SSL_read() returns -1 on EOF in OpenSSL 1.1.0c! */
          return 0;             /* We handle EOF in Prolog. */
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
static ssize_t
ssl_write(void *handle, char *buf, size_t size)
{ PL_SSL_INSTANCE *instance = handle;
  SSL *ssl = instance->ssl;

  assert(ssl != NULL);

  for(;;)
  { int wbytes = SSL_write(ssl, buf, size);

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

static int
protocol_version_to_integer(const term_t symbol, int *version)
{
  atom_t arg;

  if ( !PL_get_atom_ex(symbol, &arg) )
    return FALSE;

#ifdef SSL_CTX_set_min_proto_version
  if ( arg == ATOM_sslv3 )
    *version = SSL3_VERSION;
  else if ( arg == ATOM_tlsv1 )
    *version = TLS1_VERSION;
  else if ( arg == ATOM_tlsv1_1 )
    *version = TLS1_1_VERSION;
  else if ( arg == ATOM_tlsv1_2 )
    *version = TLS1_2_VERSION;
#ifdef TLS1_3_VERSION
  else if ( arg == ATOM_tlsv1_3 )
    *version = TLS1_3_VERSION;
#endif
  else
    return PL_domain_error("ssl_protocol_version", symbol);
#else
  *version = 0;                 /* prevent compiler warning */
#endif

  return TRUE;
}

/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
   We call an option *malleable* if it can be set not only when the
   context is created, but also later via ssl_set_options/3. Not all
   options fall into this category: Notably, it is not yet documented
   what OpenSSL does if a certificate and key are later replaced.

   Therefore, we split option processing between malleable options and
   those that can only be set when the context is being created.

   Note an important design principle:

   We *never* destructively modify an existing Prolog SSL context.
   ---------------------------------------------------------------

   Instead, when setting any options for an existing context, the
   context is always first duplicated, and the options are set on the
   copy! This is critical to ensure that all code stays thread-safe at
   the Prolog level.

   I mention this explicitly because the OpenSSL API makes it
   extremely tempting to modify some paramaters destructively.
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */

static int
parse_malleable_options(PL_SSL *conf, module_t module, term_t options)
{ term_t tail = PL_copy_term_ref(options);
  term_t head = PL_new_term_ref();

  while( PL_get_list_ex(tail, head, tail) )
  { atom_t name;
    size_t arity;

    if ( !PL_get_name_arity(head, &name, &arity) )
      return PL_type_error("ssl_option", head);

    if ( name == ATOM_cipher_list && arity == 1 )
    { char *s;

      if ( !get_char_arg(1, head, &s) )
	return FALSE;

      if (conf->cipher_list) free(conf->cipher_list);
      conf->cipher_list = ssl_strdup(s);
    } else if ( name == ATOM_ecdh_curve && arity == 1 )
    { char *s;

      if ( !get_char_arg(1, head, &s) )
	return FALSE;

      if (conf->ecdh_curve) free(conf->ecdh_curve);
      conf->ecdh_curve = ssl_strdup(s);
    } else if ( name == ATOM_host && arity == 1 )
    { char *s;

      if ( !get_char_arg(1, head, &s) )
	return FALSE;

      if (conf->host) free(conf->host);
      conf->host = ssl_strdup(s);
    } else if ( name == ATOM_peer_cert && arity == 1 )
    { int val;

      if ( !get_bool_arg(1, head, &val) )
	return FALSE;

      conf->peer_cert_required = val;
    } else if ( name == ATOM_cert_verify_hook && arity == 1 )
    { term_t cb = PL_new_term_ref();
      _PL_get_arg(1, head, cb);

      if (conf->cb_cert_verify.goal)
        PL_erase(conf->cb_cert_verify.goal);

      conf->cb_cert_verify.goal   = PL_record(cb);
      conf->cb_cert_verify.module = module;
    } else if ( name == ATOM_close_parent && arity == 1 )
    { int val;

      if ( !get_bool_arg(1, head, &val) )
	return FALSE;

      conf->close_parent = val;
    } else if ( name == ATOM_disable_ssl_methods && arity == 1 )
    { term_t opt_head = PL_new_term_ref();
      term_t opt_tail = PL_new_term_ref();
      long options = 0;
      long isset;

      _PL_get_arg(1, head, opt_tail);
      while( PL_get_list_ex(opt_tail, opt_head, opt_tail) )
      {  atom_t option_name;
         if ( !PL_get_atom_ex(opt_head, &option_name) )
            return FALSE;
         if (option_name == ATOM_sslv2)
            options |= SSL_OP_NO_SSLv2;
         else if (option_name == ATOM_sslv23)
            options |= SSL_OP_NO_SSLv3 | SSL_OP_NO_SSLv2;
         else if (option_name == ATOM_sslv3)
            options |= SSL_OP_NO_SSLv3;
#ifdef SSL_OP_NO_TLSv1
         else if (option_name == ATOM_tlsv1)
            options |= SSL_OP_NO_TLSv1;
#endif
#ifdef SSL_OP_NO_TLSv1_1
         else if (option_name == ATOM_tlsv1_1)
            options |= SSL_OP_NO_TLSv1_1;
#endif
#ifdef SSL_OP_NO_TLSv1_2
         else if (option_name == ATOM_tlsv1_2)
            options |= SSL_OP_NO_TLSv1_2;
#endif
      }
      if ( !PL_get_nil_ex(opt_tail) )
	return FALSE;

      if ( (isset=(SSL_CTX_set_options(conf->ctx, options)&options)) != options )
	ssl_deb(1, "SSL_CTX_set_options 0x%lx only set 0x%lx\n", options, isset);
    } else if ( name == ATOM_min_protocol_version && arity == 1 )
    { term_t val = PL_new_term_ref();
      int version;

      _PL_get_arg(1, head, val);

      if ( !protocol_version_to_integer(val, &version) )
        return FALSE;
      conf->min_protocol.is_set  = TRUE;
      conf->min_protocol.version = version;
    } else if ( name == ATOM_max_protocol_version && arity == 1 )
    { term_t val = PL_new_term_ref();
      int version;

      _PL_get_arg(1, head, val);

      if ( !protocol_version_to_integer(val, &version) )
        return FALSE;
      conf->max_protocol.is_set  = TRUE;
      conf->max_protocol.version = version;
    } else if ( name == ATOM_sni_hook && arity == 1 &&
                conf->role == PL_SSL_SERVER )
    { term_t cb = PL_new_term_ref();
      _PL_get_arg(1, head, cb);

      if (conf->cb_sni.goal)
        PL_erase(conf->cb_sni.goal);

      conf->cb_sni.goal   = PL_record(cb);
      conf->cb_sni.module = module;
    } else if ( name == ATOM_close_notify && arity == 1 )
    { int val;

      if ( !get_bool_arg(1, head, &val) )
	return FALSE;

      conf->close_notify = val;
    } else if ( name == ATOM_alpn_protocols && arity == 1 )
    { term_t protos_tail = PL_new_term_ref();
      term_t protos_head = PL_new_term_ref();
      _PL_get_arg(1, head, protos_tail);
      size_t current_size = 0;
      unsigned char *protos_vec = NULL;
      size_t total_length = 0;

      while( PL_get_list_ex(protos_tail, protos_head, protos_tail) )
      { char *proto;
	size_t proto_len;

        if ( !PL_get_nchars(protos_head, &proto_len, &proto,
			    CVT_ATOM|CVT_STRING|CVT_EXCEPTION|REP_UTF8|BUF_RING) )
          return FALSE;
        total_length += proto_len + 1;
        if ( total_length > current_size ) {
          unsigned char* new_protos_vec = realloc(protos_vec, total_length);
          if ( new_protos_vec == NULL ) {
            if ( protos_vec != NULL ) free(protos_vec);
            return PL_resource_error("memory");
          } else {
            protos_vec = new_protos_vec;
          }
        }
        protos_vec[current_size] = proto_len;
        memcpy(protos_vec + current_size + 1, proto, proto_len);
        current_size = total_length;
      }
      conf->alpn_protos = protos_vec;
      conf->alpn_protos_len = current_size;
    } else if ( name == ATOM_alpn_protocol_hook && arity == 1 &&
                conf->role == PL_SSL_SERVER )
    { term_t cb = PL_new_term_ref();
      _PL_get_arg(1, head, cb);
      if ( conf->cb_alpn_proto.goal ) PL_erase(conf->cb_alpn_proto.goal);
      conf->cb_alpn_proto.goal = PL_record(cb);
      conf->cb_alpn_proto.module = module;
    } else
      continue;
  }

  return PL_get_nil_ex(tail);
}


static foreign_t
pl_ssl_set_options(term_t config, term_t options)
{ PL_SSL *conf;
  module_t module = NULL;

  if ( !get_conf(config, &conf) )
    return FALSE;

  if ( !PL_strip_module(options, &module, options) )
    return FALSE;

  return
    parse_malleable_options(conf, module, options) &&
    set_malleable_options(conf);
}

static foreign_t
pl_ssl_context(term_t role, term_t config, term_t options, term_t method)
{ atom_t a;
  PL_SSL *conf;
  int r;
  term_t tail;
  term_t head = PL_new_term_ref();
  module_t module = NULL;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
  atom_t method_name;
#endif
  const SSL_METHOD *ssl_method = NULL;

  if ( !PL_strip_module(options, &module, options) )
    return FALSE;
  tail = PL_copy_term_ref(options);

  if ( !PL_get_atom_ex(role, &a) )
    return FALSE;
  if ( a == ATOM_server )
    r = PL_SSL_SERVER;
  else if ( a == ATOM_client )
    r = PL_SSL_CLIENT;
  else
    return PL_domain_error("ssl_role", role);

#if OPENSSL_VERSION_NUMBER < 0x10100000L
  if (!PL_get_atom(method, &method_name))
     return PL_domain_error("ssl_method", method);
  if (method_name == ATOM_sslv23)
    ssl_method = SSLv23_method();
#ifndef OPENSSL_NO_SSL2
  else if (method_name == ATOM_sslv2)
    ssl_method = SSLv2_method();
#endif
#ifndef OPENSSL_NO_SSL3_METHOD
  else if (method_name == ATOM_sslv3)
    ssl_method = SSLv3_method();
#endif
#ifdef SSL_OP_NO_TLSv1
  else if (method_name == ATOM_tlsv1)
    ssl_method = TLSv1_method();
#endif
#ifdef SSL_OP_NO_TLSv1_1
  else if (method_name == ATOM_tlsv1_1)
    ssl_method = TLSv1_1_method();
#endif
#ifdef SSL_OP_NO_TLSv1_2
  else if (method_name == ATOM_tlsv1_2)
    ssl_method = TLSv1_2_method();
#endif
  else
    return PL_domain_error("ssl_method", method);
#else
    ssl_method = TLS_method();  /* In OpenSSL >= 1.1.0, always use TLS_method() */
#endif

  if ( !(conf = ssl_init(r, ssl_method)) )
    return PL_resource_error("memory");
  while( PL_get_list(tail, head, tail) )
  { atom_t name;
    size_t arity;

    if ( !PL_get_name_arity(head, &name, &arity) )
      return PL_type_error("ssl_option", head);

    if ( name == ATOM_password && arity == 1 )
    { char *s;

      if ( !get_char_arg(1, head, &s) )
	return FALSE;

      if (conf->password) free(conf->password);
      conf->password = ssl_strdup(s);
    } else if ( name == ATOM_require_crl && arity == 1 )
    { int val;

      if ( !get_bool_arg(1, head, &val) )
	return FALSE;

      conf->crl_required = val;
    } else if ( name == ATOM_crl && arity == 1 )
    { STACK_OF(X509_CRL) *crls = sk_X509_CRL_new_null();
      term_t list_head = PL_new_term_ref();
      term_t list_tail = PL_new_term_ref();
      _PL_get_arg(1, head, list_tail);
      while( PL_get_list(list_tail, list_head, list_tail) )
      { atom_t crl_name;
        X509_CRL *crl;
        if (PL_is_atom(list_head) && PL_get_atom(list_head, &crl_name))
        { FILE *file = fopen(PL_atom_chars(crl_name), "rb");
          if ( file )
          { crl = PEM_read_X509_CRL(file, NULL, NULL, NULL);
            sk_X509_CRL_push(crls, crl);
          } else
            return PL_existence_error("file", list_head);
        }
      }
      if (conf->crl_list)
        sk_X509_CRL_pop_free(conf->crl_list, X509_CRL_free);
      conf->crl_list = crls;
    } else if ( name == ATOM_certificate_file && arity == 1 )
    { char *file;

      if ( !get_file_arg(1, head, &file) )
	return FALSE;

      if (conf->certificate_file) free(conf->certificate_file);
      conf->certificate_file = ssl_strdup(file);
    } else if ( name == ATOM_cacerts && arity == 1 )
    { term_t CATail = PL_new_term_ref();
      term_t CAHead = PL_new_term_ref();
      _PL_get_arg(1, head, CATail);
      if (conf->cacerts)
	sk_X509_pop_free(conf->cacerts, X509_free);
      conf->cacerts = sk_X509_new_null();
      while (PL_get_list_ex(CATail, CAHead, CATail))
      { X509* cert = NULL;
        if (PL_is_functor(CAHead, FUNCTOR_certificate1))
        { _PL_get_arg(1, CAHead, CAHead);
          if (!get_certificate_blob(CAHead, &cert))
	  { sk_X509_pop_free(conf->cacerts, X509_free);
	    conf->cacerts = NULL;
	    return FALSE;
	  }
	  /* Duplicate the certificate here so that if it is freed by AGC the
	     certificate is still valid in conf->cacerts.
	     The duplicates will be cleaned up when the conf is freed
	  */
	  sk_X509_push(conf->cacerts, X509_dup(cert));
	}
	else if (PL_is_functor(CAHead, FUNCTOR_file1))
	{ char *file;
	  _PL_get_arg(1, CAHead, CAHead);
	  /* These certificate(s) will be cleaned up when the conf is freed */
	  if ( !PL_get_file_name(CAHead, &file, PL_FILE_EXIST) || !load_certificates_from_file(file, conf->cacerts))
	  { sk_X509_pop_free(conf->cacerts, X509_free);
	    conf->cacerts = NULL;
	    return FALSE;
	  }
	}
	else if (PL_is_functor(CAHead, FUNCTOR_system1))
	{ _PL_get_arg(1, CAHead, CAHead);
	  atom_t a;
	  if ( !PL_get_atom_ex(CAHead, &a) )
	    return FALSE;
	  if ( a == ATOM_root_certificates )
	  { STACK_OF(X509) *system_certs = system_root_certificates();
	    if ( system_certs )
	    { int index = 0;
	      /* We make a copy of all the system certs here since we later free all the
		 certificates and do not want to free the ones in the system_root_certificates
		 stack. The duplicates will be cleaned up when the conf is freed
	      */
	      while (index < sk_X509_num(system_certs))
	      { sk_X509_push(conf->cacerts, X509_dup(sk_X509_value(system_certs, index++)));
	      }
	    }
	  }
	}
      }
      if (!PL_get_nil_ex(CATail))
      { sk_X509_pop_free(conf->cacerts, X509_free);
	conf->cacerts = NULL;
	return FALSE;
      }
    } else if ( name == ATOM_certificate_file && arity == 1 )
    { char *file;

      if ( !get_file_arg(1, head, &file) )
	return FALSE;

      if (conf->certificate_file) free(conf->certificate_file);
      conf->certificate_file = ssl_strdup(file);
    } else if ( name == ATOM_certificate_key_pairs && arity == 1 )
    { term_t cert_head = PL_new_term_ref();
      term_t cert_tail = PL_new_term_ref();
      _PL_get_arg(1, head, cert_tail);
      while( PL_get_list(cert_tail, cert_head, cert_tail) )
      { atom_t name;
        char *certificate, *key;
        int idx = conf->num_cert_key_pairs;

        if ( idx >= SSL_MAX_CERT_KEY_PAIRS )
          return PL_domain_error("fewer_certificates", options);

        ssl_deb(4, "loading certificate/key pair with index %d\n", idx);

        if ( !PL_get_name_arity(cert_head, &name, &arity) ||
             name != ATOM_minus ||
             arity != 2 )
          return PL_type_error("pair", cert_head);

        if ( !get_char_arg(1, cert_head, &certificate) )
          return FALSE;
        if ( !get_char_arg(2, cert_head, &key) )
          return FALSE;

        conf->cert_key_pairs[idx].certificate = ssl_strdup(certificate);
        conf->cert_key_pairs[idx].key         = ssl_strdup(key);
        conf->num_cert_key_pairs++;
      }
      if ( !PL_get_nil_ex(cert_tail) )
        return FALSE;
    } else if ( name == ATOM_key_file && arity == 1 )
    { char *file;

      if ( !get_file_arg(1, head, &file) )
	return FALSE;

      if (conf->key_file) free(conf->key_file);
      conf->key_file = ssl_strdup(file);
    } else if ( name == ATOM_pem_password_hook && arity == 1 )
    { term_t cb = PL_new_term_ref();
      _PL_get_arg(1, head, cb);
      conf->cb_pem_passwd.goal   = PL_record(cb);
      conf->cb_pem_passwd.module = module;
    } else
      continue;
  }

  if ( !parse_malleable_options(conf, module, options) )
    return FALSE;

  return unify_conf(config, conf) && ssl_config(conf);
}


static int
pl_ssl_close(void *handle)
{ PL_SSL_INSTANCE *instance = handle;

  assert(instance->close_needed > 0);

  if ( --instance->close_needed == 0 )
    return ssl_close(instance);

  return 0;
}


static int
pl_ssl_control(void *handle, int action, void *data)
{ PL_SSL_INSTANCE *instance = handle;

  switch(action)
  {
#ifdef __WINDOWS__
    case SIO_GETFILENO:
      return -1;
    case SIO_GETWINSOCK:
      { if (instance->sread != NULL)
        { (*instance->sread->functions->control)(instance->sread->handle,
                                                 SIO_GETWINSOCK,
                                                 data);
          return 0;
        } else if (instance->swrite != NULL)
        { (*instance->swrite->functions->control)(instance->swrite->handle,
                                                  SIO_GETWINSOCK,
                                                  data);
          return 0;
        }
      }
      return -1;
#else
    case SIO_GETFILENO:
      { if (instance->sread != NULL)
        {  int fd = Sfileno(instance->sread);
           int *fdp = data;
           *fdp = fd;
           return 0;
        } else if (instance->swrite != NULL)
        {  int fd = Sfileno(instance->swrite);
           int *fdp = data;
           *fdp = fd;
           return 0;
        }
      }
      return -1;
#endif
    case SIO_SETENCODING:
    case SIO_FLUSHOUTPUT:
      return 0;
    default:
      return -1;
  }
}


static IOFUNCTIONS ssl_funcs =
{ ssl_read,				/* read */
  ssl_write,				/* write */
  NULL,					/* seek */
  pl_ssl_close,				/* close */
  pl_ssl_control			/* control */
};


/**
 * FIXME: if anything goes wrong, the instance is not reclaimed.
 * Can we simple call free() on it?
 */
static foreign_t
pl_ssl_negotiate(term_t config,
		 term_t org_in, term_t org_out, /* wire streams */
		 term_t in, term_t out)		/* data streams */
{ PL_SSL *conf;
  IOSTREAM *sorg_in = NULL, *sorg_out = NULL;
  IOSTREAM *i, *o;
  PL_SSL_INSTANCE * instance = NULL;
  int rc = FALSE;

  if ( !get_conf(config, &conf) )
    return FALSE;
  if ( !PL_get_stream_handle(org_in, &sorg_in) ||
       !PL_get_stream_handle(org_out, &sorg_out) )
    goto out;

  if ( !(rc = ssl_ssl_bio(conf, sorg_in, sorg_out, &instance)) )
  { rc = raise_ssl_error(ERR_get_error());
    goto out;
  }

  if ( !(i=Snew(instance, SIO_INPUT|SIO_RECORDPOS|SIO_FBUF, &ssl_funcs)) )
  { rc = PL_resource_error("memory");
    goto out;
  }
  instance->close_needed++;
  if ( !PL_unify_stream(in, i) )
  { Sclose(i);
    goto out;
  }
  Sset_filter(sorg_in, i);
  instance->dread = i;

  if ( !(o=Snew(instance, SIO_OUTPUT|SIO_RECORDPOS|SIO_FBUF, &ssl_funcs)) )
  { rc = PL_resource_error("memory");
    goto out;
  }
  instance->close_needed++;
  if ( !PL_unify_stream(out, o) )
  { Sclose(i);
    Sclose(o);
    goto out;
  }
  Sset_filter(sorg_out, o);
  instance->dwrite = o;

  /* Increase atom reference count so that the context is not
     GCd until this session is complete */
  ssl_deb(4, "Increasing count on %d\n", conf->atom);
  PL_register_atom(conf->atom);

out:
  if ( sorg_in  )
  { if ( !rc )
      Sset_filter(sorg_in, NULL);
    PL_release_stream(sorg_in);
  }
  if ( sorg_out )
  { if ( !rc )
      Sset_filter(sorg_out, NULL);
    PL_release_stream(sorg_out);
  }

  return rc;
}

static void
ssl_copy_callback(const PL_SSL_CALLBACK old, PL_SSL_CALLBACK *new)
{
  if (old.goal)
  { new->goal = PL_duplicate_record(old.goal);
    new->module = old.module;
  }
}

/* This is used to avoid casting a function pointer. The second argument of sk_X509_deep_copy
   expects a function with a const argument
*/
static X509 *x509dup(const X509 *cx)
{ X509 *x = (X509 *)cx;
  return X509_dup(x);
}

static foreign_t
pl_ssl_init_from_context(term_t term_old, term_t term_new)
{
  PL_SSL *old, *new;
  int idx;

  if ( !get_conf(term_old, &old) ||
       !get_conf(term_new, &new) )
    return FALSE;

  new->role                = old->role;

  new->password            = ssl_strdup(old->password);

  new->close_parent        = old->close_parent;
  new->close_notify        = old->close_notify;
  new->host                = ssl_strdup(old->host);
  new->cacerts             = old->cacerts?sk_X509_deep_copy(old->cacerts, x509dup, X509_free):NULL;
  new->certificate_file    = ssl_strdup(old->certificate_file);
  new->key_file            = ssl_strdup(old->key_file);
  new->min_protocol        = old->min_protocol;
  new->max_protocol        = old->max_protocol;
  new->peer_cert_required  = old->peer_cert_required;
  new->cipher_list         = ssl_strdup(old->cipher_list);
  new->ecdh_curve          = ssl_strdup(old->ecdh_curve);

#ifndef HAVE_X509_CHECK_HOST
  new->hostname_check_status = old->hostname_check_status;
#endif

  if (old->crl_list)
    new->crl_list          = sk_X509_CRL_dup(old->crl_list);
  new->crl_required        = old->crl_required;

  ssl_copy_callback(old->cb_cert_verify, &new->cb_cert_verify);
  ssl_copy_callback(old->cb_pem_passwd, &new->cb_pem_passwd);
  ssl_copy_callback(old->cb_sni, &new->cb_sni);
  ssl_copy_callback(old->cb_alpn_proto, &new->cb_alpn_proto);

  for (idx = 0; idx < old->num_cert_key_pairs; idx++)
  { new->cert_key_pairs[idx].certificate = ssl_strdup(old->cert_key_pairs[idx].certificate);
    new->cert_key_pairs[idx].key = ssl_strdup(old->cert_key_pairs[idx].key);
    new->num_cert_key_pairs++;
  }

  if ( old->alpn_protos ) {
    unsigned char *protos_copy = malloc(old->alpn_protos_len * sizeof(unsigned char));
    if ( protos_copy == NULL )
      return PL_resource_error("memory");
    memcpy(old->alpn_protos, protos_copy, old->alpn_protos_len);
    new->alpn_protos = protos_copy;
  }

  return ssl_config(new);
}


static foreign_t
pl_ssl_add_certificate_key(term_t config, term_t cert_arg, term_t key_arg)
{ PL_SSL *conf;
  char *cert, *key;
  int idx;
  X509 *certX509;

  if ( !get_conf(config, &conf) )
    return FALSE;

  idx = conf->num_cert_key_pairs;
  if ( idx < SSL_MAX_CERT_KEY_PAIRS &&
       PL_get_chars(cert_arg, &cert, CVT_ATOM|CVT_STRING|CVT_EXCEPTION) &&
       PL_get_chars(key_arg, &key, CVT_ATOM|CVT_STRING|CVT_EXCEPTION) &&
       ssl_use_certificate(conf, cert, &certX509) &&
       ssl_use_key(conf, key) )
  { conf->cert_key_pairs[idx].certificate = ssl_strdup(cert);
    conf->cert_key_pairs[idx].key = ssl_strdup(key);
    conf->cert_key_pairs[idx].certificate_X509 = certX509;

    conf->num_cert_key_pairs++;
    return TRUE;
  }

  return FALSE;
}


static foreign_t
pl_ssl_debug(term_t level)
{ int l;

  if ( !PL_get_integer_ex(level, &l) )
    return FALSE;

  ssl_set_debug(l);

  return TRUE;
}


static int
add_key_string(term_t list, functor_t f, size_t len, const unsigned char*s)
{ term_t tmp;
  int rc;

  rc = ( (tmp = PL_new_term_refs(2)) &&
	 PL_unify_list_ex(list, tmp+0, list) &&
	 PL_put_string_nchars(tmp+1, len, (const char*)s) &&
	 PL_unify_term(tmp+0, PL_FUNCTOR, f, PL_TERM, tmp+1)
       );
  if ( tmp )
    PL_reset_term_refs(tmp);
  return rc;
}


static foreign_t
pl_system_root_certificates(term_t list)
{ STACK_OF(X509) *certs;
  term_t head = PL_new_term_ref();
  term_t tail = PL_copy_term_ref(list);
  int index = 0;

  if ( !(certs=system_root_certificates()) )
    return PL_unify_nil(list);

  while (index < sk_X509_num(certs))
  { if ( !(PL_unify_list(tail, head, tail) &&
           unify_certificate_blob_copy(head, sk_X509_value(certs, index++))) )
    { return FALSE;
    }
  }

  return PL_unify_nil(tail);
}


static foreign_t
pl_verify_certificate(term_t Cert, term_t Chain, term_t Roots)
{ X509* cert = NULL;
  X509_STORE_CTX* ctx = NULL;
  X509_STORE* store = NULL;
  STACK_OF(X509) *chain = NULL;
  STACK_OF(X509) *roots = NULL;
  int rc = 1;
  int index = 0;

  if ( !get_certificate_blob(Cert, &cert))
    return FALSE;

  if ( PL_is_functor(Roots, FUNCTOR_system1) )
  { _PL_get_arg(1, Roots, Roots);
    atom_t a;

    if ( !PL_get_atom_ex(Roots, &a) )
      return FALSE;
    if ( a == ATOM_root_certificates )
      roots = system_root_certificates();
    else
      return PL_domain_error("certificate_list", Roots);
  } else if ( !get_certificate_blobs(Roots, &roots))
    return FALSE;

  if ( !get_certificate_blobs(Chain, &chain))
    rc = FALSE;

  rc &= ((ctx = X509_STORE_CTX_new()) != NULL);
  rc &= ((store = X509_STORE_new()) != NULL);

  /* Add roots to store */
  if (rc)
  { for ( index = 0; index < sk_X509_num(roots); index++ )
      X509_STORE_add_cert(store, sk_X509_value(roots, index));
    Sdprintf("Added %d certificates to the store\n", index);

    rc &= X509_STORE_CTX_init(ctx, store, cert, chain);
    rc &= X509_verify_cert(ctx);
    if (rc <= 0)
      { char msg[1024];
	ERR_error_string(X509_STORE_CTX_get_error(ctx), &msg[0]);
	Sdprintf("Failed to verify certificate: %s (%d)\n", msg, rc);
      }
  }
  if (store != NULL)
    X509_STORE_free(store);
  if (ctx != NULL)
    X509_STORE_CTX_free(ctx);
  if (chain != NULL)
    sk_X509_free(chain);

  if (roots != NULL && roots != system_root_store)
    sk_X509_free(roots);
  return rc;
}

static int
get_ssl_stream(term_t stream_t, IOSTREAM **locked, IOSTREAM **ssl)
{ IOSTREAM *stream, *ssl_stream;

  if ( !PL_get_stream(stream_t, &stream, SIO_INPUT) )
    return FALSE;

  for( ssl_stream = stream;
       ssl_stream && ssl_stream->functions != &ssl_funcs;
       ssl_stream = ssl_stream->downstream )
    ;

  if ( ssl_stream )
  { *locked = stream;
    *ssl    = ssl_stream;

    return TRUE;
  }

  PL_release_stream(stream);
  PL_domain_error("ssl_stream", stream_t);

  return FALSE;
}


static foreign_t
pl_ssl_peer_certificate(term_t stream_t, term_t Cert)
{ IOSTREAM *stream, *ssl_stream;
  PL_SSL_INSTANCE *instance;
  X509 *cert;
  int rc = FALSE;

  if ( !get_ssl_stream(stream_t, &stream, &ssl_stream) )
    return FALSE;

  instance = ssl_stream->handle;
  if ( (cert = ssl_peer_certificate(instance)) )
    rc = unify_certificate_blob_copy(Cert, cert);
  PL_release_stream(stream);

  return rc;
}

static foreign_t
pl_ssl_peer_certificate_chain(term_t stream_t, term_t chain)
{ IOSTREAM *stream, *ssl_stream;
  PL_SSL_INSTANCE *instance;
  int rc;

  if ( !get_ssl_stream(stream_t, &stream, &ssl_stream) )
    return FALSE;

  instance = ssl_stream->handle;
  rc = unify_certificate_copies_inorder(chain,
                                        SSL_get_peer_cert_chain(instance->ssl));
  PL_release_stream(stream);

  return rc;
}


static foreign_t
pl_ssl_session(term_t stream_t, term_t session_t)
{ IOSTREAM *stream, *ssl_stream;
  PL_SSL_INSTANCE* instance;
  SSL* ssl;
  SSL_SESSION* session;
  term_t list_t = PL_copy_term_ref(session_t);
  term_t node_t = PL_new_term_ref();
  int version;
  unsigned char *master_key;
  int master_key_length;
  const char *cipher;

  if ( !get_ssl_stream(stream_t, &stream, &ssl_stream) )
     return FALSE;

  instance = ssl_stream->handle;
  PL_release_stream(stream);

  if ( !(ssl = instance->ssl) ||
       !(session = SSL_get1_session(ssl)) )
    return PL_existence_error("ssl_session", stream_t);

#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
  version = session->ssl_version;
  master_key = session->master_key;
  master_key_length = session->master_key_length;
  /* session_key is SSL2 specific, i.e., obsolete */
#ifndef OPENSSL_NO_SSL2
  if ( !add_key_string(list_t, FUNCTOR_session_key1,
		       session->key_arg_length, session->key_arg) )
    goto err;
#endif
#else
  version = SSL_SESSION_get_protocol_version(session);
  if ( (master_key = PL_malloc(SSL_MAX_MASTER_KEY_LENGTH)) == NULL )
  { SSL_SESSION_free(session);
    return PL_resource_error("memory");
  }
  master_key_length = SSL_SESSION_get_master_key(session, master_key, SSL_MAX_MASTER_KEY_LENGTH);
#endif

  if ( !PL_unify_list_ex(list_t, node_t, list_t) )
    goto err;
  if ( !PL_unify_term(node_t,
		      PL_FUNCTOR, FUNCTOR_version1,
		      PL_INT, version))
    goto err;

  cipher = SSL_get_cipher_name(ssl);

  if ( !add_key_string(list_t, FUNCTOR_cipher1,
		       strlen(cipher), (unsigned char*)cipher) )
    goto err;

  if ( !add_key_string(list_t, FUNCTOR_master_key1,
		       master_key_length, master_key) )
    goto err;

#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
  if ( !add_key_string(list_t, FUNCTOR_session_id1,
		       session->session_id_length, session->session_id) )
    goto err;

  if ( ssl->s3 != NULL ) /* If the connection is SSLv2?! */
  { if ( !add_key_string(list_t, FUNCTOR_client_random1,
			 SSL3_RANDOM_SIZE, ssl->s3->client_random) )
      goto err;

    if ( !add_key_string(list_t, FUNCTOR_server_random1,
			 SSL3_RANDOM_SIZE, ssl->s3->server_random) )
      goto err;
  }
#else
  /* Note: session_id has no correspondence in OpenSSL >= 1.1.0 */

  { unsigned char random[SSL3_RANDOM_SIZE];

    SSL_get_client_random(ssl, random, SSL3_RANDOM_SIZE);
    if ( !add_key_string(list_t, FUNCTOR_client_random1,
                         SSL3_RANDOM_SIZE, random) )
      goto err;

    SSL_get_server_random(ssl, random, SSL3_RANDOM_SIZE);
    if ( !add_key_string(list_t, FUNCTOR_server_random1,
			 SSL3_RANDOM_SIZE, random) )
      goto err;
  }

  PL_free(master_key);
#endif

#ifdef HAVE_SSL_CTX_SET_ALPN_PROTOS
  { const unsigned char *data;
    unsigned int len;
    SSL_get0_alpn_selected(ssl, &data, &len);
    if ( !add_key_string(list_t, FUNCTOR_alpn_protocol1,
                         len, data)) {
      goto err;
    }
  }
#endif

  SSL_SESSION_free(session);
  return PL_unify_nil_ex(list_t);

err:
  SSL_SESSION_free(session);
  return FALSE;
}


		 /*******************************
		 *	     INSTALL		*
		 *******************************/

#define MKATOM(n) ATOM_ ## n = PL_new_atom(#n);

install_t
install_ssl4pl(void)
{ MKATOM(server);
  MKATOM(client);
  MKATOM(password);
  MKATOM(host);
  MKATOM(peer_cert);
  MKATOM(cacerts);
  MKATOM(certificate_file);
  MKATOM(certificate_key_pairs);
  MKATOM(key_file);
  MKATOM(pem_password_hook);
  MKATOM(cert_verify_hook);
  MKATOM(close_parent);
  MKATOM(close_notify);
  MKATOM(disable_ssl_methods);
  MKATOM(min_protocol_version);
  MKATOM(max_protocol_version);
  MKATOM(cipher_list);
  MKATOM(ecdh_curve);
  MKATOM(root_certificates);
  MKATOM(sni_hook);
  MKATOM(sslv2);
  MKATOM(sslv23);
  MKATOM(sslv3);
  MKATOM(tlsv1);
  MKATOM(tlsv1_1);
  MKATOM(tlsv1_2);
  MKATOM(tlsv1_3);
  MKATOM(require_crl);
  MKATOM(crl);
  MKATOM(alpn_protocols);
  MKATOM(alpn_protocol_hook);

  ATOM_minus                = PL_new_atom("-");

  FUNCTOR_error2            = PL_new_functor(PL_new_atom("error"), 2);
  FUNCTOR_ssl_error4        = PL_new_functor(PL_new_atom("ssl_error"), 4);
  FUNCTOR_permission_error3 = PL_new_functor(PL_new_atom("permission_error"), 3);
  FUNCTOR_version1          = PL_new_functor(PL_new_atom("version"), 1);
  FUNCTOR_notbefore1        = PL_new_functor(PL_new_atom("notbefore"), 1);
  FUNCTOR_notafter1         = PL_new_functor(PL_new_atom("notafter"), 1);
  FUNCTOR_subject1          = PL_new_functor(PL_new_atom("subject"), 1);
  FUNCTOR_issuername1       = PL_new_functor(PL_new_atom("issuer_name"), 1);
  FUNCTOR_serial1           = PL_new_functor(PL_new_atom("serial"), 1);
  FUNCTOR_key1              = PL_new_functor(PL_new_atom("key"), 1);
  FUNCTOR_public_key1       = PL_new_functor(PL_new_atom("public_key"), 1);
  FUNCTOR_private_key1      = PL_new_functor(PL_new_atom("private_key"), 1);
  FUNCTOR_rsa8              = PL_new_functor(PL_new_atom("rsa"), 8);
  FUNCTOR_ec3               = PL_new_functor(PL_new_atom("ec"), 3);
  FUNCTOR_hash1             = PL_new_functor(PL_new_atom("hash"), 1);
  FUNCTOR_next_update1      = PL_new_functor(PL_new_atom("next_update"), 1);
  FUNCTOR_signature1        = PL_new_functor(PL_new_atom("signature"), 1);
  FUNCTOR_signature_algorithm1 = PL_new_functor(PL_new_atom("signature_algorithm"), 1);
  FUNCTOR_to_be_signed1     = PL_new_functor(PL_new_atom("to_be_signed"), 1);
  FUNCTOR_equals2           = PL_new_functor(PL_new_atom("="), 2);
  FUNCTOR_crl1              = PL_new_functor(PL_new_atom("crl"), 1);
  FUNCTOR_revoked2          = PL_new_functor(PL_new_atom("revoked"), 2);
  FUNCTOR_revocations1      = PL_new_functor(PL_new_atom("revocations"), 1);
#ifndef OPENSSL_NO_SSL2
  FUNCTOR_session_key1      = PL_new_functor(PL_new_atom("session_key"), 1);
#endif
  FUNCTOR_cipher1           = PL_new_functor(PL_new_atom("cipher"), 1);
  FUNCTOR_master_key1       = PL_new_functor(PL_new_atom("master_key"), 1);
  FUNCTOR_session_id1       = PL_new_functor(PL_new_atom("session_id"), 1);
  FUNCTOR_client_random1    = PL_new_functor(PL_new_atom("client_random"), 1);
  FUNCTOR_server_random1    = PL_new_functor(PL_new_atom("server_random"), 1);
  FUNCTOR_alpn_protocol1    = PL_new_functor(PL_new_atom("alpn_protocol"), 1);
  FUNCTOR_system1           = PL_new_functor(PL_new_atom("system"), 1);
  FUNCTOR_unknown1          = PL_new_functor(PL_new_atom("unknown"), 1);
  FUNCTOR_unsupported_hash_algorithm1 = PL_new_functor(PL_new_atom("unsupported_hash_algorithm"), 1);
  FUNCTOR_certificate1      = PL_new_functor(PL_new_atom("certificate"), 1);
  FUNCTOR_file1             = PL_new_functor(PL_new_atom("file"), 1);
  PL_register_foreign("_ssl_context",	4, pl_ssl_context,    0);
  PL_register_foreign("_ssl_init_from_context",
					2, pl_ssl_init_from_context, 0);
  PL_register_foreign("ssl_negotiate",	5, pl_ssl_negotiate,  0);
  PL_register_foreign("_ssl_add_certificate_key",
					3, pl_ssl_add_certificate_key, 0);
  PL_register_foreign("_ssl_set_options", 2, pl_ssl_set_options, 0);
  PL_register_foreign("ssl_debug",	1, pl_ssl_debug,      0);
  PL_register_foreign("ssl_session",    2, pl_ssl_session,    0);
  PL_register_foreign("ssl_peer_certificate",
                                        2, pl_ssl_peer_certificate, 0);
  PL_register_foreign("ssl_peer_certificate_chain",
                                        2, pl_ssl_peer_certificate_chain, 0);
  PL_register_foreign("load_crl",       2, pl_load_crl,      0);
  PL_register_foreign("load_certificate",2,pl_load_certificate,      0);
  PL_register_foreign("write_certificate",3,pl_write_certificate,      0);
  PL_register_foreign("verify_certificate",3,pl_verify_certificate,      0);
  PL_register_foreign("load_private_key",3,pl_load_private_key,      0);
  PL_register_foreign("load_public_key", 2,pl_load_public_key,      0);
  PL_register_foreign("system_root_certificates", 1, pl_system_root_certificates, 0);

  PL_register_foreign("certificate_field", 2, pl_certificate_field, PL_FA_NONDETERMINISTIC);
  PL_register_foreign("verify_certificate_issuer", 2, pl_verify_certificate_issuer, 0);
  PL_register_foreign("same_certificate", 2, pl_same_certificate, 0);

/* Note that libcrypto threading needs to be initialized exactly once.
   This is achieved by loading library(crypto) from library(ssl) and
   do the initialization from the library(crypto) foreign installation.
*/
  ssl_lib_init();

  PL_set_prolog_flag("ssl_library_version", PL_ATOM,
#ifdef HAVE_OPENSSL_VERSION
		     OpenSSL_version(OPENSSL_VERSION)
#else
		     SSLeay_version(SSLEAY_VERSION)
#endif
		     );

  PL_set_prolog_flag("system_cacert_filename", PL_ATOM,
		     SYSTEM_CACERT_FILENAME);
}

install_t
uninstall_ssl4pl(void)
{ ssl_lib_exit();
}
