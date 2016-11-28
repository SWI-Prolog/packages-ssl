/*  Part of SWI-Prolog

    Author:        Jan van der Steen, Jan Wielemaker and Matt Lilley
    E-mail:        J.Wielemaker@vu.nl
    WWW:           http://www.swi-prolog.org
    Copyright (c)  2004-2015, SWI-Prolog Foundation
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
#include "ssllib.h"

#ifdef _REENTRANT
#include <pthread.h>
#endif

static atom_t ATOM_server;
static atom_t ATOM_client;
static atom_t ATOM_password;
static atom_t ATOM_host;
static atom_t ATOM_cert;
static atom_t ATOM_peer_cert;
static atom_t ATOM_cacert_file;
static atom_t ATOM_require_crl;
static atom_t ATOM_crl;
static atom_t ATOM_certificate_file;
static atom_t ATOM_certificate;
static atom_t ATOM_key_file;
static atom_t ATOM_pem_password_hook;
static atom_t ATOM_cert_verify_hook;
static atom_t ATOM_close_parent;
static atom_t ATOM_disable_ssl_methods;
static atom_t ATOM_cipher_list;
static atom_t ATOM_ecdh_curve;
static atom_t ATOM_key;
static atom_t ATOM_root_certificates;
static atom_t ATOM_sni_hook;

static atom_t ATOM_sslv2;
static atom_t ATOM_sslv23;
static atom_t ATOM_sslv3;
static atom_t ATOM_tlsv1;
static atom_t ATOM_tlsv1_1;
static atom_t ATOM_tlsv1_2;
static atom_t ATOM_minus;			/* "-" */
static atom_t ATOM_text;
static atom_t ATOM_octet;
static atom_t ATOM_utf8;

static atom_t ATOM_sha1;
static atom_t ATOM_sha224;
static atom_t ATOM_sha256;
static atom_t ATOM_sha384;
static atom_t ATOM_sha512;

static atom_t ATOM_pkcs;
static atom_t ATOM_pkcs_oaep;
static atom_t ATOM_none;
static atom_t ATOM_block;
static atom_t ATOM_encoding;
static atom_t ATOM_padding;

static functor_t FUNCTOR_unsupported_hash_algorithm1;
static functor_t FUNCTOR_system1;
       functor_t FUNCTOR_error2;	/* also used in ssllib.c */
       functor_t FUNCTOR_ssl_error4;	/* also used in ssllib.c */
static functor_t FUNCTOR_permission_error3;
static functor_t FUNCTOR_ip4;
static functor_t FUNCTOR_version1;
static functor_t FUNCTOR_notbefore1;
static functor_t FUNCTOR_notafter1;
static functor_t FUNCTOR_subject1;
static functor_t FUNCTOR_issuername1;
static functor_t FUNCTOR_serial1;
static functor_t FUNCTOR_public_key1;
static functor_t FUNCTOR_private_key1;
static functor_t FUNCTOR_rsa8;
static functor_t FUNCTOR_key1;
static functor_t FUNCTOR_hash1;
static functor_t FUNCTOR_next_update1;
static functor_t FUNCTOR_signature1;
static functor_t FUNCTOR_equals2;
static functor_t FUNCTOR_crl1;
static functor_t FUNCTOR_revocations1;
static functor_t FUNCTOR_revoked2;
#ifndef OPENSSL_NO_SSL2
static functor_t FUNCTOR_session_key1;
#endif
static functor_t FUNCTOR_master_key1;
static functor_t FUNCTOR_session_id1;
static functor_t FUNCTOR_client_random1;
static functor_t FUNCTOR_server_random1;
static functor_t FUNCTOR_system1;
static functor_t FUNCTOR_unknown1;

typedef enum
{ RSA_MODE, EVP_MODE
} crypt_mode_t;

static int i2d_X509_CRL_INFO_wrapper(void* i, unsigned char** d)
{
   return i2d_X509_CRL_INFO(i, d);
}

static int i2d_X509_CINF_wrapper(void* i, unsigned char** d)
{
   return i2d_X509_CINF(i, d);
}

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
get_predicate_arg(int a, module_t m, term_t t, int arity, predicate_t *pred)
{ term_t t2 = PL_new_term_ref();
  atom_t name;

  _PL_get_arg(a, t, t2);
  if ( !PL_strip_module(t2, &m, t2) ||
       !PL_get_atom_ex(t2, &name) )
    return FALSE;

  *pred = PL_pred(PL_new_functor(name, arity), m);

  return TRUE;
}


static int
get_bn_arg(int a, term_t t, BIGNUM **bn)
{ term_t arg;
  char *hex;

  if ( (arg=PL_new_term_ref()) &&
       PL_get_arg(a, t, arg) &&
       PL_get_chars(arg, &hex,
		    CVT_ATOM|CVT_STRING|REP_ISO_LATIN_1|CVT_EXCEPTION) )
  { if ( strcmp(hex, "-") == 0 )
      *bn = NULL;
    else
      BN_hex2bn(bn, hex);

    return TRUE;
  }

  return FALSE;
}


static int
unify_bignum_arg(int a, term_t t, const BIGNUM *bn)
{ term_t arg;

  if ( (arg = PL_new_term_ref()) &&
       PL_get_arg(a, t, arg) )
  { int rc;

    if ( bn )
    { char *hex = BN_bn2hex(bn);

      rc = PL_unify_chars(arg, PL_STRING|REP_ISO_LATIN_1, (size_t)-1, hex);
      OPENSSL_free(hex);
    } else
      rc = PL_unify_atom(arg, ATOM_minus);

    PL_reset_term_refs(arg);
    return rc;
  }

  return FALSE;
}


static int
recover_rsa(term_t t, RSA** rsap)
{ RSA *rsa = RSA_new();

#if OPENSSL_VERSION_NUMBER < 0x10100000L
  if ( get_bn_arg(1, t, &rsa->n) &&
       get_bn_arg(2, t, &rsa->e) &&
       get_bn_arg(3, t, &rsa->d) &&
       get_bn_arg(4, t, &rsa->p) &&
       get_bn_arg(5, t, &rsa->q) &&
       get_bn_arg(6, t, &rsa->dmp1) &&
       get_bn_arg(7, t, &rsa->dmq1) &&
       get_bn_arg(8, t, &rsa->iqmp)
     )
  {
#else
  BIGNUM *n = NULL, *e = NULL, *d = NULL, *p = NULL,
    *q = NULL, *dmp1 = NULL, *dmq1 = NULL, *iqmp = NULL;

  if ( get_bn_arg(1, t, &n) &&
       get_bn_arg(2, t, &e) &&
       get_bn_arg(3, t, &d) &&
       get_bn_arg(4, t, &p) &&
       get_bn_arg(5, t, &q) &&
       get_bn_arg(6, t, &dmp1) &&
       get_bn_arg(7, t, &dmq1) &&
       get_bn_arg(8, t, &iqmp) )
  {
    if ( !RSA_set0_key(rsa, n, e, d) ||
         ( (p || q) && !RSA_set0_factors(rsa, p, q) ) ||
         ( (dmp1 || dmq1 || iqmp) &&
           !RSA_set0_crt_params(rsa, dmp1, dmq1, iqmp)) )
    { RSA_free(rsa);
      return FALSE;
    }
#endif
    *rsap = rsa;
    return TRUE;
  }

  RSA_free(rsa);
  return FALSE;
}


static int
recover_private_key(term_t t, RSA** rsap)
{ if ( PL_is_functor(t, FUNCTOR_private_key1) )
  { term_t arg;

    if ( (arg = PL_new_term_ref()) &&
	 PL_get_arg(1, t, arg) )
      return recover_rsa(arg, rsap);

    return FALSE;
  }

  return PL_type_error("private_key", t);
}


static int
recover_public_key(term_t t, RSA** rsap)
{ if ( PL_is_functor(t, FUNCTOR_public_key1) )
  { term_t arg;

    if ( (arg = PL_new_term_ref()) &&
	 PL_get_arg(1, t, arg) )
      return recover_rsa(arg, rsap);

    return FALSE;
  }

  return PL_type_error("public_key", t);
}


static int
unify_rsa(term_t item, RSA* rsa)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
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


static int
unify_bytes_hex(term_t t, size_t len, const unsigned char *data)
{ char tmp[512];
  char *out, *o;
  static const char *tohex = "0123456789ABCDEF";
  const unsigned char *end = data+len;
  int rc;

  if ( len*2 <= sizeof(tmp) )
    out = tmp;
  else if ( !(out = malloc(len*2)) )
    return PL_resource_error("memory");

  for(o=out ; data < end; data++)
  { *o++ = tohex[(*data >> 4) & 0xf];
    *o++ = tohex[(*data >> 0) & 0xf];
  }

  rc = PL_unify_chars(t, PL_STRING|REP_ISO_LATIN_1, len*2, out);
  if ( out != tmp )
    free(out);

  return rc;
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

#if !defined(HAVE_OPENSSL_ZALLOC) && !defined(OPENSSL_zalloc)
static void *
OPENSSL_zalloc(size_t num)
{ void *ret = OPENSSL_malloc(num);
  if (ret != NULL)
    memset(ret, 0, num);
  return ret;
}
#endif

#ifndef HAVE_EVP_MD_CTX_FREE
void
EVP_MD_CTX_free(EVP_MD_CTX *ctx)
{ EVP_MD_CTX_cleanup(ctx);
  OPENSSL_free(ctx);
}

EVP_MD_CTX *
EVP_MD_CTX_new(void)
{ return OPENSSL_zalloc(sizeof(EVP_MD_CTX));
}
#endif

static int
unify_hash(term_t hash, const ASN1_OBJECT* algorithm,
	   int (*i2d)(void*, unsigned char**), void * data)
{ const EVP_MD *type;
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  int digestible_length;
  unsigned char* digest_buffer;
  unsigned char digest[EVP_MAX_MD_SIZE];
  unsigned int digest_length;
  unsigned char* p;
  int nid = 0;
  /* Generate hash */
  nid = OBJ_obj2nid(algorithm);
  /* Annoyingly, EVP_get_digestbynid doesnt work for some of these algorithms. Instead check for
     them explicitly and set the digest manually
  */
  if (nid == NID_ecdsa_with_SHA1)
  { type = EVP_sha1();
  } else if (nid == NID_ecdsa_with_SHA256)
  { type = EVP_sha256();
  } else if (nid == NID_ecdsa_with_SHA384)
  { type = EVP_sha384();
#ifdef HAVE_OPENSSL_MD2_H
  } else if (nid == NID_md2WithRSAEncryption)
  { type = EVP_md2();
#endif
  } else
  { type = EVP_get_digestbynid(nid);
    if (type == NULL)
      return PL_unify_term(hash,
                           PL_FUNCTOR, FUNCTOR_unsupported_hash_algorithm1,
                           PL_INTEGER, nid);
  }

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

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#define X509_REVOKED_get0_serialNumber(R) ((R)->serialNumber)
#define X509_REVOKED_get0_revocationDate(R) ((R)->revocationDate)
#define EVP_PKEY_base_id(key) ((key)->type)
#define X509_CRL_get0_nextUpdate(C) X509_CRL_get_nextUpdate(C)
#ifndef HAVE_X509_CRL_GET0_SIGNATURE
static void
X509_CRL_get0_signature(const X509_CRL *crl, const ASN1_BIT_STRING **psig, const X509_ALGOR **palg)
{
  *psig = crl->signature;
  *palg = crl->sig_alg;
}
#endif

#ifndef HAVE_X509_GET0_SIGNATURE
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
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        unify_hash(hash, palg->algorithm, i2d_X509_CRL_INFO_wrapper, crl->crl) &&
#else
	/* TODO: is crl a valid choice here? */
        unify_hash(hash, palg->algorithm, i2d_X509_CRL_INFO_wrapper, crl) &&
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
      rc = PL_unify_atom_chars(item, "ec_key");
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


static int
unify_certificate(term_t cert, X509* data)
{ term_t list = PL_copy_term_ref(cert);
  term_t item = PL_new_term_ref();
  BIO * mem = NULL;
  long n;
  EVP_PKEY *key;
  term_t issuername;
  term_t subject;
  term_t hash;
  term_t not_before;
  term_t not_after;
  term_t signature;
  unsigned int crl_ext_id;
  unsigned char *p;
  X509_EXTENSION * crl_ext = NULL;

  const ASN1_BIT_STRING *psig;
  const X509_ALGOR *palg;
  X509_get0_signature(&psig, &palg, data);

  if (!(PL_unify_list(list, item, list) &&
        PL_unify_term(item,
                      PL_FUNCTOR, FUNCTOR_version1,
                      PL_LONG, X509_get_version(data))
         ))
     return FALSE;
  if (!(PL_unify_list(list, item, list) &&
        (not_before = PL_new_term_ref()) &&
        unify_asn1_time(not_before, X509_get_notBefore(data)) &&
        PL_unify_term(item,
                      PL_FUNCTOR, FUNCTOR_notbefore1,
                      PL_TERM, not_before)))
     return FALSE;

  if (!(PL_unify_list(list, item, list) &&
        (not_after = PL_new_term_ref()) &&
        unify_asn1_time(not_after, X509_get_notAfter(data)) &&
        PL_unify_term(item,
                      PL_FUNCTOR, FUNCTOR_notafter1,
                      PL_TERM, not_after)))
     return FALSE;


  if ((mem = BIO_new(BIO_s_mem())) != NULL)
  { i2a_ASN1_INTEGER(mem, X509_get_serialNumber(data));
    if ((n = BIO_get_mem_data(mem, &p)) > 0)
    {  if (!(PL_unify_list(list, item, list) &&
             PL_unify_term(item,
                           PL_FUNCTOR, FUNCTOR_serial1,
                           PL_NCHARS, (size_t)n, p)
              ))
        { BIO_vfree(mem);
          return FALSE;
        }
    } else
      Sdprintf("Failed to print serial - continuing without serial\n");
  } else
    Sdprintf("Failed to allocate BIO for printing - continuing without serial\n");
  BIO_vfree(mem);

  if (!(PL_unify_list(list, item, list) &&
        (subject = PL_new_term_ref()) &&
        unify_name(subject, X509_get_subject_name(data)) &&
        PL_unify_term(item,
                      PL_FUNCTOR, FUNCTOR_subject1,
                      PL_TERM, subject))
     )
     return FALSE;
  if (!((hash = PL_new_term_ref()) &&
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        unify_hash(hash, palg->algorithm, i2d_X509_CINF_wrapper, data->cert_info) &&
#else
        /* TODO: Is "data" a valid choice for the last argument? */
        unify_hash(hash, palg->algorithm, i2d_X509_CINF_wrapper, data) &&
#endif
        PL_unify_list(list, item, list) &&
        PL_unify_term(item,
                      PL_FUNCTOR, FUNCTOR_hash1,
                      PL_TERM, hash)))
     return FALSE;
  if (!((signature = PL_new_term_ref()) &&
	unify_bytes_hex(signature, psig->length, psig->data) &&
	PL_unify_list(list, item, list) &&
        PL_unify_term(item,
                      PL_FUNCTOR, FUNCTOR_signature1,
                      PL_TERM, signature)
         ))
     return FALSE;

  if (!(PL_unify_list(list, item, list) &&
        (issuername = PL_new_term_ref()) &&
        unify_name(issuername, X509_get_issuer_name(data)) &&
        PL_unify_term(item,
                      PL_FUNCTOR, FUNCTOR_issuername1,
                      PL_TERM, issuername))
     )
     return FALSE;

  if (!PL_unify_list(list, item, list))
    return FALSE;
  /* X509_extract_key returns a copy of the existing key */
  key = X509_extract_key(data);
  if ( !PL_unify_functor(item, FUNCTOR_key1) ||
       !PL_get_arg(1, item, item) ||
       !unify_public_key(key, item) )
    return FALSE;
  EVP_PKEY_free(key);


  /* If the cert has a CRL distribution point, return that. If it does not,
     it is not an error
  */
  crl_ext_id = X509_get_ext_by_NID(data, NID_crl_distribution_points, -1);
  crl_ext = X509_get_ext(data, crl_ext_id);
  if (crl_ext != NULL)
  { STACK_OF(DIST_POINT) * distpoints;
    int i, j;
    term_t crl;
    term_t crl_list;
    term_t crl_item;

    if (!PL_unify_list(list, item, list))
       return FALSE;

    distpoints = X509_get_ext_d2i(data, NID_crl_distribution_points, NULL, NULL);
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
    if (!PL_unify_nil(crl_list))
       return FALSE;
    if (!PL_unify_term(item,
                       PL_FUNCTOR, FUNCTOR_crl1,
                       PL_TERM, crl))
       return FALSE;
  }
  return PL_unify_nil(list);
}

static int
unify_certificates(term_t certs, term_t tail, STACK_OF(X509)* stack)
{ term_t item = PL_new_term_ref();
  term_t list = PL_copy_term_ref(certs);
  X509* cert = sk_X509_pop(stack);
  int retval = 1;

  while (cert != NULL && retval == 1)
  { retval &= PL_unify_list(list, item, list);
    retval &= unify_certificate(item, cert);
    X509_free(cert);
    cert = sk_X509_pop(stack);
    if (cert == NULL)
      return PL_unify(tail, item) && PL_unify_nil(list);
  }
  return retval && PL_unify_nil(list);
}

static foreign_t
pl_load_public_key(term_t source, term_t key_t)
{ EVP_PKEY* key;
  BIO* bio;
  IOSTREAM* stream;
  int c;

  if ( !PL_get_stream_handle(source, &stream) )
    return FALSE;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
  bio = BIO_new(&bio_read_functions);
#else
  bio = BIO_new(bio_read_method());
#endif
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
#if OPENSSL_VERSION_NUMBER < 0x10100000L
  bio = BIO_new(&bio_read_functions);
#else
  bio = BIO_new(bio_read_method());
#endif
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

#if OPENSSL_VERSION_NUMBER < 0x10100000L
  bio = BIO_new(&bio_read_functions);
#else
  bio = BIO_new(bio_read_method());
#endif
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
#if OPENSSL_VERSION_NUMBER < 0x10100000L
  bio = BIO_new(&bio_read_functions);
#else
  bio = BIO_new(bio_read_method());
#endif
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
  if (unify_certificate(cert, x509))
  { X509_free(x509);
    PL_succeed;
  } else
  { X509_free(x509);
    PL_fail;
  }
}


static void
acquire_ssl(atom_t atom)
{ ssl_deb(4, "Acquire on atom %d\n", atom);
}


static int
release_ssl(atom_t atom)
{ PL_SSL* conf;
  size_t size;

  conf = PL_blob_data(atom, &size, NULL);
  ssl_deb(4, "Releasing PL_SSL %p\n", conf);
  ssl_exit(conf);	/* conf is freed by an internal call from OpenSSL
	                   via ssl_config_free() */
  return TRUE;
}

static int
compare_ssl(atom_t a, atom_t b)
{ PL_SSL* *ssla = PL_blob_data(a, NULL, NULL);
  PL_SSL* *sslb = PL_blob_data(b, NULL, NULL);

  return ( ssla > sslb ?  1 :
	   ssla < sslb ? -1 : 0
	 );
}

static int
write_ssl(IOSTREAM *s, atom_t symbol, int flags)
{ PL_SSL *ssl = PL_blob_data(symbol, NULL, NULL);

  Sfprintf(s, "<ssl_context>(%p)", ssl);

  return TRUE;
}

static PL_blob_t ssl_context_type =
{ PL_BLOB_MAGIC,
  PL_BLOB_NOCOPY,
  "ssl_context",
  release_ssl,
  compare_ssl,
  write_ssl,
  acquire_ssl
};


static int
put_conf(term_t config, PL_SSL *conf)
{ return PL_unify_atom(config, conf->atom);
}


static int
register_conf(term_t config, PL_SSL *conf)
{ term_t blob = PL_new_term_ref();
  int rc;

  PL_put_blob(blob, conf, sizeof(void*), &ssl_context_type);
  rc = PL_get_atom(blob, &conf->atom);
  assert(rc);
  ssl_deb(4, "Atom created: %d\n", conf->atom);
  return put_conf(config, conf);
}


static int
get_conf(term_t config, PL_SSL **conf)
{ PL_blob_t *type;
  void *data;

  if ( PL_get_blob(config, &data, NULL, &type) && type == &ssl_context_type )
  { PL_SSL *ssl = data;

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
  term_t av = PL_new_term_refs(2);
  predicate_t pred = (predicate_t) config->pl_ssl_cb_pem_passwd_data;
  char *passwd = NULL;
  size_t len;

  /*
   * hook(+SSL, -Passwd)
   */

  put_conf(av+0, config);
  if ( PL_call_predicate(NULL, PL_Q_PASS_EXCEPTION, pred, av) )
  { if ( PL_get_nchars(av+1, &len, &passwd, CVT_ALL) )
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
  term_t av = PL_new_term_refs(3);
  predicate_t pred = (predicate_t) config->pl_ssl_cb_sni_data;
  PL_SSL *new_config = NULL;

  /*
   * hook(+SSL0, +Hostname, -SSL)
   */
  put_conf(av+0, config);
  if ( PL_unify_chars(av+1, PL_ATOM|REP_UTF8, strlen(host), host)
       && PL_call_predicate(NULL, PL_Q_PASS_EXCEPTION, pred, av) )
    if ( !get_conf(av+2, &new_config) )
      PL_warning("sni_hook returned wrong type");

  PL_close_foreign_frame(fid);
  return new_config;
}

static BOOL
pl_cert_verify_hook(PL_SSL *config,
                    X509 * cert,
		    X509_STORE_CTX * ctx,
		    const char *error,
                    int error_unknown)
{ fid_t fid = PL_open_foreign_frame();
  term_t av = PL_new_term_refs(5);
  term_t error_term = PL_new_term_ref();
  predicate_t pred = (predicate_t) config->pl_ssl_cb_cert_verify_data;
  int val;
  STACK_OF(X509)* stack;

  assert(pred);

  stack = X509_STORE_CTX_get1_chain(ctx);


  /*
   * hook(+SSL, +Certificate, +Error)
   */

  put_conf(av+0, config);
  if ( error_unknown )
    val = PL_unify_term(error_term,
                        PL_FUNCTOR, FUNCTOR_unknown1,
                        PL_CHARS, error);
  else
    val = PL_unify_atom_chars(error_term, error);
  /*Sdprintf("\n---Certificate:'%s'---\n", certificate);*/
  val &= ( unify_certificate(av+1, cert) &&
           unify_certificates(av+2, av+3, stack) &&
           PL_unify(av+4, error_term) &&
           PL_call_predicate(NULL, PL_Q_PASS_EXCEPTION, pred, av) );

  /* free any items still on stack, since X509_STORE_CTX_get1_chain returns a copy */
  sk_X509_pop_free(stack, X509_free);
  PL_close_foreign_frame(fid);

  return val;
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

      ssl_set_password(conf, s);
    } else if ( name == ATOM_cipher_list && arity == 1 )
    { char *s;

      if ( !get_char_arg(1, head, &s) )
	return FALSE;

      ssl_set_cipher_list(conf, s);
    } else if ( name == ATOM_ecdh_curve && arity == 1 )
    { char *s;

      if ( !get_char_arg(1, head, &s) )
	return FALSE;

      ssl_set_ecdh_curve(conf, s);

    } else if ( name == ATOM_host && arity == 1 )
    { char *s;

      if ( !get_char_arg(1, head, &s) )
	return FALSE;

      ssl_set_host(conf, s);
    } else if ( name == ATOM_cert && arity == 1 )
    { int val;

      if ( !get_bool_arg(1, head, &val) )
	return FALSE;

      ssl_set_cert(conf, val);
    } else if ( name == ATOM_peer_cert && arity == 1 )
    { int val;

      if ( !get_bool_arg(1, head, &val) )
	return FALSE;

      ssl_set_peer_cert(conf, val);
    } else if ( name == ATOM_require_crl && arity == 1 )
    { int val;

      if ( !get_bool_arg(1, head, &val) )
	return FALSE;

      ssl_set_crl_required(conf, val);
    } else if ( name == ATOM_crl && arity == 1 )
    { X509_crl_list *x_head=NULL, *x_tail=NULL;
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
            list_add_X509_crl(crl, &x_head, &x_tail);
          } else
            return PL_existence_error("file", list_head);
        }
      }
      ssl_set_crl_list(conf, x_head);
    } else if ( name == ATOM_cacert_file && arity == 1 )
    { term_t val = PL_new_term_ref();
      char *file;

      _PL_get_arg(1, head, val);
      if ( PL_is_functor(val, FUNCTOR_system1) )
      { _PL_get_arg(1, val, val);
	atom_t a;

	if ( !PL_get_atom_ex(val, &a) )
	  return FALSE;
	if ( a == ATOM_root_certificates )
	  ssl_set_use_system_cacert(conf, TRUE);
	else
	  return PL_domain_error("system_cacert", val);
      } else if ( PL_get_file_name(val, &file, PL_FILE_EXIST) )
      { ssl_set_cacert(conf, file);
      } else
	return FALSE;
    } else if ( name == ATOM_certificate_file && arity == 1 )
    { char *file;

      if ( !get_file_arg(1, head, &file) )
	return FALSE;

      ssl_set_certf(conf, file);
    } else if ( name == ATOM_certificate && arity == 1 )
    { char *s;

      if ( !get_char_arg(1, head, &s) )
	return FALSE;

      ssl_set_certificate(conf, s);
    } else if ( name == ATOM_key_file && arity == 1 )
    { char *file;

      if ( !get_file_arg(1, head, &file) )
	return FALSE;

      ssl_set_keyf(conf, file);
    } else if ( name == ATOM_key && arity == 1 )
    { char *s;

      if ( !get_char_arg(1, head, &s) )
	return FALSE;

      ssl_set_key(conf, s);
    } else if ( name == ATOM_pem_password_hook && arity == 1 )
    { predicate_t hook;

      if ( !get_predicate_arg(1, module, head, 2, &hook) )
	return FALSE;

      ssl_set_cb_pem_passwd(conf, pl_pem_passwd_hook, (void *)hook);
    } else if ( name == ATOM_cert_verify_hook && arity == 1 )
    { predicate_t hook;

      if ( !get_predicate_arg(1, module, head, 5, &hook) )
	return FALSE;

      ssl_set_cb_cert_verify(conf, pl_cert_verify_hook, (void *)hook);
    } else if ( name == ATOM_close_parent && arity == 1 )
    { int val;

      if ( !get_bool_arg(1, head, &val) )
	return FALSE;

      ssl_set_close_parent(conf, val);
    } else if ( name == ATOM_disable_ssl_methods && arity == 1 )
    { term_t opt_head = PL_new_term_ref();
      term_t opt_tail = PL_new_term_ref();
      int options = 0;
      _PL_get_arg(1, head, opt_tail);
      while( PL_get_list(opt_tail, opt_head, opt_tail) )
      {  atom_t option_name;
         if (!PL_get_atom(opt_head, &option_name))
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

      ssl_set_method_options(conf, options);
    } else if ( name == ATOM_sni_hook && arity == 1 && r == PL_SSL_SERVER)
    { predicate_t hook;

      if ( !get_predicate_arg(1, module, head, 3, &hook) )
        return FALSE;

      ssl_set_cb_sni(conf, pl_sni_hook, (void *) hook);
    } else
      continue;
  }

  if ( !PL_get_nil_ex(tail) )
    return FALSE;

  return register_conf(config, conf) && ssl_config(conf, options);
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
        {  SOCKET fd = Sfileno(instance->sread);
           SOCKET *fdp = data;
           *fdp = fd;
           return 0;
        } else if (instance->swrite != NULL)
        {  SOCKET fd = Sfileno(instance->swrite);
           SOCKET *fdp = data;
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



static foreign_t
pl_ssl_exit(term_t config)
{
  /* This is now handled by GC and this predicate does nothing.
     See release_ssl()
  */
  PL_succeed;
}


static IOFUNCTIONS ssl_funcs =
{ ssl_read,				/* read */
  ssl_write,				/* write */
  NULL,					/* seek */
  pl_ssl_close,				/* close */
  pl_ssl_control			/* control */
};


static foreign_t
pl_ssl_put_socket(term_t config, term_t data)
{ PL_SSL *conf;
  if ( !get_conf(config, &conf) )
    return FALSE;
  return PL_get_integer(data, &conf->sock);
}

static foreign_t
pl_ssl_get_socket(term_t config, term_t data)
{ PL_SSL *conf;
  if ( !get_conf(config, &conf) )
    return FALSE;
  return PL_unify_integer(data, conf->sock);
}


/**
 * FIXME: if anything goes wrong, the instance is not reclaimed.
 * Can we simple call free() on it?
 */
static foreign_t
pl_ssl_negotiate(term_t config,
		 term_t org_in, term_t org_out, /* wire streams */
		 term_t in, term_t out)		/* data streams */
{ PL_SSL *conf;
  IOSTREAM *sorg_in, *sorg_out;
  IOSTREAM *i, *o;
  PL_SSL_INSTANCE * instance = NULL;
  int rc;

  if ( !get_conf(config, &conf) )
    return FALSE;
  if ( !PL_get_stream_handle(org_in, &sorg_in) )
    return FALSE;
  if ( !PL_get_stream_handle(org_out, &sorg_out) )
    return FALSE;

  if ( !(rc = ssl_ssl_bio(conf, sorg_in, sorg_out, &instance)) )
  { PL_release_stream(sorg_in);
    PL_release_stream(sorg_out);
    return raise_ssl_error(ERR_get_error());
  }

  if ( !(i=Snew(instance, SIO_INPUT|SIO_RECORDPOS|SIO_FBUF, &ssl_funcs)) )
  { PL_release_stream(sorg_in);
    PL_release_stream(sorg_out);
    return PL_resource_error("memory");
  }
  instance->close_needed++;
  if ( !PL_unify_stream(in, i) )
  { Sclose(i);
    PL_release_stream(sorg_in);
    PL_release_stream(sorg_out);
    return FALSE;
  }
  Sset_filter(sorg_in, i);
  PL_release_stream(sorg_in);
  instance->dread = i;

  if ( !(o=Snew(instance, SIO_OUTPUT|SIO_RECORDPOS|SIO_FBUF, &ssl_funcs)) )
  { PL_release_stream(sorg_out);
    return PL_resource_error("memory");
  }
  instance->close_needed++;
  if ( !PL_unify_stream(out, o) )
  { Sclose(i);
    Sset_filter(sorg_in, NULL);
    PL_release_stream(sorg_out);
    Sclose(o);
    return FALSE;
  }
  Sset_filter(sorg_out, o);
  PL_release_stream(sorg_out);
  instance->dwrite = o;

  /* Increase atom reference count so that the context is not
     GCd until this session is complete */
  ssl_deb(4, "Increasing count on %d\n", conf->atom);
  PL_register_atom(conf->atom);
  return TRUE;
}


		 /*******************************
		 *       RSA ENCRYPT/DECRYPT	*
		 *******************************/

static int
get_text_representation(term_t t, int *rep)
{ atom_t a;

  if ( PL_get_atom_ex(t, &a) )
  { if      ( a == ATOM_octet ) *rep = REP_ISO_LATIN_1;
    else if ( a == ATOM_utf8  ) *rep = REP_UTF8;
    else if ( a == ATOM_text  ) *rep = REP_MB;
    else return PL_domain_error("encoding", t);

    return TRUE;
  }

  return FALSE;
}

static int
get_padding(term_t t, crypt_mode_t mode, int *padding)
{ atom_t a;

  if ( PL_get_atom_ex(t, &a) )
  { if      ( a == ATOM_pkcs && mode == RSA_MODE )       *padding = RSA_PKCS1_PADDING;
    else if ( a == ATOM_pkcs_oaep && mode == RSA_MODE  ) *padding = RSA_PKCS1_OAEP_PADDING;
    else if ( a == ATOM_none && mode == RSA_MODE  )      *padding = RSA_NO_PADDING;
    else if ( a == ATOM_sslv23  && mode == RSA_MODE )    *padding = RSA_SSLV23_PADDING;
    else if ( a == ATOM_none  && mode == EVP_MODE )      *padding = 0;
    else if ( a == ATOM_block  && mode == EVP_MODE )     *padding = 1;
    else return PL_domain_error("padding", t);

    return TRUE;
  }

  return FALSE;
}


static int
get_enc_text(term_t text, term_t enc, size_t *len, unsigned char **data)
{ int flags;

  if ( get_text_representation(enc, &flags) )
  { flags |= CVT_ATOM|CVT_STRING|CVT_LIST|CVT_EXCEPTION;
    return PL_get_nchars(text, len, (char**)data, flags);
  }

  return FALSE;
}


static int
parse_options(term_t options_t, crypt_mode_t mode, int* rep, int* padding)
{ if (PL_is_atom(options_t)) /* Is really an encoding */
  { if (rep == NULL)
      return TRUE;
    else if ( !get_text_representation(options_t, rep) )
      return FALSE;
  } else
  { term_t tail = PL_copy_term_ref(options_t);
    term_t head = PL_new_term_ref();

    while( PL_get_list_ex(tail, head, tail) )
    { atom_t name;
      size_t arity;
      term_t arg = PL_new_term_ref();

      if ( !PL_get_name_arity(head, &name, &arity) ||
           arity != 1 ||
           !PL_get_arg(1, head, arg) )
        return PL_type_error("option", head);

      if ( name == ATOM_encoding )
      { if ( !get_text_representation(arg, rep) )
          return FALSE;
      } else if ( name == ATOM_padding && padding != NULL)
      { if ( !get_padding(arg, mode, padding) )
        return FALSE;
      }
    }
    if ( !PL_get_nil_ex(tail) )
      return FALSE;
  }

  return TRUE;
}

static foreign_t
pl_rsa_private_decrypt(term_t private_t, term_t cipher_t,
		       term_t plain_t, term_t options_t)
{ size_t cipher_length;
  unsigned char* cipher;
  unsigned char* plain;
  int outsize;
  RSA* key;
  int rep = REP_UTF8;
  int padding = RSA_PKCS1_PADDING;
  int retval;

  if ( !parse_options(options_t, RSA_MODE, &rep, &padding))
    return FALSE;

  if( !PL_get_nchars(cipher_t, &cipher_length, (char**)&cipher,
		     CVT_ATOM|CVT_STRING|CVT_LIST|CVT_EXCEPTION) )
    return FALSE;
  if ( !recover_private_key(private_t, &key) )
    return FALSE;

  outsize = RSA_size(key);
  ssl_deb(1, "Output size is going to be %d", outsize);
  plain = PL_malloc(outsize);
  ssl_deb(1, "Allocated %d bytes for plaintext", outsize);
  if ((outsize = RSA_private_decrypt((int)cipher_length, cipher,
				     plain, key, padding)) <= 0)
  { ssl_deb(1, "Failure to decrypt!");
    RSA_free(key);
    PL_free(plain);
    return raise_ssl_error(ERR_get_error());
  }
  ssl_deb(1, "decrypted bytes: %d", outsize);
  ssl_deb(1, "Freeing RSA");
  RSA_free(key);
  ssl_deb(1, "Assembling plaintext");
  retval = PL_unify_chars(plain_t, rep | PL_STRING, outsize, (char*)plain);
  ssl_deb(1, "Freeing plaintext");
  PL_free(plain);
  ssl_deb(1, "Done");

  return retval;
}

static foreign_t
pl_rsa_public_decrypt(term_t public_t, term_t cipher_t,
                      term_t plain_t, term_t options_t)
{ size_t cipher_length;
  unsigned char* cipher;
  unsigned char* plain;
  int outsize;
  RSA* key;
  int rep = REP_UTF8;
  int padding = RSA_PKCS1_PADDING;
  int retval;

  if ( !parse_options(options_t, RSA_MODE, &rep, &padding))
    return FALSE;
  if ( !PL_get_nchars(cipher_t, &cipher_length, (char**)&cipher,
		      CVT_ATOM|CVT_STRING|CVT_LIST|CVT_EXCEPTION) )
    return FALSE;
  if ( !recover_public_key(public_t, &key) )
    return FALSE;

  outsize = RSA_size(key);
  ssl_deb(1, "Output size is going to be %d", outsize);
  plain = PL_malloc(outsize);
  ssl_deb(1, "Allocated %d bytes for plaintext", outsize);
  if ((outsize = RSA_public_decrypt((int)cipher_length, cipher,
                                    plain, key, padding)) <= 0)
  { ssl_deb(1, "Failure to decrypt!");
    RSA_free(key);
    PL_free(plain);
    return raise_ssl_error(ERR_get_error());
  }
  ssl_deb(1, "decrypted bytes: %d", outsize);
  ssl_deb(1, "Freeing RSA");
  RSA_free(key);
  ssl_deb(1, "Assembling plaintext");
  retval = PL_unify_chars(plain_t, rep | PL_STRING, outsize, (char*)plain);
  ssl_deb(1, "Freeing plaintext");
  PL_free(plain);
  ssl_deb(1, "Done");

  return retval;
}

static foreign_t
pl_rsa_public_encrypt(term_t public_t,
                      term_t plain_t, term_t cipher_t, term_t options_t)
{ size_t plain_length;
  unsigned char* cipher;
  unsigned char* plain;
  int outsize;
  RSA* key;
  int rep = REP_UTF8;
  int padding = RSA_PKCS1_PADDING;
  int retval;

  if ( !parse_options(options_t, RSA_MODE, &rep, &padding))
    return FALSE;

  ssl_deb(1, "Generating terms");
  ssl_deb(1, "Collecting plaintext");
  if ( !PL_get_nchars(plain_t, &plain_length, (char**)&plain,
		      CVT_ATOM|CVT_STRING|CVT_LIST|CVT_EXCEPTION | rep))
    return FALSE;
  if ( !recover_public_key(public_t, &key) )
    return FALSE;

  outsize = RSA_size(key);
  ssl_deb(1, "Output size is going to be %d\n", outsize);
  cipher = PL_malloc(outsize);
  ssl_deb(1, "Allocated %d bytes for ciphertext\n", outsize);
  if ( (outsize = RSA_public_encrypt((int)plain_length, plain,
				     cipher, key, padding)) <= 0)
  { ssl_deb(1, "Failure to encrypt!");
    PL_free(cipher);
    RSA_free(key);
    return raise_ssl_error(ERR_get_error());
  }
  ssl_deb(1, "encrypted bytes: %d\n", outsize);
  ssl_deb(1, "Freeing RSA");
  RSA_free(key);
  ssl_deb(1, "Assembling plaintext");
  retval = PL_unify_chars(cipher_t, PL_STRING|REP_ISO_LATIN_1,
			  outsize, (char*)cipher);
  ssl_deb(1, "Freeing plaintext");
  PL_free(cipher);
  ssl_deb(1, "Done");

  return retval;
}


static foreign_t
pl_rsa_private_encrypt(term_t private_t,
                       term_t plain_t, term_t cipher_t, term_t options_t)
{ size_t plain_length;
  unsigned char* cipher;
  unsigned char* plain;
  int outsize;
  RSA* key;
  int rep = REP_UTF8;
  int padding = RSA_PKCS1_PADDING;
  int retval;

  if ( !parse_options(options_t, RSA_MODE, &rep, &padding))
    return FALSE;

  if ( !PL_get_nchars(plain_t, &plain_length, (char**)&plain,
		      CVT_ATOM|CVT_STRING|CVT_LIST|CVT_EXCEPTION | rep))
    return FALSE;
  if ( !recover_private_key(private_t, &key) )
    return FALSE;

  outsize = RSA_size(key);
  ssl_deb(1, "Output size is going to be %d", outsize);
  cipher = PL_malloc(outsize);
  ssl_deb(1, "Allocated %d bytes for ciphertext", outsize);
  if ((outsize = RSA_private_encrypt((int)plain_length, plain,
                                     cipher, key, padding)) <= 0)
  { ssl_deb(1, "Failure to encrypt!");
    PL_free(cipher);
    RSA_free(key);
    return raise_ssl_error(ERR_get_error());
  }
  ssl_deb(1, "encrypted bytes: %d", outsize);
  ssl_deb(1, "Freeing RSA");
  RSA_free(key);
  ssl_deb(1, "Assembling plaintext");
  retval = PL_unify_chars(cipher_t, PL_STRING|REP_ISO_LATIN_1,
			  outsize, (char*)cipher);
  ssl_deb(1, "Freeing cipher");
  PL_free(cipher);
  ssl_deb(1, "Done");

  return retval;
}


static int
get_digest_type(term_t t, int *type)
{ atom_t a;

  if ( PL_get_atom_ex(t, &a) )
  { if      ( a == ATOM_sha1   ) *type = NID_sha1;
    else if ( a == ATOM_sha224 ) *type = NID_sha224;
    else if ( a == ATOM_sha256 ) *type = NID_sha256;
    else if ( a == ATOM_sha384 ) *type = NID_sha384;
    else if ( a == ATOM_sha512 ) *type = NID_sha512;
    else
    { PL_domain_error("digest_type", t);
      return FALSE;
    }

    return TRUE;
  }

  return FALSE;
}


static foreign_t
pl_rsa_sign(term_t Private, term_t Type, term_t Enc,
	    term_t Data, term_t Signature)
{ unsigned char *data;
  size_t data_len;
  RSA *key;
  unsigned char *signature;
  unsigned int signature_len;
  int rc;
  int type;

  if ( !get_enc_text(Data, Enc, &data_len, &data) ||
       !recover_private_key(Private, &key) ||
       !get_digest_type(Type, &type) )
    return FALSE;

  signature_len = RSA_size(key);
  signature = PL_malloc(signature_len);
  rc = RSA_sign(type,
		data, (unsigned int)data_len,
		signature, &signature_len, key);
  RSA_free(key);
  if ( rc != 1 )
  { PL_free(signature);
    return raise_ssl_error(ERR_get_error());
  }
  rc = PL_unify_chars(Signature, PL_STRING|REP_ISO_LATIN_1,
		      signature_len, (char*)signature);
  PL_free(signature);

  return rc;
}

static foreign_t
pl_rsa_verify(term_t Public, term_t Type, term_t Enc,
	    term_t Data, term_t Signature)
{ unsigned char *data;
  size_t data_len;
  RSA *key;
  unsigned char *signature;
  size_t signature_len;
  int rc;
  int type;

  if ( !get_enc_text(Data, Enc, &data_len, &data) ||
       !recover_public_key(Public, &key) ||
       !get_digest_type(Type, &type) ||
       !PL_get_nchars(Signature, &signature_len, (char**)&signature, CVT_ATOM|CVT_STRING|CVT_LIST|CVT_EXCEPTION) )
    return FALSE;

  rc = RSA_verify(type,
                  data, (unsigned int)data_len,
                  signature, (unsigned int)signature_len, key);
  RSA_free(key);
  if ( rc != 1 )
  { return raise_ssl_error(ERR_get_error());
  }
  return 1;
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
pl_ssl_session(term_t stream_t, term_t session_t)
{ IOSTREAM* stream;
  PL_SSL_INSTANCE* instance;
  SSL* ssl;
  SSL_SESSION* session;
  term_t list_t = PL_copy_term_ref(session_t);
  term_t node_t = PL_new_term_ref();
  int version;
  unsigned char *master_key;
  int master_key_length;

  if ( !PL_get_stream_handle(stream_t, &stream) )
     return FALSE;
  if ( stream->functions != &ssl_funcs )
  { PL_release_stream(stream);
    return PL_domain_error("ssl_stream", stream_t);
  }

  instance = stream->handle;
  PL_release_stream(stream);

  if ( !(ssl = instance->ssl) ||
       !(session = SSL_get_session(ssl)) )
    return PL_existence_error("ssl_session", stream_t);

#if OPENSSL_VERSION_NUMBER < 0x10100000L
  version = session->ssl_version;
  master_key = session->master_key;
  master_key_length = session->master_key_length;
  /* session_key is SSL2 specific, i.e., obsolete */
#ifndef OPENSSL_NO_SSL2
  if ( !add_key_string(list_t, FUNCTOR_session_key1,
		       session->key_arg_length, session->key_arg) )
    return FALSE;
#endif
#else
  version = SSL_SESSION_get_protocol_version(session);
  if ( (master_key = PL_malloc(SSL_MAX_MASTER_KEY_LENGTH)) == NULL )
    return PL_resource_error("memory");
  master_key_length = SSL_SESSION_get_master_key(session, master_key, SSL_MAX_MASTER_KEY_LENGTH);
#endif

  if ( !PL_unify_list_ex(list_t, node_t, list_t) )
    return FALSE;
  if ( !PL_unify_term(node_t,
		      PL_FUNCTOR, FUNCTOR_version1,
		      PL_INTEGER, version))
    return FALSE;


  if ( !add_key_string(list_t, FUNCTOR_master_key1,
		       master_key_length, master_key) )
    return FALSE;

#if OPENSSL_VERSION_NUMBER < 0x10100000L
  if ( !add_key_string(list_t, FUNCTOR_session_id1,
		       session->session_id_length, session->session_id) )
    return FALSE;

  if ( ssl->s3 != NULL ) /* If the connection is SSLv2?! */
  { if ( !add_key_string(list_t, FUNCTOR_client_random1,
			 SSL3_RANDOM_SIZE, ssl->s3->client_random) )
      return FALSE;

    if ( !add_key_string(list_t, FUNCTOR_server_random1,
			 SSL3_RANDOM_SIZE, ssl->s3->server_random) )
      return FALSE;
  }
#else
  /* Note: session_id has no correspondence in OpenSSL >= 1.1.0 */

  { unsigned char random[SSL3_RANDOM_SIZE];

    SSL_get_client_random(ssl, random, SSL3_RANDOM_SIZE);
    if ( !add_key_string(list_t, FUNCTOR_client_random1,
                         SSL3_RANDOM_SIZE, random) )
      return FALSE;

    SSL_get_server_random(ssl, random, SSL3_RANDOM_SIZE);
    if ( !add_key_string(list_t, FUNCTOR_server_random1,
			 SSL3_RANDOM_SIZE, random) )
      return FALSE;
  }

  PL_free(master_key);
#endif

  return PL_unify_nil_ex(list_t);
}


static foreign_t
pl_system_root_certificates(term_t list)
{ X509_list *certs;
  term_t head = PL_new_term_ref();
  term_t tail = PL_copy_term_ref(list);

  if ( !(certs=system_root_certificates()) )
    return PL_unify_nil(list);

  for(; certs; certs = certs->next)
  { if ( !(PL_unify_list(tail, head, tail) &&
	   unify_certificate(head, certs->cert)))
    { return FALSE;
    }
  }

  return PL_unify_nil(tail);
}

static foreign_t
pl_ssl_peer_certificate(term_t stream_t, term_t Cert)
{ IOSTREAM* stream;
  PL_SSL_INSTANCE* instance;
  X509 *cert;

  if ( !PL_get_stream_handle(stream_t, &stream) )
    return FALSE;
  if ( stream->functions != &ssl_funcs )
  { PL_release_stream(stream);
    return PL_domain_error("ssl_stream", stream_t);
  }

  instance = stream->handle;
  PL_release_stream(stream);
  if ( (cert = ssl_peer_certificate(instance)) )
  { return unify_certificate(Cert, cert);
  }

  return FALSE;
}


static foreign_t
pl_evp_decrypt(term_t ciphertext_t, term_t algorithm_t,
	       term_t key_t, term_t iv_t, term_t plaintext_t,
	       term_t options_t)
{ EVP_CIPHER_CTX* ctx = NULL;
  const EVP_CIPHER *cipher;
  char* key;
  char* iv;
  char* ciphertext;
  size_t cipher_length;
  int plain_length;
  char* algorithm;
  char* plaintext;
  int cvt_flags = CVT_ATOM|CVT_STRING|CVT_LIST|CVT_EXCEPTION;
  int rep = REP_UTF8;
  int padding = 1;

  if ( !parse_options(options_t, EVP_MODE, &rep, &padding))
    return FALSE;

  if ( !PL_get_chars(key_t, &key, cvt_flags) ||
       !PL_get_chars(iv_t, &iv, cvt_flags) ||
       !PL_get_nchars(ciphertext_t, &cipher_length, &ciphertext, cvt_flags) ||
       !PL_get_chars(algorithm_t, &algorithm, cvt_flags) )
    return FALSE;

  if ( (cipher = EVP_get_cipherbyname(algorithm)) == NULL )
    return PL_domain_error("cipher", algorithm_t);
  if ((ctx = EVP_CIPHER_CTX_new()) == NULL)
    return FALSE;

  EVP_CIPHER_CTX_init(ctx);
  EVP_DecryptInit_ex(ctx, cipher, NULL,
		     (const unsigned char*)key, (const unsigned char*)iv);
  EVP_CIPHER_CTX_set_padding(ctx, padding);
  plaintext = PL_malloc(cipher_length + EVP_CIPHER_block_size(cipher));
  if ( EVP_DecryptUpdate(ctx, (unsigned char*)plaintext, &plain_length,
			 (unsigned char*)ciphertext, cipher_length) == 1 )
  { int last_chunk = plain_length;
    int rc;
    rc = EVP_DecryptFinal_ex(ctx, (unsigned char*)(plaintext + plain_length),
                              &last_chunk);
    EVP_CIPHER_CTX_free(ctx);
    ERR_print_errors_fp(stderr);
    rc &= PL_unify_chars(plaintext_t, rep | PL_STRING, plain_length + last_chunk,
                         plaintext);
    PL_free(plaintext);
    return rc;
  }

  PL_free(plaintext);
  EVP_CIPHER_CTX_free(ctx);

  return FALSE;
}

static foreign_t
pl_evp_encrypt(term_t plaintext_t, term_t algorithm_t,
               term_t key_t, term_t iv_t, term_t ciphertext_t,
	       term_t options_t)
{ EVP_CIPHER_CTX* ctx = NULL;
  const EVP_CIPHER *cipher;
  char* key;
  char* iv;
  char* ciphertext;
  int cipher_length;
  char* algorithm;
  char* plaintext;
  size_t plain_length;
  int cvt_flags = CVT_ATOM|CVT_STRING|CVT_LIST|CVT_EXCEPTION;
  int rep = REP_UTF8;

  if ( !parse_options(options_t, EVP_MODE, &rep, NULL))
    return FALSE;

  if ( !PL_get_chars(key_t, &key, cvt_flags) ||
       !PL_get_chars(iv_t, &iv, cvt_flags) ||
       !PL_get_nchars(plaintext_t, &plain_length, &plaintext, cvt_flags | rep) ||
       !PL_get_chars(algorithm_t, &algorithm, cvt_flags) )
    return FALSE;

  if ( (cipher = EVP_get_cipherbyname(algorithm)) == NULL )
    return PL_domain_error("cipher", algorithm_t);
  if ((ctx = EVP_CIPHER_CTX_new()) == NULL)
    return FALSE;

  EVP_CIPHER_CTX_init(ctx);
  EVP_EncryptInit_ex(ctx, cipher, NULL,
		     (const unsigned char*)key, (const unsigned char*)iv);

  ciphertext = PL_malloc(plain_length + EVP_CIPHER_block_size(cipher));
  if ( EVP_EncryptUpdate(ctx, (unsigned char*)ciphertext, &cipher_length,
                         (unsigned char*)plaintext, plain_length) == 1 )
  { int last_chunk;
    int rc;

    EVP_EncryptFinal_ex(ctx, (unsigned char*)(ciphertext + cipher_length),
			&last_chunk);
    EVP_CIPHER_CTX_free(ctx);
    rc = PL_unify_chars(ciphertext_t,  PL_STRING|REP_ISO_LATIN_1,
			cipher_length + last_chunk, ciphertext);
    PL_free(ciphertext);
    return rc;
  }

  PL_free(ciphertext);
  EVP_CIPHER_CTX_free(ctx);

  return FALSE;
}

		 /*******************************
		 *	     INSTALL		*
		 *******************************/


install_t
install_ssl4pl(void)
{ ATOM_server             = PL_new_atom("server");
  ATOM_client             = PL_new_atom("client");
  ATOM_password           = PL_new_atom("password");
  ATOM_host               = PL_new_atom("host");
  ATOM_cert               = PL_new_atom("cert");
  ATOM_peer_cert          = PL_new_atom("peer_cert");
  ATOM_cacert_file        = PL_new_atom("cacert_file");
  ATOM_certificate_file   = PL_new_atom("certificate_file");
  ATOM_certificate        = PL_new_atom("certificate");
  ATOM_key_file           = PL_new_atom("key_file");
  ATOM_key                = PL_new_atom("key");
  ATOM_pem_password_hook  = PL_new_atom("pem_password_hook");
  ATOM_cert_verify_hook   = PL_new_atom("cert_verify_hook");
  ATOM_close_parent       = PL_new_atom("close_parent");
  ATOM_disable_ssl_methods= PL_new_atom("disable_ssl_methods");
  ATOM_cipher_list        = PL_new_atom("cipher_list");
  ATOM_ecdh_curve         = PL_new_atom("ecdh_curve");
  ATOM_root_certificates  = PL_new_atom("root_certificates");
  ATOM_sni_hook           = PL_new_atom("sni_hook");
  ATOM_sslv2              = PL_new_atom("sslv2");
  ATOM_sslv23             = PL_new_atom("sslv23");
  ATOM_sslv3              = PL_new_atom("sslv3");
  ATOM_tlsv1              = PL_new_atom("tlsv1");
  ATOM_tlsv1_1            = PL_new_atom("tlsv1_1");
  ATOM_tlsv1_2            = PL_new_atom("tlsv1_2");
  ATOM_minus		  = PL_new_atom("-");
  ATOM_text		  = PL_new_atom("text");
  ATOM_octet		  = PL_new_atom("octet");
  ATOM_utf8		  = PL_new_atom("utf8");
  ATOM_require_crl	  = PL_new_atom("require_crl");
  ATOM_crl	          = PL_new_atom("crl");
  ATOM_sha1		  = PL_new_atom("sha1");
  ATOM_sha224		  = PL_new_atom("sha224");
  ATOM_sha256		  = PL_new_atom("sha256");
  ATOM_sha384		  = PL_new_atom("sha384");
  ATOM_sha512		  = PL_new_atom("sha512");
  ATOM_pkcs	          = PL_new_atom("pkcs");
  ATOM_pkcs_oaep	  = PL_new_atom("pkcs_oaep");
  ATOM_none	          = PL_new_atom("none");
  ATOM_block	          = PL_new_atom("block");
  ATOM_encoding	          = PL_new_atom("encoding");
  ATOM_padding	          = PL_new_atom("padding");

  FUNCTOR_error2          = PL_new_functor(PL_new_atom("error"), 2);
  FUNCTOR_ssl_error4      = PL_new_functor(PL_new_atom("ssl_error"), 4);
  FUNCTOR_permission_error3=PL_new_functor(PL_new_atom("permission_error"), 3);
  FUNCTOR_ip4		  = PL_new_functor(PL_new_atom("ip"), 4);
  FUNCTOR_version1	  = PL_new_functor(PL_new_atom("version"), 1);
  FUNCTOR_notbefore1	  = PL_new_functor(PL_new_atom("notbefore"), 1);
  FUNCTOR_notafter1	  = PL_new_functor(PL_new_atom("notafter"), 1);
  FUNCTOR_subject1	  = PL_new_functor(PL_new_atom("subject"), 1);
  FUNCTOR_issuername1	  = PL_new_functor(PL_new_atom("issuer_name"), 1);
  FUNCTOR_serial1	  = PL_new_functor(PL_new_atom("serial"), 1);
  FUNCTOR_key1	          = PL_new_functor(PL_new_atom("key"), 1);
  FUNCTOR_public_key1     = PL_new_functor(PL_new_atom("public_key"), 1);
  FUNCTOR_private_key1    = PL_new_functor(PL_new_atom("private_key"), 1);
  FUNCTOR_rsa8		  = PL_new_functor(PL_new_atom("rsa"), 8);
  FUNCTOR_hash1	          = PL_new_functor(PL_new_atom("hash"), 1);
  FUNCTOR_next_update1    = PL_new_functor(PL_new_atom("next_update"), 1);
  FUNCTOR_signature1      = PL_new_functor(PL_new_atom("signature"), 1);
  FUNCTOR_equals2         = PL_new_functor(PL_new_atom("="), 2);
  FUNCTOR_crl1            = PL_new_functor(PL_new_atom("crl"), 1);
  FUNCTOR_revoked2        = PL_new_functor(PL_new_atom("revoked"), 2);
  FUNCTOR_revocations1    = PL_new_functor(PL_new_atom("revocations"), 1);
#ifndef OPENSSL_NO_SSL2
  FUNCTOR_session_key1    = PL_new_functor(PL_new_atom("session_key"), 1);
#endif
  FUNCTOR_master_key1     = PL_new_functor(PL_new_atom("master_key"), 1);
  FUNCTOR_session_id1     = PL_new_functor(PL_new_atom("session_id"), 1);
  FUNCTOR_client_random1  = PL_new_functor(PL_new_atom("client_random"), 1);
  FUNCTOR_server_random1  = PL_new_functor(PL_new_atom("server_random"), 1);
  FUNCTOR_system1         = PL_new_functor(PL_new_atom("system"), 1);
  FUNCTOR_unknown1         = PL_new_functor(PL_new_atom("unknown"), 1);
  FUNCTOR_unsupported_hash_algorithm1 = PL_new_functor(PL_new_atom("unsupported_hash_algorithm"), 1);

  PL_register_foreign("_ssl_context",	4, pl_ssl_context,    0);
  PL_register_foreign("_ssl_exit",	1, pl_ssl_exit,	      0);
  PL_register_foreign("ssl_put_socket",	2, pl_ssl_put_socket, 0);
  PL_register_foreign("ssl_get_socket",	2, pl_ssl_get_socket, 0);
  PL_register_foreign("ssl_negotiate",	5, pl_ssl_negotiate,  0);
  PL_register_foreign("ssl_debug",	1, pl_ssl_debug,      0);
  PL_register_foreign("ssl_session",    2, pl_ssl_session,    0);
  PL_register_foreign("ssl_peer_certificate",
					2, pl_ssl_peer_certificate, 0);
  PL_register_foreign("load_crl",       2, pl_load_crl,      0);
  PL_register_foreign("load_certificate",2,pl_load_certificate,      0);
  PL_register_foreign("load_private_key",3,pl_load_private_key,      0);
  PL_register_foreign("load_public_key", 2,pl_load_public_key,      0);
  PL_register_foreign("rsa_private_decrypt", 4, pl_rsa_private_decrypt, 0);
  PL_register_foreign("rsa_private_encrypt", 4, pl_rsa_private_encrypt, 0);
  PL_register_foreign("rsa_public_decrypt", 4, pl_rsa_public_decrypt, 0);
  PL_register_foreign("rsa_public_encrypt", 4, pl_rsa_public_encrypt, 0);
  PL_register_foreign("system_root_certificates", 1, pl_system_root_certificates, 0);
  PL_register_foreign("rsa_sign", 5, pl_rsa_sign, 0);
  PL_register_foreign("rsa_verify", 5, pl_rsa_verify, 0);
  PL_register_foreign("evp_decrypt",        6, pl_evp_decrypt, 0);
  PL_register_foreign("evp_encrypt",        6, pl_evp_encrypt, 0);

  /*
   * Initialize ssllib
   */
  (void) ssl_lib_init();

  PL_set_prolog_flag("ssl_library_version", PL_ATOM,
		     SSLeay_version(SSLEAY_VERSION));
  PL_set_prolog_flag("system_cacert_filename", PL_ATOM,
		     SYSTEM_CACERT_FILENAME);
}

install_t
uninstall_ssl4pl(void)
{ ssl_lib_exit();
}
