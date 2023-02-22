/*  Part of SWI-Prolog

    Author:        Matt Lilley and Markus Triska
    WWW:           http://www.swi-prolog.org
    Copyright (c)  2004-2017, SWI-Prolog Foundation
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
#include <assert.h>
#include <string.h>
#include <SWI-Stream.h>
#include <SWI-Prolog.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#ifdef HAVE_OPENSSL_CORE_NAMES_H
#include <openssl/core_names.h>
#endif
#ifdef HAVE_OPENSSL_PARAM_BUILD_H
#include <openssl/param_build.h>
#endif
#ifdef HAVE_OPENSSL_KDF_H
#include <openssl/kdf.h>
#endif
#include "crypt_blowfish.h"

#include "cryptolib.c"

static atom_t ATOM_sslv23;
static atom_t ATOM_minus;                       /* "-" */
static atom_t ATOM_text;
static atom_t ATOM_octet;
static atom_t ATOM_utf8;

static atom_t ATOM_md5;
static atom_t ATOM_sha1;
static atom_t ATOM_sha224;
static atom_t ATOM_sha256;
static atom_t ATOM_sha384;
static atom_t ATOM_sha512;
static atom_t ATOM_blake2s256;
static atom_t ATOM_blake2b512;
static atom_t ATOM_sha3_224;
static atom_t ATOM_sha3_256;
static atom_t ATOM_sha3_384;
static atom_t ATOM_sha3_512;
static atom_t ATOM_ripemd160;

static atom_t ATOM_pkcs1;
static atom_t ATOM_pkcs1_oaep;
static atom_t ATOM_none;
static atom_t ATOM_block;
static atom_t ATOM_algorithm;
static atom_t ATOM_hmac;
static atom_t ATOM_close_parent;
static atom_t ATOM_encoding;
static atom_t ATOM_padding;

static functor_t FUNCTOR_public_key1;
static functor_t FUNCTOR_private_key1;

typedef enum
{ RSA_MODE, EVP_MODE
} crypt_mode_t;

#if defined HAVE_EVP_PKEY_NEW && defined HAVE_EVP_PKEY_FREE && defined HAVE_EVP_PKEY_GET_BN_PARAM && defined HAVE_EVP_PKEY_GET_OCTET_STRING_PARAM && defined HAVE_EVP_PKEY_GET_SIZE && defined HAVE_EVP_PKEY_DECRYPT && defined HAVE_EVP_PKEY_ENCRYPT && defined HAVE_EVP_PKEY_SIGN && defined HAVE_EVP_PKEY_VERIFY && defined HAVE_EVP_PKEY_Q_KEYGEN && defined HAVE_OSSL_PARAM_CONSTRUCT_UTF8_STRING && defined HAVE_BN_CHECK_PRIME && defined HAVE_OSSL_PARAM_BLD_NEW
#define USE_EVP_API 1
#endif

#ifdef USE_EVP_API
#define RSAKEY EVP_PKEY
#else
#define RSAKEY RSA
#endif



                 /***************************
                 *       RANDOM BYTES       *
                 ****************************/

static foreign_t
pl_crypto_n_random_bytes(term_t tn, term_t tout)
{ size_t len;
  int rc;
  unsigned char *buffer;

  if ( !PL_get_size_ex(tn, &len) )
    return FALSE;

  if ( !(buffer = malloc(len)) )
    return PL_resource_error("memory");

  if ( RAND_bytes(buffer, len) == 0 )
  { free(buffer);
    return raise_ssl_error(ERR_get_error());
  }

  rc = PL_unify_chars(tout, PL_CODE_LIST|REP_ISO_LATIN_1,
		      len, (const char *) buffer);

  free(buffer);

  return rc;
}


                 /***************************
                 *         HASHING          *
                 ****************************/


#define HASH_CONTEXT_MAGIC (~ 0x53481284L)

typedef struct hash_context
{ int             magic;
  atom_t          atom;
  IOENC           encoding;
  const EVP_MD   *algorithm;

  IOSTREAM       *parent_stream;      /* Original stream */
  IOSTREAM       *hash_stream;
  IOENC           parent_encoding;
  int             close_parent;

  EVP_MD_CTX     *ctx;
#if defined USE_EVP_API
  EVP_MAC         *mac;
  EVP_MAC_CTX     *mac_ctx;
#else
  HMAC_CTX       *mac_ctx;
#endif
  char           *mac_key;
} PL_CRYPTO_HASH_CONTEXT;

static void
free_crypto_hash_context(PL_CRYPTO_HASH_CONTEXT *c)
{ EVP_MD_CTX_free(c->ctx);
  free(c->mac_key);
#ifdef USE_EVP_API
  EVP_MAC_free(c->mac);
  EVP_MAC_CTX_free(c->mac_ctx);
#elif defined HAVE_HMAC_CTX_FREE
  HMAC_CTX_free(c->mac_ctx);
#endif
  free(c);
}

static int
release_hash_context(atom_t atom)
{ PL_CRYPTO_HASH_CONTEXT **cp = PL_blob_data(atom, NULL, NULL);
  PL_CRYPTO_HASH_CONTEXT  *c = *cp;

  ssl_deb(4, "Releasing PL_CRYPTO_HASH_CONTEXT %p\n", c);
  free_crypto_hash_context(c);
  return TRUE;
}

static int
compare_hash_context(atom_t a, atom_t b)
{ PL_CRYPTO_HASH_CONTEXT **cp1 = PL_blob_data(a, NULL, NULL);
  PL_CRYPTO_HASH_CONTEXT **cp2 = PL_blob_data(b, NULL, NULL);
  PL_CRYPTO_HASH_CONTEXT  *c1 = *cp1;
  PL_CRYPTO_HASH_CONTEXT  *c2 = *cp2;

  return ( c1 > c2 ?  1 :
           c1 < c2 ? -1 : 0
         );
}

static int
write_hash_context(IOSTREAM *s, atom_t symbol, int flags)
{ PL_CRYPTO_HASH_CONTEXT **cp = PL_blob_data(symbol, NULL, NULL);
  PL_CRYPTO_HASH_CONTEXT  *c  = *cp;

  Sfprintf(s, "<crypto_hash_context>(%p)", c);

  return TRUE;
}

static void
acquire_hash_context(atom_t atom)
{ PL_CRYPTO_HASH_CONTEXT **cp = PL_blob_data(atom, NULL, NULL);
  PL_CRYPTO_HASH_CONTEXT  *c  = *cp;

  c->atom = atom;
}

static PL_blob_t crypto_hash_context_type =
{ PL_BLOB_MAGIC,
  0,
  "crypto_hash_context",
  release_hash_context,
  compare_hash_context,
  write_hash_context,
  acquire_hash_context
};


static int
unify_hash_context(term_t tcontext, PL_CRYPTO_HASH_CONTEXT *context)
{ if ( PL_unify_blob(tcontext, &context, sizeof(context), &crypto_hash_context_type) )
    return TRUE;

  free_crypto_hash_context(context);
  if ( !PL_exception(0) )
    return PL_uninstantiation_error(tcontext);

  return FALSE;
}


static int
get_hash_context(term_t tcontext, PL_CRYPTO_HASH_CONTEXT **context)
{ PL_blob_t *type;
  void *data;

  if ( PL_get_blob(tcontext, &data, NULL, &type) &&
       type == &crypto_hash_context_type )
  { PL_CRYPTO_HASH_CONTEXT *c = *(PL_CRYPTO_HASH_CONTEXT**)data;

    assert(c->magic == HASH_CONTEXT_MAGIC);
    *context = c;

    return TRUE;
  }

  return PL_type_error("crypto_hash_context", tcontext);
}

typedef struct algorithm_pair {
  atom_t a_algorithm;
  const EVP_MD *algorithm;
} ALGORITHM_PAIR;

#define ALGO(a) { ATOM_## a , EVP_## a() }
#define NELEMS(array) (sizeof(array)/sizeof((array)[0]))

static int
get_hash_algorithm(atom_t a_algorithm, const EVP_MD **algorithm)
{ int i;
  ALGORITHM_PAIR algorithms[] =
    { ALGO(md5), ALGO(ripemd160),
#if defined(HAVE_EVP_BLAKE2B512) && defined(HAVE_EVP_BLAKE2S256)
      ALGO(blake2s256), ALGO(blake2b512),
#endif
#if defined(HAVE_EVP_SHA3_224) && defined(HAVE_EVP_SHA3_256) && \
    defined(HAVE_EVP_SHA3_384) && defined(HAVE_EVP_SHA3_512)
      ALGO(sha3_224), ALGO(sha3_256), ALGO(sha3_384), ALGO(sha3_512),
#endif
      ALGO(sha1), ALGO(sha224), ALGO(sha256), ALGO(sha384), ALGO(sha512)
    };

  for (i = 0; i < NELEMS(algorithms); i++)
  { if (a_algorithm == algorithms[i].a_algorithm)
    { *algorithm = algorithms[i].algorithm;
      return TRUE;
    }
  }

  return FALSE;
}

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
hash_options(term_t options, PL_CRYPTO_HASH_CONTEXT *result)
{ term_t opts = PL_copy_term_ref(options);
  term_t opt = PL_new_term_ref();

  /* defaults */
  result->encoding = REP_UTF8;
  result->algorithm = EVP_sha256();

  while(PL_get_list(opts, opt, opts))
  { atom_t aname;
    size_t arity;

    if ( PL_get_name_arity(opt, &aname, &arity) && arity == 1 )
    { term_t a = PL_new_term_ref();

      _PL_get_arg(1, opt, a);

      if ( aname == ATOM_algorithm )
      { atom_t a_algorithm;

        if ( !PL_get_atom_ex(a, &a_algorithm) )
          return FALSE;

        if ( !get_hash_algorithm(a_algorithm, &result->algorithm) )
          return PL_domain_error("algorithm", a);
      } else if ( aname == ATOM_hmac )
      { size_t key_len;
        char *key;

        if ( !PL_get_nchars(a, &key_len, &key,
                      CVT_ATOM|CVT_STRING|CVT_LIST|CVT_EXCEPTION) )
          return FALSE;
        result->mac_key = ssl_strdup(key);
      } else if ( aname == ATOM_close_parent )
      { if ( !PL_get_bool_ex(a, &result->close_parent) )
          return FALSE;
      } else if ( aname == ATOM_encoding )
      {  int rep;
         if ( !get_text_representation(a, &rep) )
           return PL_domain_error("encoding", a);

         result->encoding = ( rep == REP_UTF8 ) ? REP_UTF8 : REP_ISO_LATIN_1;
      }
    } else
    { return PL_type_error("option", opt);
    }
  }

  if ( !PL_get_nil_ex(opts) )
    return FALSE;

  return TRUE;
}


static foreign_t
pl_crypto_hash_context_new(term_t tcontext, term_t options)
{
  PL_CRYPTO_HASH_CONTEXT *context = NULL;

  context = malloc(sizeof(*context));

  if ( !context )
    return FALSE;

  memset(context, 0, sizeof(*context));
  context->magic    = HASH_CONTEXT_MAGIC;

  if ( !hash_options(options, context) )
    return FALSE;

#ifdef USE_EVP_API
  if ( context->mac_key )
  { OSSL_PARAM params[2];
    context->mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if ( context->mac == NULL )
    { return FALSE;
    }
    context->mac_ctx = EVP_MAC_CTX_new(context->mac);
    if ( context->mac_ctx == NULL )
    { EVP_MAC_free(context->mac);
      return FALSE;
    }
    params[0] = OSSL_PARAM_construct_utf8_string("digest", (char *)EVP_MD_name(context->algorithm), 0);
    params[1] = OSSL_PARAM_construct_end();
    if ( !EVP_MAC_init(context->mac_ctx,
                       (unsigned char*)context->mac_key, strlen(context->mac_key),
                       params) )
    { EVP_MAC_CTX_free(context->mac_ctx);
      EVP_MAC_free(context->mac);
      return FALSE;
    }
  }
#elif defined HAVE_HMAC_CTX_NEW
  if ( context->mac_key )
  { context->mac_ctx = HMAC_CTX_new();
    if ( !HMAC_Init_ex(context->mac_ctx,
                       context->mac_key, strlen(context->mac_key),
                       context->algorithm, NULL) )
    { HMAC_CTX_free(context->mac_ctx);
      return FALSE;
    }
  }
#endif

  if ( !context->mac_ctx )
  { context->ctx = EVP_MD_CTX_new();
    if ( !EVP_DigestInit_ex(context->ctx, context->algorithm, NULL) )
    { EVP_MD_CTX_free(context->ctx);
      return FALSE;
    }
  }

  return unify_hash_context(tcontext, context);
}

static foreign_t
pl_crypto_hash_context_copy(term_t tin, term_t tout)
{
  PL_CRYPTO_HASH_CONTEXT *in, *out;
  int rc = 0;

  if ( !get_hash_context(tin, &in) )
    return FALSE;

  out = malloc(sizeof(*out));

  if ( !out )
    return FALSE;

  out->magic = HASH_CONTEXT_MAGIC;
  out->mac_key = ssl_strdup(in->mac_key);

  out->encoding = in->encoding;
  out->algorithm = in->algorithm;

  out->ctx = in->ctx ? EVP_MD_CTX_new() : NULL;
  if ( out->ctx )
  { if ( !EVP_DigestInit_ex(out->ctx, out->algorithm, NULL) )
    { EVP_MD_CTX_free(out->ctx);
      return FALSE;
    }
    rc = EVP_MD_CTX_copy_ex(out->ctx, in->ctx);
  }
#if defined(USE_EVP_API) && defined(USE_EVP_API)
  out->mac = in->mac;
  if ( in->mac != NULL )
  { EVP_MAC_up_ref(in->mac);
  }
  out->mac_ctx = in->mac_ctx ? EVP_MAC_CTX_dup(in->mac_ctx) : NULL;
  rc = TRUE;
#elif defined(HAVE_HMAC_CTX_NEW) && defined(HAVE_HMAC_CTX_FREE)
  out->mac_ctx = in->mac_ctx ? HMAC_CTX_new() : NULL;

  if ( out->mac_ctx )
  { if ( !HMAC_Init_ex(out->mac_ctx,
                       out->mac_key, strlen(out->mac_key),
                       out->algorithm, NULL) )
    { HMAC_CTX_free(out->mac_ctx);
      return FALSE;
    }
    rc = HMAC_CTX_copy(out->mac_ctx, in->mac_ctx);
  }
#else
  out->mac_ctx = NULL;
#endif

  return unify_hash_context(tout, out) && rc;
}


static int
hash_append(PL_CRYPTO_HASH_CONTEXT *context, void *data, size_t size)
{
  if ( context->mac_ctx )
  {
#ifdef USE_EVP_API
    return  EVP_MAC_update(context->mac_ctx, data, size);
#else
    return HMAC_Update(context->mac_ctx, data, size);
#endif
  }

  return EVP_DigestUpdate(context->ctx, data, size);
}


static foreign_t
pl_crypto_update_hash_context(term_t from, term_t tcontext)
{
  PL_CRYPTO_HASH_CONTEXT *context = NULL;
  size_t datalen;
  char *data;

  if ( !get_hash_context(tcontext, &context) )
    return FALSE;

  if ( !PL_get_nchars(from, &datalen, &data,
                      CVT_ATOM|CVT_STRING|CVT_LIST|CVT_EXCEPTION|context->encoding) )
    return FALSE;


  return hash_append(context, data, datalen);
}

static foreign_t
pl_crypto_hash_context_hash(term_t tcontext, term_t hash)
{
  PL_CRYPTO_HASH_CONTEXT *context = NULL;
  unsigned char digest[EVP_MAX_MD_SIZE];
  size_t len;
  if ( !get_hash_context(tcontext, &context) )
    return FALSE;

  if ( context->mac_ctx )
  {
#ifdef USE_EVP_API
    EVP_MAC_final(context->mac_ctx, digest, &len, EVP_MAX_MD_SIZE);
#else
    unsigned int ulen;
    HMAC_Final(context->mac_ctx, digest, &ulen);
    len = ulen;
#endif
  } else
  { unsigned int ulen;
    EVP_DigestFinal_ex(context->ctx, digest, &ulen);
    len = ulen;
  }

  return PL_unify_list_ncodes(hash, len, (char *) digest);
}


                 /***************************
                 *     Hashes on streams    *
                 ****************************/

static ssize_t                          /* range-limited read */
hash_read(void *handle, char *buf, size_t size)
{ PL_CRYPTO_HASH_CONTEXT *ctx = handle;
  ssize_t rd;

  if ( (rd = Sfread(buf, sizeof(char), size, ctx->parent_stream)) >= 0 )
  { hash_append(ctx, buf, rd);

    return rd;
  }

  return rd;
}


static ssize_t
hash_write(void *handle, char *buf, size_t size)
{ PL_CRYPTO_HASH_CONTEXT *ctx = handle;
  size_t written = 0;

  hash_append(ctx, buf, size);

  while ( written < size )
  { ssize_t wr = Sfwrite(buf+written, sizeof(char), size, ctx->parent_stream);

    if ( wr >= 0 )
    { written += wr;
    } else
      return wr;
  }

  return size;
}


static int
hash_control(void *handle, int op, void *data)
{ PL_CRYPTO_HASH_CONTEXT *ctx = handle;

  switch(op)
  { case SIO_SETENCODING:
      return 0;                         /* allow switching encoding */
    default:
      if ( ctx->parent_stream->functions->control )
        return (*ctx->parent_stream->functions->control)(ctx->parent_stream->handle, op, data);
      return -1;
  }
}


static int
hash_close(void *handle)
{ int rc = 0;
  PL_CRYPTO_HASH_CONTEXT *ctx = handle;

  ctx->parent_stream->encoding = ctx->parent_encoding;
  if ( ctx->parent_stream->upstream )
    Sset_filter(ctx->parent_stream, NULL);

  if ( ctx->close_parent )
    rc = Sclose(ctx->parent_stream);

  free_crypto_hash_context(ctx);

  return rc;
}

static IOFUNCTIONS hash_functions =
{ hash_read,
  hash_write,
  NULL,                 /* seek */
  hash_close,
  hash_control,
  NULL,                 /* seek64 */
};

#define COPY_FLAGS (SIO_INPUT|SIO_OUTPUT| \
                    SIO_TEXT| \
                    SIO_REPXML|SIO_REPPL|\
                    SIO_RECORDPOS)

static foreign_t
pl_crypto_open_hash_stream(term_t org, term_t new, term_t tcontext)
{ PL_CRYPTO_HASH_CONTEXT *context;
  IOSTREAM *s, *s2;

  if ( !get_hash_context(tcontext, &context) )
    return FALSE;

  if ( !PL_get_stream_handle(org, &s) )
    return FALSE;                       /* Error */

  context->parent_encoding = s->encoding;
  context->parent_stream = s;

  if ( !(s2 = Snew(context,
                   (s->flags&COPY_FLAGS)|SIO_FBUF,
                   &hash_functions))    )
  { PL_release_stream(s);

    return FALSE;
  }

  s2->encoding = s->encoding;
  s->encoding = ENC_OCTET;
  context->hash_stream = s2;

  if ( PL_unify_stream(new, s2) )
  { Sset_filter(s, s2);
    PL_release_stream(s);
    /* Increase atom reference count so that the context is not
       GCd until this session is complete */
    PL_register_atom(context->atom);

    return TRUE;
  } else
  { PL_release_stream(s);
    return FALSE;
  }
}


static foreign_t
pl_crypto_stream_hash_context(term_t stream, term_t tcontext)
{ IOSTREAM *s;
  int rc;

  if ( PL_get_stream_handle(stream, &s) )
  { PL_CRYPTO_HASH_CONTEXT *ctx = s->handle;
    rc = unify_hash_context(tcontext, ctx);
    PL_release_stream(s);
    return rc;
  }

  return FALSE;
}

                 /***************************
                 *    Hashes of passwords   *
                 ****************************/

static foreign_t
pl_crypto_password_hash_pbkdf2(term_t tpw, term_t tsalt, term_t titer, term_t tdigest)
{ char *pw, *salt;
  size_t pwlen, saltlen;
  int iter;
  const int DIGEST_LEN = 64;
  unsigned char digest[DIGEST_LEN];

  if ( !PL_get_nchars(tpw, &pwlen, &pw,
                      CVT_ATOM|CVT_STRING|CVT_LIST|CVT_EXCEPTION|REP_UTF8) ||
       !PL_get_nchars(tsalt, &saltlen, &salt, CVT_LIST) ||
       !PL_get_integer_ex(titer, &iter) )
    return FALSE;

  PKCS5_PBKDF2_HMAC((const char *) pw, pwlen,
                    (const unsigned char *) salt, saltlen,
                    iter, EVP_sha512(), DIGEST_LEN, digest);

  return PL_unify_list_ncodes(tdigest, DIGEST_LEN, (char *) digest);
}

static foreign_t
pl_crypto_password_hash_bcrypt(term_t tpw, term_t tsetting, term_t tdigest)
{ char *pw, *setting;
  size_t pwlen, settinglen;
  const int DIGEST_LEN = 7 + 22 + 31 + 1;
  char digest[DIGEST_LEN];

  if ( !PL_get_nchars(tpw, &pwlen, &pw,
                      CVT_ATOM|CVT_STRING|CVT_LIST|CVT_EXCEPTION|REP_UTF8) ||
       !PL_get_nchars(tsetting, &settinglen, &setting,
                      CVT_ATOM|CVT_STRING|CVT_LIST|CVT_EXCEPTION|REP_UTF8) )
    return FALSE;

  char* ret = _crypt_blowfish_rn(pw, setting, (char *) digest, DIGEST_LEN);
  if ( ret == NULL )
    return FALSE;

  return PL_unify_chars(tdigest, PL_ATOM | REP_UTF8, DIGEST_LEN - 1, (char *) digest);
}

static foreign_t
pl_crypto_data_hkdf(term_t tkey, term_t tsalt, term_t tinfo, term_t talg,
                    term_t tencoding, term_t toutlen, term_t tout)
{
#if defined(HAVE_OPENSSL_KDF_H) && defined(EVP_PKEY_HKDF)
  EVP_PKEY_CTX *pctx;
  char *salt, *key, *info;
  size_t keylen, infolen, outlen, saltlen;
  int rep;
  const EVP_MD *alg;
  unsigned char *out;
  atom_t a_algorithm;

  if ( !PL_get_nchars(tsalt, &saltlen, &salt, CVT_LIST) ||
       !PL_get_size_ex(toutlen, &outlen) ||
       !PL_get_atom_ex(talg, &a_algorithm) )
    return FALSE;

  if ( !get_text_representation(tencoding, &rep) )
    return PL_domain_error("encoding", tencoding);

  if ( !PL_get_nchars(tkey, &keylen, &key,
                      CVT_ATOM|CVT_STRING|CVT_LIST|CVT_EXCEPTION|rep) ||
       !PL_get_nchars(tinfo, &infolen, &info,
                      CVT_ATOM|CVT_STRING|CVT_LIST|CVT_EXCEPTION) )
    return FALSE;

  if ( !get_hash_algorithm(a_algorithm, &alg) )
    return PL_domain_error("algorithm", a_algorithm);

  if ( !(out = malloc(outlen)) )
    return PL_resource_error("memory");

  pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);

  if ( (EVP_PKEY_derive_init(pctx) > 0) &&
       (EVP_PKEY_CTX_set_hkdf_md(pctx, alg) > 0) &&
       (EVP_PKEY_CTX_set1_hkdf_salt(pctx, (unsigned char*)salt, saltlen) > 0) &&
       (EVP_PKEY_CTX_set1_hkdf_key(pctx, (unsigned char*)key, keylen) > 0) &&
       (EVP_PKEY_CTX_add1_hkdf_info(pctx, (unsigned char*)info, infolen) > 0) &&
       (EVP_PKEY_derive(pctx, out, &outlen) > 0) )
  { int rc = PL_unify_list_ncodes(tout, outlen, (char *) out);
    free(out);
    EVP_PKEY_CTX_free(pctx);
    return rc;
  }

  free(out);
  EVP_PKEY_CTX_free(pctx);
  return raise_ssl_error(ERR_get_error());
#else
  return ssl_missing("HKDF");
#endif
}

                 /***************************
                 *       Bignums & Keys     *
                 ****************************/

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

#ifndef OPENSSL_NO_EC

#ifdef USE_EVP_API
#define ECKEY EVP_PKEY
#else
#define ECKEY EC_KEY
#endif

static int
recover_ec(term_t t, ECKEY **rec)
{
  ECKEY *key;
  BIGNUM *privkey = NULL;
  term_t pubkey;
  unsigned char *codes;
  size_t codes_len;
  term_t tcurve = PL_new_term_ref();
  char *curve;

  if ( !(tcurve &&
         PL_get_arg(3, t, tcurve) &&
         PL_get_chars(tcurve, &curve, CVT_ATOM|CVT_STRING|CVT_EXCEPTION) &&
#ifdef USE_EVP_API
         (key = EVP_EC_gen(curve))
#else
         (key = EC_KEY_new_by_curve_name(OBJ_sn2nid(curve)))
#endif
     ) )
    return FALSE;

  if ( !get_bn_arg(1, t, &privkey) )
  {
#ifdef USE_EVP_API
    EVP_PKEY_free(key);
#else
    EC_KEY_free(key);
#endif
    return FALSE;
  }

  if ( privkey )
  {
#ifdef USE_EVP_API
    EVP_PKEY_set_bn_param(key, "priv", privkey);
#else
    EC_KEY_set_private_key(key, privkey);
#endif
  }

  if ( (pubkey=PL_new_term_ref()) &&
       PL_get_arg(2, t, pubkey) &&
       PL_get_nchars(pubkey, &codes_len, (char **) &codes,
                     CVT_ATOM|CVT_STRING|CVT_LIST|CVT_EXCEPTION) &&
#ifdef USE_EVP_API
        EVP_PKEY_set_octet_string_param(key, "pub", (const unsigned char*) codes, codes_len)
#else
       (key = o2i_ECPublicKey(&key, (const unsigned char**) &codes, codes_len))
#endif
  )
  { *rec = key;
    return TRUE;
  }

#ifdef USE_EVP_API
  EVP_PKEY_free(key);
#else
  EC_KEY_free(key);
#endif
  return FALSE;
}
#endif


static int
recover_rsa(term_t t, RSAKEY** keyp)
{
#ifdef USE_EVP_API
  RSAKEY* key = EVP_PKEY_new();
#else
  RSAKEY *key = RSA_new();
#endif

#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
  if ( get_bn_arg(1, t, &key->n) &&
       get_bn_arg(2, t, &key->e) &&
       get_bn_arg(3, t, &key->d) &&
       get_bn_arg(4, t, &key->p) &&
       get_bn_arg(5, t, &key->q) &&
       get_bn_arg(6, t, &key->dmp1) &&
       get_bn_arg(7, t, &key->dmq1) &&
       get_bn_arg(8, t, &key->iqmp)
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
#ifdef USE_EVP_API
  OSSL_PARAM_BLD *param_builder;
  OSSL_PARAM *params = NULL;
  EVP_PKEY_CTX* ctx;
  ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
  if (!ctx)
  { return FALSE;
  }
  param_builder = OSSL_PARAM_BLD_new();
  if ( ! ( OSSL_PARAM_BLD_push_BN(param_builder, OSSL_PKEY_PARAM_RSA_N, n) &&
           OSSL_PARAM_BLD_push_BN(param_builder, OSSL_PKEY_PARAM_RSA_E, e) &&
           OSSL_PARAM_BLD_push_BN(param_builder, OSSL_PKEY_PARAM_RSA_D, d) ) ||
        ( ( p || q ) && ! ( OSSL_PARAM_BLD_push_BN(param_builder, OSSL_PKEY_PARAM_RSA_FACTOR1, p) &&
                            OSSL_PARAM_BLD_push_BN(param_builder, OSSL_PKEY_PARAM_RSA_FACTOR2, q) ) ) ||
        ( ( dmp1 || dmq1 || iqmp ) && ! ( OSSL_PARAM_BLD_push_BN(param_builder, OSSL_PKEY_PARAM_RSA_EXPONENT1, dmp1) &&
                                          OSSL_PARAM_BLD_push_BN(param_builder, OSSL_PKEY_PARAM_RSA_EXPONENT2, dmq1) &&
                                          OSSL_PARAM_BLD_push_BN(param_builder, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, iqmp) ) ) )
  { EVP_PKEY_free(key);
    OSSL_PARAM_BLD_free(param_builder);
    return raise_ssl_error(ERR_get_error());
  }
  params = OSSL_PARAM_BLD_to_param(param_builder);
  if (!params)
  { EVP_PKEY_CTX_free(ctx);
    return FALSE;
  }
	OSSL_PARAM_BLD_free(param_builder);
  if (EVP_PKEY_fromdata_init(ctx) <= 0)
  { EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    return raise_ssl_error(ERR_get_error());
  }
  if (EVP_PKEY_fromdata(ctx, &key, EVP_PKEY_KEYPAIR, params) <= 0)
  { EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    return raise_ssl_error(ERR_get_error());
  }
  EVP_PKEY_CTX_free(ctx);
  OSSL_PARAM_free(params);
  *keyp = key;
  return TRUE;
#else
    if ( !RSA_set0_key(key, n, e, d) ||
         ( (p || q) && !RSA_set0_factors(key, p, q) ) ||
         ( (dmp1 || dmq1 || iqmp) &&
           !RSA_set0_crt_params(key, dmp1, dmq1, iqmp)) )
    { RSA_free(key);
      return FALSE;
    }
#endif
#endif
    *keyp = key;
    return TRUE;
  }
#ifdef USE_EVP_API
  EVP_PKEY_free(key);
#else
  RSA_free(key);
#endif
  return FALSE;
}


static int
recover_private_key(term_t t, RSAKEY** rsap)
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
recover_public_key(term_t t, RSAKEY** rsap)
{ if ( PL_is_functor(t, FUNCTOR_public_key1) )
  { term_t arg;

    if ( (arg = PL_new_term_ref()) &&
	 PL_get_arg(1, t, arg) )
      return recover_rsa(arg, rsap);

    return FALSE;
  }

  return PL_type_error("public_key", t);
}


                 /*******************************
                 *       OPTION PROCESSING      *
                 *******************************/

static int
get_padding(term_t t, crypt_mode_t mode, int *padding)
{ atom_t a;

  if ( PL_get_atom_ex(t, &a) )
  { if      ( a == ATOM_pkcs1 && mode == RSA_MODE )      *padding = RSA_PKCS1_PADDING;
    else if ( a == ATOM_pkcs1_oaep && mode == RSA_MODE ) *padding = RSA_PKCS1_OAEP_PADDING;
    else if ( a == ATOM_none && mode == RSA_MODE  )      *padding = RSA_NO_PADDING;
#ifdef RSA_SSLV23_PADDING    /* removed from OpenSSL 3.0 */
    else if ( a == ATOM_sslv23  && mode == RSA_MODE )    *padding = RSA_SSLV23_PADDING;
#endif
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



                 /*******************************
                 *       ECDSA SIGN/VERIFY      *
                 *******************************/


static foreign_t
pl_ecdsa_sign(term_t Private, term_t Data, term_t Enc, term_t Signature)
{
#ifndef OPENSSL_NO_ECDSA
  unsigned char *data;
  size_t data_len;
  ECKEY *key;
  unsigned char *signature = NULL;
  int rc;
#ifdef USE_EVP_API
  size_t signature_len;
#else
  ECDSA_SIG *sig;
  unsigned int signature_len;
#endif

  if ( !recover_ec(Private, &key) ||
       !get_enc_text(Data, Enc, &data_len, &data) )
    return FALSE;

#ifdef USE_EVP_API
  signature_len = EVP_PKEY_get_size(key);
  EVP_PKEY_CTX *sign_ctx = EVP_PKEY_CTX_new(key, NULL);
  EVP_PKEY_sign_init(sign_ctx);
  rc = EVP_PKEY_sign(sign_ctx,
		                 signature, &signature_len,
		                 data, (unsigned int)data_len);
  EVP_PKEY_CTX_free(sign_ctx);
  if (!rc)
    return raise_ssl_error(ERR_get_error());
#else
  sig = ECDSA_do_sign(data, (unsigned int)data_len, key);
  EC_KEY_free(key);
  if ( (signature_len = i2d_ECDSA_SIG(sig, &signature)) < 0 )
    return raise_ssl_error(ERR_get_error());
#endif

  rc = unify_bytes_hex(Signature, signature_len, signature);
  OPENSSL_free(signature);

  return rc;
#else
  return ssl_missing("ECDSA");
#endif
}

static foreign_t
pl_ecdsa_verify(term_t Public, term_t Data, term_t Enc, term_t Signature)
{
#ifndef OPENSSL_NO_ECDSA
  unsigned char *data;
  size_t data_len;
  ECKEY *key;
  ECDSA_SIG *sig;
  unsigned char *signature;
  const unsigned char *copy;
  size_t signature_len;
  int rc;

  if ( !recover_ec(Public, &key) ||
       !get_enc_text(Data, Enc, &data_len, &data) ||
       !PL_get_nchars(Signature, &signature_len, (char **) &signature, REP_ISO_LATIN_1|CVT_LIST|CVT_EXCEPTION) )
    return FALSE;

  copy = signature;

  if ( !(sig = d2i_ECDSA_SIG(NULL, &copy, signature_len)) )
    return FALSE;

#ifdef USE_EVP_API
  EVP_PKEY_CTX *verify_ctx = EVP_PKEY_CTX_new(key, NULL);
  EVP_PKEY_verify_init(verify_ctx);
  rc = EVP_PKEY_verify(verify_ctx,
                       signature, (unsigned int)signature_len,
                       data, (unsigned int)data_len);
  EVP_PKEY_CTX_free(verify_ctx);
  EVP_PKEY_free(key);
#else
  rc = ECDSA_do_verify(data, data_len, sig, key);

  EC_KEY_free(key);
#endif
  ECDSA_SIG_free(sig);

  if (rc == 0 || rc == 1 )
    return rc;

  return raise_ssl_error(ERR_get_error());
#else
  return ssl_missing("ECDSA");
#endif
}



                 /*******************************
                 *       RSA ENCRYPT/DECRYPT    *
                 *******************************/


static foreign_t
pl_rsa_private_decrypt(term_t private_t, term_t cipher_t,
		       term_t plain_t, term_t options_t)
{ size_t cipher_length;
  unsigned char* cipher;
  unsigned char* plain;
#ifdef USE_EVP_API
  size_t outsize;
#else
  int outsize;
#endif
  RSAKEY* key;
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
#ifdef USE_EVP_API
  outsize = EVP_PKEY_get_size(key);
#else
  outsize = RSA_size(key);
#endif
  ssl_deb(1, "Output size is going to be %d", outsize);
  plain = PL_malloc(outsize);
  ssl_deb(1, "Allocated %d bytes for plaintext", outsize);
#ifdef USE_EVP_API
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key, NULL);
  if ( !ctx )
  { EVP_PKEY_free(key);
    PL_free(plain);
    return raise_ssl_error(ERR_get_error());
  }
  if ( EVP_PKEY_decrypt_init(ctx) <= 0 || EVP_PKEY_CTX_set_rsa_padding(ctx, padding) <= 0)
  { EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(key);
    PL_free(plain);
    return raise_ssl_error(ERR_get_error());
  }
  if ( EVP_PKEY_decrypt(ctx, plain, &outsize, cipher, cipher_length) <= 0)
  { ssl_deb(1, "Failure to decrypt!");
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(key);
    PL_free(plain);
    return raise_ssl_error(ERR_get_error());
  }
  EVP_PKEY_CTX_free(ctx);
#else
  if ((outsize = RSA_private_decrypt((int)cipher_length, cipher,
				     plain, key, padding)) <= 0)
  { ssl_deb(1, "Failure to decrypt!");
    RSA_free(key);
    PL_free(plain);
    return raise_ssl_error(ERR_get_error());
  }
#endif
  ssl_deb(1, "decrypted bytes: %d", outsize);
  ssl_deb(1, "Freeing RSA");
#ifdef USE_EVP_API
  EVP_PKEY_free(key);
#else
  RSA_free(key);
#endif
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
#ifdef USE_EVP_API
  size_t outsize;
#else
  int outsize;
#endif
  RSAKEY* key;
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
#ifdef USE_EVP_API
  outsize = EVP_PKEY_get_size(key);
#else
  outsize = RSA_size(key);
#endif
  ssl_deb(1, "Output size is going to be %d", outsize);
  plain = PL_malloc(outsize);
  ssl_deb(1, "Allocated %d bytes for plaintext", outsize);
#ifdef USE_EVP_API
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key, NULL);
  if ( !ctx )
  { EVP_PKEY_free(key);
    PL_free(plain);
    return raise_ssl_error(ERR_get_error());
  }
  // EVP_PKEY_decrypt is only for private-key decryption.
  // The equivalent to RSA_public_decrypt is actually EVP_PKEY_verify_recover
  if ( EVP_PKEY_verify_recover_init(ctx) <= 0 || EVP_PKEY_CTX_set_rsa_padding(ctx, padding) <= 0)
  { EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(key);
    PL_free(plain);
    return raise_ssl_error(ERR_get_error());
  }
  if (EVP_PKEY_verify_recover(ctx, plain, &outsize, cipher, cipher_length) <= 0)
  { ssl_deb(1, "Failure to decrypt!");
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(key);
    PL_free(plain);
    return raise_ssl_error(ERR_get_error());
  }
  EVP_PKEY_CTX_free(ctx);
#else
  if ((outsize = RSA_public_decrypt((int)cipher_length, cipher,
                                    plain, key, padding)) <= 0)
  { ssl_deb(1, "Failure to decrypt!");
    RSA_free(key);
    PL_free(plain);
    return raise_ssl_error(ERR_get_error());
  }
#endif
  ssl_deb(1, "decrypted bytes: %d", outsize);
  ssl_deb(1, "Freeing RSA");
#ifdef USE_EVP_API
  EVP_PKEY_free(key);
#else
  RSA_free(key);
#endif
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
#ifdef USE_EVP_API
  size_t outsize;
#else
  int outsize;
#endif
  RSAKEY* key;
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

#ifdef USE_EVP_API
  outsize = EVP_PKEY_get_size(key);
#else
  outsize = RSA_size(key);
#endif
  ssl_deb(1, "Output size is going to be %d\n", outsize);
  cipher = PL_malloc(outsize);
  ssl_deb(1, "Allocated %d bytes for ciphertext\n", outsize);
#ifdef USE_EVP_API
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key, NULL);
  if ( !ctx )
  { EVP_PKEY_free(key);
    PL_free(plain);
    return raise_ssl_error(ERR_get_error());
  }
  if ( EVP_PKEY_encrypt_init(ctx) <= 0 || EVP_PKEY_CTX_set_rsa_padding(ctx, padding) <= 0)
  { EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(key);
    PL_free(plain);
    return raise_ssl_error(ERR_get_error());
  }
  if ( EVP_PKEY_encrypt(ctx, cipher, &outsize, plain, plain_length) <= 0 )
  { ssl_deb(1, "Failure to encrypt!");
    EVP_PKEY_CTX_free(ctx);
    PL_free(cipher);
    EVP_PKEY_free(key);
    return raise_ssl_error(ERR_get_error());
  }
  EVP_PKEY_CTX_free(ctx);
#else
  if ( (outsize = RSA_public_encrypt((int)plain_length, plain,
				     cipher, key, padding)) <= 0)
  { ssl_deb(1, "Failure to encrypt!");
    PL_free(cipher);
    RSA_free(key);
    return raise_ssl_error(ERR_get_error());
  }
#endif
  ssl_deb(1, "encrypted bytes: %d\n", outsize);
  ssl_deb(1, "Freeing RSA");
#ifdef USE_EVP_API
  EVP_PKEY_free(key);
#else
  RSA_free(key);
#endif
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
#ifdef USE_EVP_API
  size_t outsize;
#else
  int outsize;
#endif
  RSAKEY* key;
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

#ifdef USE_EVP_API
  outsize = EVP_PKEY_get_size(key);
#else
  outsize = RSA_size(key);
#endif
  ssl_deb(1, "Output size is going to be %d", outsize);
  cipher = PL_malloc(outsize);
  ssl_deb(1, "Allocated %d bytes for ciphertext", outsize);
#ifdef USE_EVP_API
  memset(cipher, 0, outsize);
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key, NULL);
  if ( !ctx )
  { EVP_PKEY_free(key);
    PL_free(plain);
    return raise_ssl_error(ERR_get_error());
  }
  // EVP_PKEY_ENCRYPT is only for public encryption.
  if ( (EVP_PKEY_sign_init(ctx) <= 0) || (EVP_PKEY_CTX_set_rsa_padding(ctx, padding) <= 0))
  { EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(key);
    PL_free(plain);
    return raise_ssl_error(ERR_get_error());
  }
  if ( EVP_PKEY_sign(ctx, cipher, &outsize, plain, plain_length) <= 0 )
  { ssl_deb(1, "Failure to encrypt!");
    EVP_PKEY_CTX_free(ctx);
    PL_free(cipher);
    EVP_PKEY_free(key);
    return raise_ssl_error(ERR_get_error());
  }
#else
  if ((outsize = RSA_private_encrypt((int)plain_length, plain,
                                     cipher, key, padding)) <= 0)
  { ssl_deb(1, "Failure to encrypt!");
    PL_free(cipher);
    RSA_free(key);
    return raise_ssl_error(ERR_get_error());
  }
#endif
  ssl_deb(1, "encrypted bytes: %d", outsize);
  ssl_deb(1, "Freeing RSA");
#ifdef USE_EVP_API
  EVP_PKEY_free(key);
#else
  RSA_free(key);
#endif
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
  RSAKEY *key;
  unsigned char *signature;
#ifdef USE_EVP_API
  size_t signature_len;
#else
  unsigned int signature_len;
#endif
  int rc;
  int type;

  if ( !get_enc_text(Data, Enc, &data_len, &data) ||
       !recover_private_key(Private, &key) ||
       !get_digest_type(Type, &type) )
    return FALSE;

#ifdef USE_EVP_API
  signature_len = EVP_PKEY_get_size(key);
#else
  signature_len = RSA_size(key);
#endif
  signature = PL_malloc(signature_len);
#if defined USE_EVP_API
  OSSL_PARAM params[2];
  params[0] = OSSL_PARAM_construct_utf8_string("digest", (char *)OBJ_nid2ln(type), 0);
  params[1] = OSSL_PARAM_construct_end();
  EVP_PKEY_CTX *sign_ctx = EVP_PKEY_CTX_new(key, NULL);
  EVP_PKEY_sign_init_ex(sign_ctx, params);
  rc = EVP_PKEY_sign(sign_ctx,
		signature, &signature_len,
		data, (unsigned int)data_len);
  EVP_PKEY_CTX_free(sign_ctx);
#else
  rc = RSA_sign(type,
		data, (unsigned int)data_len,
		signature, &signature_len, key);
#endif
#ifdef USE_EVP_API
  EVP_PKEY_free(key);
#else
  RSA_free(key);
#endif
  if ( rc != 1 )
  { PL_free(signature);
    return raise_ssl_error(ERR_get_error());
  }
  rc = unify_bytes_hex(Signature, signature_len, signature);
  PL_free(signature);

  return rc;
}

static foreign_t
pl_rsa_verify(term_t Public, term_t Type, term_t Enc,
	    term_t Data, term_t Signature)
{ unsigned char *data;
  size_t data_len;
  RSAKEY *key;
  unsigned char *signature;
  size_t signature_len;
  int rc;
  int type;

  if ( !get_enc_text(Data, Enc, &data_len, &data) ||
       !recover_public_key(Public, &key) ||
       !get_digest_type(Type, &type) ||
       !PL_get_nchars(Signature, &signature_len, (char**)&signature, REP_ISO_LATIN_1|CVT_LIST|CVT_EXCEPTION) )
    return FALSE;
#if defined USE_EVP_API
  OSSL_PARAM params[2];
  params[0] = OSSL_PARAM_construct_utf8_string("digest", (char *)OBJ_nid2ln(type), 0);
  params[1] = OSSL_PARAM_construct_end();
  EVP_PKEY_CTX *verify_ctx = EVP_PKEY_CTX_new(key, NULL);
  EVP_PKEY_verify_init_ex(verify_ctx, params);
  rc = EVP_PKEY_verify(verify_ctx,
                       signature, (unsigned int)signature_len,
                       data, (unsigned int)data_len);
  EVP_PKEY_CTX_free(verify_ctx);
#else
  rc = RSA_verify(type,
                  data, (unsigned int)data_len,
                  signature, (unsigned int)signature_len, key);
#endif
#ifdef USE_EVP_API
  EVP_PKEY_free(key);
#else
  RSA_free(key);
#endif

  if ( rc == 0 || rc == 1 )
    return rc;

  return raise_ssl_error(ERR_get_error());
}



#ifndef HAVE_EVP_CIPHER_CTX_RESET
#define EVP_CIPHER_CTX_reset(C) EVP_CIPHER_CTX_init(C)
#endif

static foreign_t
pl_crypto_data_decrypt(term_t ciphertext_t, term_t algorithm_t,
                       term_t key_t, term_t iv_t,
                       term_t authtag_t,
                       term_t plaintext_t,
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
#ifdef EVP_CTRL_AEAD_SET_TAG
  char *authtag;
  size_t authlen;
#endif

  if ( !parse_options(options_t, EVP_MODE, &rep, &padding) )
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

  EVP_CIPHER_CTX_reset(ctx);
  EVP_DecryptInit_ex(ctx, cipher, NULL,
		     (const unsigned char*)key, (const unsigned char*)iv);

#ifdef EVP_CTRL_AEAD_SET_TAG
  if ( PL_get_nchars(authtag_t, &authlen, &authtag, CVT_LIST) &&
       ( authlen > 0 ) )
  { if ( !EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, authlen, authtag) )
    { EVP_CIPHER_CTX_free(ctx);
      return raise_ssl_error(ERR_get_error());
    }
  }
#endif

  EVP_CIPHER_CTX_set_padding(ctx, padding);
  plaintext = PL_malloc(cipher_length + EVP_CIPHER_block_size(cipher));
  if ( EVP_DecryptUpdate(ctx, (unsigned char*)plaintext, &plain_length,
			 (unsigned char*)ciphertext, cipher_length) == 1 )
  { int last_chunk = plain_length;
    int rc;
    rc = EVP_DecryptFinal_ex(ctx, (unsigned char*)(plaintext + plain_length),
                              &last_chunk);

    EVP_CIPHER_CTX_free(ctx);

    if ( !rc )
      return raise_ssl_error(ERR_get_error());

    ERR_print_errors_fp(stderr);
    rc &= PL_unify_chars(plaintext_t, rep | PL_STRING, plain_length + last_chunk,
                         plaintext);
    PL_free(plaintext);
    return rc;
  }

  PL_free(plaintext);
  EVP_CIPHER_CTX_free(ctx);

  return raise_ssl_error(ERR_get_error());
}

static foreign_t
pl_crypto_data_encrypt(term_t plaintext_t, term_t algorithm_t,
                       term_t key_t, term_t iv_t,
                       term_t authlen_t, term_t authtag_t,
                       term_t ciphertext_t,
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
  int padding = 1;
  int authlen;
  const int MAX_AUTHLEN = 256;
#ifdef EVP_CTRL_AEAD_SET_TAG
  char authtag[MAX_AUTHLEN];
#endif

  if ( !parse_options(options_t, EVP_MODE, &rep, &padding) ||
       !PL_get_integer_ex(authlen_t, &authlen) ||
       ( authlen > MAX_AUTHLEN ) )
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

  EVP_CIPHER_CTX_reset(ctx);
  EVP_EncryptInit_ex(ctx, cipher, NULL,
		     (const unsigned char*)key, (const unsigned char*)iv);
  EVP_CIPHER_CTX_set_padding(ctx, padding);
  ciphertext = PL_malloc(plain_length + EVP_CIPHER_block_size(cipher));
  if ( EVP_EncryptUpdate(ctx, (unsigned char*)ciphertext, &cipher_length,
                         (unsigned char*)plaintext, plain_length) == 1 )
  { int last_chunk;
    int rc;

    if ( !EVP_EncryptFinal_ex(ctx, (unsigned char*)(ciphertext + cipher_length),
                              &last_chunk) )
      return raise_ssl_error(ERR_get_error());

#ifdef EVP_CTRL_AEAD_SET_TAG
    if ( authlen >= 0 )
    { if ( !EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, authlen, authtag) )
        return raise_ssl_error(ERR_get_error());

      if ( !PL_unify_list_ncodes(authtag_t, authlen, authtag) )
        return FALSE;
    }
#endif

    EVP_CIPHER_CTX_free(ctx);
    rc = PL_unify_chars(ciphertext_t,  PL_STRING|REP_ISO_LATIN_1,
			cipher_length + last_chunk, ciphertext);
    PL_free(ciphertext);
    return rc;
  }

  PL_free(ciphertext);
  EVP_CIPHER_CTX_free(ctx);

  return raise_ssl_error(ERR_get_error());
}


          /*******************************************
          *      MODULAR MULTIPLICATIVE INVERSE      *
          ********************************************/

static foreign_t
pl_crypto_modular_inverse(term_t tx, term_t tm, term_t tout)
{ BIGNUM *x = NULL, *m = NULL, *r = NULL;
  BN_CTX *ctx = NULL;
  char *hex = NULL;
  int rc, ssl_err = FALSE;

  if ( get_bn_arg(1, tx, &x) &&
       get_bn_arg(1, tm, &m)  &&
       ( ctx = BN_CTX_new() ) &&
       ( r = BN_mod_inverse(NULL, x, m, ctx) ) &&
       ( hex = BN_bn2hex(r) ) )
  { rc = PL_unify_chars(tout, PL_STRING|REP_ISO_LATIN_1, strlen(hex), hex);
  } else
  { ssl_err = TRUE;
  }

  OPENSSL_free(hex);
  BN_free(x);
  BN_free(m);
  BN_free(r);
  BN_CTX_free(ctx);

  if ( ssl_err )
  { return raise_ssl_error(ERR_get_error());
  }

  return rc;
}

                 /*******************
                 *      PRIMES      *
                 ********************/

static foreign_t
pl_crypto_generate_prime(term_t tbits, term_t tprime, term_t tsafe,
                         term_t toptions)
{ BIGNUM *prime = NULL;
  int bits, safe;
  char *hex = NULL;
  int rc, ssl_err = FALSE;

  if ( !PL_get_integer_ex(tbits, &bits) )
    return FALSE;

  if ( !PL_get_bool_ex(tsafe, &safe) )
    return FALSE;

  if ( ( prime = BN_new() ) &&
       ( BN_generate_prime_ex(prime, bits, safe, NULL, NULL, NULL ) ) &&
       ( hex = BN_bn2hex(prime) ) )
  { rc = PL_unify_chars(tprime, PL_STRING|REP_ISO_LATIN_1, strlen(hex), hex);
  } else
  { ssl_err = TRUE;
  }

  OPENSSL_free(hex);
  BN_free(prime);

  if ( ssl_err )
  { return raise_ssl_error(ERR_get_error());
  }

  return rc;
}

static foreign_t
pl_crypto_is_prime(term_t tprime, term_t tnchecks)
{ BIGNUM *prime = NULL;
  BN_CTX *ctx = NULL;
  int nchecks;
  int ret = -1;

  if ( !PL_get_integer_ex(tnchecks, &nchecks) )
    return FALSE;

  nchecks = ( nchecks < 0 ) ? BN_prime_checks : nchecks;

  if ( ( ctx = BN_CTX_new() ) &&
       get_bn_arg(1, tprime, &prime) )
  {
#ifdef HAVE_BN_CHECK_PRIME
  // Note that we ignore nchecks here. BN_check_prime is listed as the replacement for BN_is_prime_ex
  // but I could not find any information *anywhere* about how to pass in nchecks. Looking at the code in openssl
  // it appears that they take some steps to correctly determine the value of nchecks. See
  //     hhttps://github.com/openssl/openssl/blob/26b3e44a661899f0d0cb709482170cc411a94233/crypto/bn/bn_prime.c#L247
  ret = BN_check_prime(prime, ctx, NULL);
#else
  ret = BN_is_prime_ex(prime, nchecks, ctx, NULL);
#endif
  }

  BN_free(prime);
  BN_CTX_free(ctx);

  if ( ret == -1 )
  { return raise_ssl_error(ERR_get_error());
  }

  return ret;
}


                /*******************************
                *        ELLIPTIC CURVES       *
                *******************************/

#ifndef OPENSSL_NO_EC

#define CURVE_MAGIC (~ 0x51431485L)

typedef struct curve
{ int             magic;
  atom_t          atom;

  EC_GROUP       *group;
  BN_CTX         *ctx;
} PL_CRYPTO_CURVE;

static int
free_crypto_curve(PL_CRYPTO_CURVE *c)
{ BN_CTX_free(c->ctx);
  EC_GROUP_free(c->group);
  free(c);
  return TRUE;
}

static int
release_curve(atom_t atom)
{ size_t size;
  PL_CRYPTO_CURVE **cp = PL_blob_data(atom, &size, NULL);
  PL_CRYPTO_CURVE *c = *cp;
  ssl_deb(4, "Releasing PL_CRYPTO_CURVE %p\n", c);
  free_crypto_curve(c);
  return TRUE;
}

static int
compare_curve(atom_t a, atom_t b)
{ PL_CRYPTO_CURVE**cp1 = PL_blob_data(a, NULL, NULL);
  PL_CRYPTO_CURVE**cp2 = PL_blob_data(b, NULL, NULL);
  PL_CRYPTO_CURVE *c1 = *cp1;
  PL_CRYPTO_CURVE *c2 = *cp2;

  return ( c1 > c2 ?  1 :
           c1 < c2 ? -1 : 0
         );
}

static int
write_curve(IOSTREAM *s, atom_t symbol, int flags)
{ PL_CRYPTO_CURVE **cp = PL_blob_data(symbol, NULL, NULL);
  PL_CRYPTO_CURVE *c = *cp;
  const char *name = OBJ_nid2sn(EC_GROUP_get_curve_name(c->group));

  Sfprintf(s, "<crypto_curve>(%s, %p)", name, c);

  return TRUE;
}

static void
acquire_curve(atom_t atom)
{ size_t size;
  PL_CRYPTO_CURVE **cp = PL_blob_data(atom, &size, NULL);
  PL_CRYPTO_CURVE *c = *cp;
  c->atom = atom;
}

static PL_blob_t crypto_curve_type =
{ PL_BLOB_MAGIC,
  0,
  "crypto_curve",
  release_curve,
  compare_curve,
  write_curve,
  acquire_curve
};

static int
unify_curve(term_t tcurve, PL_CRYPTO_CURVE *curve)
{ if ( PL_unify_blob(tcurve, &curve, sizeof(curve), &crypto_curve_type) )
    return TRUE;

  free_crypto_curve(curve);

  if ( !PL_exception(0) )
    return PL_uninstantiation_error(tcurve);

  return FALSE;
}

static int
get_curve(term_t tcurve, PL_CRYPTO_CURVE **curve)
{ PL_blob_t *type;
  void *data;

  if ( PL_get_blob(tcurve, &data, NULL, &type) &&
       type == &crypto_curve_type )
  { PL_CRYPTO_CURVE *c = *(PL_CRYPTO_CURVE**)data;

    assert(c->magic == CURVE_MAGIC);
    *curve = c;

    return TRUE;
  }

  return PL_type_error("crypto_curve", tcurve);
}

#endif

static foreign_t
pl_crypto_name_curve(term_t tname, term_t tcurve)
{
#ifndef OPENSSL_NO_EC
  PL_CRYPTO_CURVE *curve = NULL;
  char *name;

  if ( !PL_get_chars(tname, &name, CVT_ATOM|CVT_STRING|CVT_EXCEPTION) )
    return FALSE;

  if ( !(curve = malloc(sizeof(*curve))) )
    return PL_resource_error("memory");

  curve->magic    = CURVE_MAGIC;
  curve->ctx      = NULL;
  curve->group    = NULL;

  if ( ( curve->group = EC_GROUP_new_by_curve_name(OBJ_sn2nid(name)) ) &&
       ( curve->ctx   = BN_CTX_new() ) )
  { return unify_curve(tcurve, curve);
  } else
  { BN_CTX_free(curve->ctx);
    EC_GROUP_free(curve->group);
    free(curve);

    return raise_ssl_error(ERR_get_error());
  }
#else
  return ssl_missing("EC");
#endif
}

static foreign_t
pl_crypto_curve_order(term_t tcurve, term_t torder)
{
#ifndef OPENSSL_NO_EC
  PL_CRYPTO_CURVE *curve = NULL;
  BIGNUM *order = NULL;
  char *hex = NULL;
  int rc = FALSE, ssl_err = FALSE;

  if ( !get_curve(tcurve, &curve) )
    return FALSE;

  if ( ( order = BN_new() ) &&
       EC_GROUP_get_order(curve->group, order, curve->ctx) &&
       ( hex = BN_bn2hex(order) ) )
  { rc = PL_unify_chars(torder, PL_STRING|REP_ISO_LATIN_1, strlen(hex), hex);
  } else
  { ssl_err = TRUE;
  }

  OPENSSL_free(hex);
  BN_free(order);

  if ( ssl_err )
  { return raise_ssl_error(ERR_get_error());
  }

  return rc;
#else
  return ssl_missing("EC");
#endif
}


static foreign_t
pl_crypto_curve_generator(term_t tcurve, term_t tx, term_t ty)
{
#ifndef OPENSSL_NO_EC
  PL_CRYPTO_CURVE *curve = NULL;
  BIGNUM *x = NULL, *y = NULL;
  char *xhex = NULL, *yhex = NULL;
  int rc = FALSE, ssl_err = FALSE;

  if ( !get_curve(tcurve, &curve) )
    return FALSE;

  if ( ( x = BN_new() ) &&
       ( y = BN_new() ) &&
       EC_POINT_get_affine_coordinates(curve->group,
                                       EC_GROUP_get0_generator(curve->group),
                                       x, y, curve->ctx) &&
       ( xhex = BN_bn2hex(x) ) &&
       ( yhex = BN_bn2hex(y) ) )
  { rc = PL_unify_chars(tx, PL_STRING|REP_ISO_LATIN_1, strlen(xhex), xhex)
      && PL_unify_chars(ty, PL_STRING|REP_ISO_LATIN_1, strlen(yhex), yhex);
  } else
  { ssl_err = TRUE;
  }

  OPENSSL_free(xhex); OPENSSL_free(yhex);
  BN_free(x); BN_free(y);

  if ( ssl_err )
  { return raise_ssl_error(ERR_get_error());
  }

  return rc;
#else
  return ssl_missing("EC");
#endif
}



static foreign_t
pl_crypto_curve_scalar_mult(term_t tcurve, term_t ts,
                           term_t tx, term_t ty, term_t ta, term_t tb)
{
#ifndef OPENSSL_NO_EC
  BIGNUM *s = NULL, *x = NULL, *y = NULL, *a = NULL, *b = NULL;
  EC_POINT *r = NULL, *q = NULL;
  char *ahex = NULL, *bhex = NULL;
  PL_CRYPTO_CURVE *curve = NULL;
  int rc, ssl_err = FALSE;

  if ( !get_curve(tcurve, &curve) )
    return FALSE;

  if ( get_bn_arg(1, ts, &s) &&
       get_bn_arg(1, tx, &x) &&
       get_bn_arg(1, ty, &y)  &&
       ( q = EC_POINT_new(curve->group) ) &&
       EC_POINT_set_affine_coordinates(curve->group, q, x, y, curve->ctx) &&
       ( r = EC_POINT_new(curve->group) ) &&
       EC_POINT_mul(curve->group, r, NULL, q, s, curve->ctx) &&
       ( a = BN_new() ) &&
       ( b = BN_new() ) &&
       EC_POINT_get_affine_coordinates(curve->group, r, a, b, curve->ctx) &&
       ( ahex = BN_bn2hex(a) ) &&
       ( bhex = BN_bn2hex(b) ) )
  { rc = PL_unify_chars(ta, PL_STRING|REP_ISO_LATIN_1, strlen(ahex), ahex)
      && PL_unify_chars(tb, PL_STRING|REP_ISO_LATIN_1, strlen(bhex), bhex);
  } else
  { rc = FALSE;					/* silence compiler */
    ssl_err = TRUE;
  }

  OPENSSL_free(ahex); OPENSSL_free(bhex);
  BN_free(a); BN_free(b);
  BN_free(s); BN_free(x); BN_free(y);
  EC_POINT_free(q); EC_POINT_free(r);

  if ( ssl_err )
    return raise_ssl_error(ERR_get_error());

  return rc;
#else
  return ssl_missing("EC");
#endif
}


                /*******************************
                *            THREADING         *
                *******************************/

/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
OpenSSL is only thread-safe as of version 1.1.0.

For earlier versions, we need to install the hooks below. This code is
based on mttest.c distributed with the OpenSSL library.
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */

#ifdef _REENTRANT

#include <pthread.h>

#if OPENSSL_VERSION_NUMBER < 0x10100000L
static pthread_mutex_t *lock_cs;
static long *lock_count;
static void (*old_locking_callback)(int, int, const char*, int) = NULL;
#ifdef HAVE_CRYPTO_THREADID_GET_CALLBACK
static void (*old_id_callback)(CRYPTO_THREADID*) = NULL;
#else
static unsigned long (*old_id_callback)(void) = NULL;
#endif

static void
crypto_thread_exit(void* ignored)
{
#ifdef HAVE_ERR_REMOVE_THREAD_STATE
  ERR_remove_thread_state(0);
#elif defined(HAVE_ERR_REMOVE_STATE)
  ERR_remove_state(0);
#else
#error "Do not know how to remove SSL error state"
#endif
}

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
#endif /* OpenSSL 1.1.0 */

#if !defined(HAVE_CRYPTO_THREADID_GET_CALLBACK) && !defined(CRYPTO_THREADID_get_callback)
#define CRYPTO_THREADID_get_callback CRYPTO_get_id_callback
#define CRYPTO_THREADID_set_callback CRYPTO_set_id_callback
#endif

static int
crypto_lib_init(void)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
  OpenSSL_add_all_algorithms();
  ERR_load_crypto_strings();

  if ( (old_id_callback=CRYPTO_THREADID_get_callback()) == 0 )
  { int i;

    lock_cs = OPENSSL_malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
    lock_count = OPENSSL_malloc(CRYPTO_num_locks() * sizeof(long));

    for (i=0; i<CRYPTO_num_locks(); i++)
    { lock_count[i]=0;
      pthread_mutex_init(&(lock_cs[i]), NULL);
    }

    old_locking_callback = CRYPTO_get_locking_callback();
#ifndef __WINDOWS__			/* JW: why not for Windows? */
    CRYPTO_THREADID_set_callback(pthreads_thread_id);
#endif
    CRYPTO_set_locking_callback(pthreads_locking_callback);

    PL_thread_at_exit(crypto_thread_exit, NULL, TRUE);
  }
#endif /*OPENSSL_VERSION_NUMBER < 0x10100000L*/

  return TRUE;
}

#else /*_REENTRANT*/

static int
crypto_lib_init(void)
{ return FALSE;
}

#endif /*_REENTRANT*/


static int
crypto_lib_exit(void)
/*
 * One-time library exit calls
 */
{
/*
 * If the module is being unloaded, we should remove callbacks pointing to
 * our address space
 */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
#ifdef _REENTRANT
#ifndef __WINDOWS__
    CRYPTO_THREADID_set_callback(old_id_callback);
#endif
    CRYPTO_set_locking_callback(old_locking_callback);
#endif
#endif
    return 0;
}

static foreign_t
crypto_set_debug(term_t level)
{ int l;

  if ( !PL_get_integer_ex(level, &l) )
    return FALSE;

  ssl_set_debug(l);

  return TRUE;
}

		 /*******************************
		 *	     INSTALL		*
		 *******************************/

#define MKATOM(n) ATOM_ ## n = PL_new_atom(#n);

install_t
install_crypto4pl(void)
{
  ATOM_minus                = PL_new_atom("-");
  MKATOM(sslv23);
  MKATOM(text);
  MKATOM(octet);
  MKATOM(utf8);

  MKATOM(sha1);
  MKATOM(sha224);
  MKATOM(sha256);
  MKATOM(sha384);
  MKATOM(sha512);
  MKATOM(md5);
  MKATOM(blake2b512);
  MKATOM(blake2s256);
  MKATOM(sha3_224);
  MKATOM(sha3_256);
  MKATOM(sha3_384);
  MKATOM(sha3_512);
  MKATOM(ripemd160);

  MKATOM(pkcs1);
  MKATOM(pkcs1_oaep);
  MKATOM(none);
  MKATOM(block);
  MKATOM(encoding);
  MKATOM(algorithm);
  MKATOM(hmac);
  MKATOM(close_parent);
  MKATOM(padding);

  FUNCTOR_public_key1       = PL_new_functor(PL_new_atom("public_key"), 1);
  FUNCTOR_private_key1      = PL_new_functor(PL_new_atom("private_key"), 1);

  PL_register_foreign("crypto_n_random_bytes", 2, pl_crypto_n_random_bytes, 0);

  PL_register_foreign("_crypto_context_new", 2,
                      pl_crypto_hash_context_new, 0);
  PL_register_foreign("_crypto_update_hash_context", 2,
                      pl_crypto_update_hash_context, 0);
  PL_register_foreign("_crypto_hash_context_copy", 2,
                      pl_crypto_hash_context_copy, 0);
  PL_register_foreign("_crypto_hash_context_hash", 2,
                      pl_crypto_hash_context_hash, 0);

  PL_register_foreign("_crypto_open_hash_stream", 3,
                      pl_crypto_open_hash_stream, 0);
  PL_register_foreign("_crypto_stream_hash_context", 2,
                      pl_crypto_stream_hash_context, 0);

  PL_register_foreign("_crypto_password_hash_pbkdf2", 4, pl_crypto_password_hash_pbkdf2, 0);
  PL_register_foreign("_crypto_password_hash_bcrypt", 3, pl_crypto_password_hash_bcrypt, 0);
  PL_register_foreign("_crypto_data_hkdf", 7, pl_crypto_data_hkdf, 0);

  PL_register_foreign("_crypto_ecdsa_sign", 4, pl_ecdsa_sign, 0);
  PL_register_foreign("_crypto_ecdsa_verify", 4, pl_ecdsa_verify, 0);

  PL_register_foreign("rsa_private_decrypt", 4, pl_rsa_private_decrypt, 0);
  PL_register_foreign("rsa_private_encrypt", 4, pl_rsa_private_encrypt, 0);
  PL_register_foreign("rsa_public_decrypt", 4, pl_rsa_public_decrypt, 0);
  PL_register_foreign("rsa_public_encrypt", 4, pl_rsa_public_encrypt, 0);
  PL_register_foreign("rsa_sign", 5, pl_rsa_sign, 0);
  PL_register_foreign("rsa_verify", 5, pl_rsa_verify, 0);
  PL_register_foreign("_crypto_data_decrypt", 7, pl_crypto_data_decrypt, 0);
  PL_register_foreign("_crypto_data_encrypt", 8, pl_crypto_data_encrypt, 0);

  PL_register_foreign("_crypto_modular_inverse", 3,
                      pl_crypto_modular_inverse, 0);
  PL_register_foreign("_crypto_generate_prime", 4,
                      pl_crypto_generate_prime, 0);
  PL_register_foreign("_crypto_is_prime", 2, pl_crypto_is_prime, 0);

  PL_register_foreign("crypto_name_curve", 2, pl_crypto_name_curve, 0);
  PL_register_foreign("_crypto_curve_order", 2, pl_crypto_curve_order, 0);
  PL_register_foreign("_crypto_curve_generator", 3,
                      pl_crypto_curve_generator, 0);
  PL_register_foreign("_crypto_curve_scalar_mult", 6,
                      pl_crypto_curve_scalar_mult, 0);
  PL_register_foreign("crypto_set_debug", 1,
		      crypto_set_debug, 0);

  /*
   * Initialize crypto library
   */
  (void) crypto_lib_init();

}

install_t
uninstall_crypto4pl(void)
{ crypto_lib_exit();
}
