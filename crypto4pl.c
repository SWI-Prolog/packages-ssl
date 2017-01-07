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
#include <SWI-Stream.h>
#include <SWI-Prolog.h>
#include <assert.h>
#include <string.h>
#include "cryptolib.h"

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

static atom_t ATOM_pkcs;
static atom_t ATOM_pkcs_oaep;
static atom_t ATOM_none;
static atom_t ATOM_block;
static atom_t ATOM_algorithm;
static atom_t ATOM_close_parent;
static atom_t ATOM_encoding;
static atom_t ATOM_padding;

static functor_t FUNCTOR_public_key1;
static functor_t FUNCTOR_private_key1;

typedef enum
{ RSA_MODE, EVP_MODE
} crypt_mode_t;


                 /***************************
                 *         HASHING          *
                 ****************************/


#define CONTEXT_MAGIC (~ 0x53481284L)

typedef struct context
{ int             magic;
  atom_t          atom;
  IOENC           encoding;
  const EVP_MD   *algorithm;

  IOSTREAM       *parent_stream;      /* Original stream */
  IOSTREAM       *hash_stream;
  IOENC           parent_encoding;
  int             close_parent;

  EVP_MD_CTX     *ctx;
} PL_CRYPTO_CONTEXT;

static int
free_crypto_context(PL_CRYPTO_CONTEXT *c)
{
  EVP_MD_CTX_free(c->ctx);
  free(c);
  return TRUE;
}

static int
release_context(atom_t atom)
{ PL_CRYPTO_CONTEXT *c;
  size_t size;

  c = PL_blob_data(atom, &size, NULL);
  ssl_deb(4, "Releasing PL_CRYPTO_CONTEXT %p\n", c);
  free_crypto_context(c);
  return TRUE;
}

static int
compare_context(atom_t a, atom_t b)
{ PL_CRYPTO_CONTEXT* *c1 = PL_blob_data(a, NULL, NULL);
  PL_CRYPTO_CONTEXT* *c2 = PL_blob_data(b, NULL, NULL);

  return ( c1 > c2 ?  1 :
           c1 < c2 ? -1 : 0
         );
}

static int
write_context(IOSTREAM *s, atom_t symbol, int flags)
{ PL_CRYPTO_CONTEXT *c = PL_blob_data(symbol, NULL, NULL);

  Sfprintf(s, "<crypto_context>(%p)", c);

  return TRUE;
}

static void
acquire_context(atom_t atom)
{ ssl_deb(4, "Acquire on atom %d\n", atom);
}

static PL_blob_t crypto_context_type =
{ PL_BLOB_MAGIC,
  PL_BLOB_NOCOPY,
  "crypto_context",
  release_context,
  compare_context,
  write_context,
  acquire_context
};

static int
put_context(term_t tcontext, PL_CRYPTO_CONTEXT *context)
{ return PL_unify_atom(tcontext, context->atom);
}

static int
register_context(term_t tcontext, PL_CRYPTO_CONTEXT *context)
{ term_t blob = PL_new_term_ref();
  int rc;

  PL_put_blob(blob, context, sizeof(void*), &crypto_context_type);
  rc = PL_get_atom(blob, &context->atom);
  assert(rc);
  ssl_deb(4, "Atom created: %d\n", context->atom);
  return put_context(tcontext, context);
}

static int
get_context(term_t tcontext, PL_CRYPTO_CONTEXT **context)
{ PL_blob_t *type;
  void *data;

  if ( PL_get_blob(tcontext, &data, NULL, &type) &&
       type == &crypto_context_type )
  { PL_CRYPTO_CONTEXT *c = data;

    assert(c->magic == CONTEXT_MAGIC);
    *context = c;

    return TRUE;
  }

  return PL_type_error("crypto_context", tcontext);
}



static int
hash_options(term_t options, PL_CRYPTO_CONTEXT *result)
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
        if ( a_algorithm == ATOM_sha1  )
        { result->algorithm = EVP_sha1();
        } else if ( a_algorithm == ATOM_sha224 )
        { result->algorithm = EVP_sha224();
        } else if ( a_algorithm == ATOM_sha256 )
        { result->algorithm = EVP_sha256();
        } else if ( a_algorithm == ATOM_sha384 )
        { result->algorithm = EVP_sha384();
        } else if ( a_algorithm == ATOM_sha512 )
        { result->algorithm = EVP_sha512();
        } else if ( a_algorithm == ATOM_md5 )
        { result->algorithm = EVP_md5();
#if defined(HAVE_EVP_BLAKE2B512) && defined(HAVE_EVP_BLAKE2S256)
        } else if ( a_algorithm == ATOM_blake2b512 )
        {  result->algorithm = EVP_blake2b512();
        } else if ( a_algorithm == ATOM_blake2s256 )
        { result->algorithm = EVP_blake2s256();
#endif
        } else
          return PL_domain_error("algorithm", a);
      } else if ( aname == ATOM_close_parent )
      { if ( !PL_get_bool_ex(a, &result->close_parent) )
          return FALSE;
      } else if ( aname == ATOM_encoding )
      { atom_t a_enc;

        if ( !PL_get_atom_ex(a, &a_enc) )
          return FALSE;
        if ( a_enc == ATOM_utf8 )
          result->encoding = REP_UTF8;
        else if ( a_enc == ATOM_octet )
          result->encoding = REP_ISO_LATIN_1;
        else
          return PL_domain_error("encoding", a);
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
pl_crypto_context_new(term_t tcontext, term_t options)
{
  PL_CRYPTO_CONTEXT *context = NULL;

  context = malloc(sizeof(*context));

  if ( !context )
    return FALSE;

  context->magic = CONTEXT_MAGIC;
  context->ctx = EVP_MD_CTX_new();

  context->parent_stream = NULL;
  context->hash_stream   = NULL;

  if ( !hash_options(options, context) )
    return FALSE;

  if ( !EVP_DigestInit_ex(context->ctx, context->algorithm, NULL) )
  { EVP_MD_CTX_free(context->ctx);
    return FALSE;
  }
  return register_context(tcontext, context);
}

static foreign_t
pl_crypto_context_copy(term_t tin, term_t tout)
{
  PL_CRYPTO_CONTEXT *in, *out;

  if ( !get_context(tin, &in) )
    return FALSE;

  out = malloc(sizeof(*out));

  if ( !out )
    return FALSE;

  out->magic = CONTEXT_MAGIC;
  out->ctx = EVP_MD_CTX_new();

  out->encoding = in->encoding;
  out->algorithm = in->algorithm;

  if ( !EVP_DigestInit_ex(out->ctx, out->algorithm, NULL) )
  { EVP_MD_CTX_free(out->ctx);
    return FALSE;
  }

  return register_context(tout, out) && EVP_MD_CTX_copy_ex(out->ctx, in->ctx);
}


static foreign_t
pl_crypto_update_context(term_t from, term_t tcontext)
{
  PL_CRYPTO_CONTEXT *context = NULL;
  size_t datalen;
  char *data;

  if ( !get_context(tcontext, &context) )
    return FALSE;

  if ( !PL_get_nchars(from, &datalen, &data,
                      CVT_ATOM|CVT_STRING|CVT_LIST|CVT_EXCEPTION|context->encoding) )
    return FALSE;


  return EVP_DigestUpdate(context->ctx, data, datalen);
}

static foreign_t
pl_crypto_context_hash(term_t tcontext, term_t hash)
{
  PL_CRYPTO_CONTEXT *context = NULL;
  unsigned char digest[EVP_MAX_MD_SIZE];
  unsigned int len;

  if ( !get_context(tcontext, &context) )
    return FALSE;

  EVP_DigestFinal_ex(context->ctx, digest, &len);
  return PL_unify_list_ncodes(hash, len, (char *) digest);
}


                 /***************************
                 *     Hashes on streams    *
                 ****************************/

static void
hash_append(PL_CRYPTO_CONTEXT *context, void *data, size_t size)
{
  EVP_DigestUpdate(context->ctx, data, size);
}


static ssize_t                          /* range-limited read */
hash_read(void *handle, char *buf, size_t size)
{ PL_CRYPTO_CONTEXT *ctx = handle;
  ssize_t rd;

  if ( (rd = Sfread(buf, sizeof(char), size, ctx->parent_stream)) >= 0 )
  { hash_append(ctx, buf, rd);

    return rd;
  }

  return rd;
}


static ssize_t
hash_write(void *handle, char *buf, size_t size)
{ PL_CRYPTO_CONTEXT *ctx = handle;
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
{ PL_CRYPTO_CONTEXT *ctx = handle;

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
  PL_CRYPTO_CONTEXT *ctx = handle;

  ctx->parent_stream->encoding = ctx->parent_encoding;
  if ( ctx->parent_stream->upstream )
    Sset_filter(ctx->parent_stream, NULL);

  if ( ctx->close_parent )
    rc = Sclose(ctx->parent_stream);

  free_crypto_context(ctx);

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
{ PL_CRYPTO_CONTEXT *context;
  IOSTREAM *s, *s2;

  if ( !get_context(tcontext, &context) )
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
pl_crypto_stream_context(term_t stream, term_t tcontext)
{ IOSTREAM *s;
  int rc;

  if ( PL_get_stream_handle(stream, &s) )
  { PL_CRYPTO_CONTEXT *ctx = s->handle;
    rc = register_context(tcontext, ctx);
    PL_release_stream(s);
    return rc;
  }

  return FALSE;
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



#ifndef HAVE_EVP_CIPHER_CTX_RESET
#define EVP_CIPHER_CTX_reset(C) EVP_CIPHER_CTX_init(C)
#endif

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

  EVP_CIPHER_CTX_reset(ctx);
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

  EVP_CIPHER_CTX_reset(ctx);
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

int
crypto_lib_init(void)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
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

int
crypto_lib_init(void)
{ return FALSE;
}

#endif /*_REENTRANT*/


int
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

  MKATOM(pkcs);
  MKATOM(pkcs_oaep);
  MKATOM(none);
  MKATOM(block);
  MKATOM(encoding);
  MKATOM(algorithm);
  MKATOM(close_parent);
  MKATOM(padding);

  FUNCTOR_public_key1       = PL_new_functor(PL_new_atom("public_key"), 1);
  FUNCTOR_private_key1      = PL_new_functor(PL_new_atom("private_key"), 1);

  PL_register_foreign("crypto_context_new", 2, pl_crypto_context_new, 0);
  PL_register_foreign("_crypto_update_context", 2, pl_crypto_update_context, 0);
  PL_register_foreign("_crypto_context_copy", 2, pl_crypto_context_copy, 0);
  PL_register_foreign("_crypto_context_hash", 2, pl_crypto_context_hash, 0);
  PL_register_foreign("_crypto_open_hash_stream", 3,
                      pl_crypto_open_hash_stream, 0);
  PL_register_foreign("_crypto_stream_context", 2, pl_crypto_stream_context, 0);

  PL_register_foreign("rsa_private_decrypt", 4, pl_rsa_private_decrypt, 0);
  PL_register_foreign("rsa_private_encrypt", 4, pl_rsa_private_encrypt, 0);
  PL_register_foreign("rsa_public_decrypt", 4, pl_rsa_public_decrypt, 0);
  PL_register_foreign("rsa_public_encrypt", 4, pl_rsa_public_encrypt, 0);
  PL_register_foreign("rsa_sign", 5, pl_rsa_sign, 0);
  PL_register_foreign("rsa_verify", 5, pl_rsa_verify, 0);
  PL_register_foreign("evp_decrypt", 6, pl_evp_decrypt, 0);
  PL_register_foreign("evp_encrypt", 6, pl_evp_encrypt, 0);

  /*
   * Initialize crypto library
   */
  (void) crypto_lib_init();

}

install_t
uninstall_crypto4pl(void)
{ crypto_lib_exit();
}
