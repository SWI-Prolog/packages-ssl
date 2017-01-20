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

:- module(crypto,
          [ crypto_data_hash/3,         % +Data, -Hash, +Options
            crypto_file_hash/3,         % +File, -Hash, +Options
            crypto_context_new/2,       % -Context, +Options
            crypto_data_context/3,      % +Data, +C0, -C
            crypto_context_hash/2,      % +Context, -Hash
            crypto_open_hash_stream/3,  % +InStream, -HashStream, +Options
            crypto_stream_hash/2,       % +HashStream, -Hash
            ecdsa_sign/4,               % +Key, +Data, -Signature, +Options
            ecdsa_verify/4,             % +Key, +Data, +Signature, +Options
            evp_decrypt/6,              % +CipherText, +Algorithm, +Key, +IV, -PlainText, +Options
            evp_encrypt/6,              % +PlainText, +Algorithm, +Key, +IV, -CipherText, +Options
            rsa_private_decrypt/4,      % +Key, +Ciphertext, -Plaintext, +Enc
            rsa_private_encrypt/4,      % +Key, +Plaintext, -Ciphertext, +Enc
            rsa_public_decrypt/4,       % +Key, +Ciphertext, -Plaintext, +Enc
            rsa_public_encrypt/4,       % +Key, +Plaintext, -Ciphertext, +Enc
            rsa_sign/4,                 % +Key, +Data, -Signature, +Options
            rsa_verify/4                % +Key, +Data, +Signature, +Options
          ]).
:- use_module(library(option)).

:- use_foreign_library(foreign(crypto4pl)).


/** <module> Cryptography and authentication library

This library provides bindings  to  functionality   of  OpenSSL  that is
related to cryptography and authentication,   not  necessarily involving
connections, sockets or streams.

The  hash functionality  of this  library subsumes  and extends  that of
`library(sha)`, `library(hash_stream)` and `library(md5)` by providing a
unified interface to all available digest algorithms.

The underlying  OpenSSL library  (`libcrypto`) is dynamically  loaded if
_either_ `library(crypto)`  or `library(ssl)` are loaded.  Therefore, if
your application uses `library(ssl)`,  you can use `library(crypto)` for
hashing without increasing the memory  footprint of your application. In
other cases, the specialised hashing  libraries are more lightweight but
less general alternatives to `library(crypto)`.

@author Matt Lilley
@author [Markus Triska](https://www.metalevel.at)
*/

%%  crypto_data_hash(+Data, -Hash, +Options) is det
%
%   Hash is the hash of Data. The conversion is controlled
%   by Options:
%
%    * algorithm(+Algorithm)
%    One of =md5=, =sha1=, =sha224=, =sha256= (default), =sha384=,
%    =sha512=, =blake2s256= or =blake2b512=. The =BLAKE= digest
%    algorithms require OpenSSL 1.1.0 or greater.
%    * encoding(+Encoding)
%    If Data is a sequence of character _codes_, this must be
%    translated into a sequence of _bytes_, because that is what
%    the hashing requires.  The default encoding is =utf8=.  The
%    other meaningful value is =octet=, claiming that Data contains
%    raw bytes.
%
%  @param Data is either an atom, string or code-list
%  @param Hash is an atom that represents the hash.

crypto_data_hash(Data, Hash, Options) :-
    crypto_context_new(Context0, Options),
    crypto_data_context(Data, Context0, Context),
    crypto_context_hash(Context, Hash).

%!  crypto_file_hash(+File, -Hash, +Options) is det.
%
%   True if  Hash is the hash  of the content of  File. For Options,
%   see crypto_data_hash/3.

crypto_file_hash(File, Hash, Options) :-
    setup_call_cleanup(open(File, read, In, [type(binary)]),
                       crypto_stream_hash(In, Hash, Options),
                       close(In)).

crypto_stream_hash(Stream, Hash, Options) :-
    crypto_context_new(Context0, Options),
    update_hash(Stream, Context0, Context),
    crypto_context_hash(Context, Hash).

update_hash(In, Context0, Context) :-
    (   at_end_of_stream(In)
    ->  Context = Context0
    ;   read_pending_codes(In, Data, []),
        crypto_data_context(Data, Context0, Context1),
        update_hash(In, Context1, Context)
    ).


%!  crypto_context_new(-Context, +Options) is det.
%
%   Context is unified  with the empty context,  taking into account
%   Options.  The  context can  be used in  crypto_data_hash/4.  For
%   Options, see crypto_data_hash/3.
%
%   @param Context is an opaque pure  Prolog term that is subject to
%          garbage collection.

%!  crypto_data_context(+Data, +Context0, -Context) is det
%
%   Context0 is an existing computation  context, and Context is the
%   new context  after hashing  Data in  addition to  the previously
%   hashed data.  Context0 may be  produced by a prior invocation of
%   either crypto_context_new/2 or crypto_data_context/3 itself.
%
%   This predicate allows a hash to be computed in chunks, which may
%   be important while working  with Metalink (RFC 5854), BitTorrent
%   or similar technologies, or simply with big files.

crypto_data_context(Data, Context0, Context) :-
    '_crypto_context_copy'(Context0, Context),
    '_crypto_update_context'(Data, Context).


%!  crypto_context_hash(+Context, -Hash)
%
%   Obtain the  hash code of  Context. Hash is an  atom representing
%   the hash code  that is associated with the current  state of the
%   computation context Context.

crypto_context_hash(Context, Hash) :-
    '_crypto_context_copy'(Context, Copy),
    '_crypto_context_hash'(Copy, List),
    crypto_hash_atom(List, Hash).

crypto_hash_atom(Codes, Hash) :-
    phrase(bytes_hex(Codes), HexCodes),
    atom_chars(Hash, HexCodes).

bytes_hex([]) --> [].
bytes_hex([H|T]) -->
    { High is H>>4,
      Low is H /\ 0xf,
      char_type(C0, xdigit(High)),
      char_type(C1, xdigit(Low))
    },
    [C0,C1],
    bytes_hex(T).

%!  crypto_open_hash_stream(+OrgStream, -HashStream, +Options) is det.
%
%   Open a filter stream on OrgStream  that maintains a hash. The hash
%   can be retrieved at any time using crypto_stream_hash/2. Available
%   Options in addition to those of crypto_data_hash/3 are:
%
%     - close_parent(+Bool)
%     If `true` (default), closing the filter stream also closes the
%     original (parent) stream.

crypto_open_hash_stream(OrgStream, HashStream, Options) :-
    crypto_context_new(Context, Options),
    '_crypto_open_hash_stream'(OrgStream, HashStream, Context).


%!  crypto_stream_hash(+HashStream, -Hash) is det.
%
%   Unify  Hash with  a hash  for  the bytes  sent to  or read  from
%   HashStream.  Note  that  the  hash is  computed  on  the  stream
%   buffers. If the stream is an  output stream, it is first flushed
%   and the Digest  represents the hash at the  current location. If
%   the stream is an input stream  the Digest represents the hash of
%   the processed input including the already buffered data.

crypto_stream_hash(Stream, Hash) :-
    '_crypto_stream_context'(Stream, Context),
    crypto_context_hash(Context, Hash).

%!  ecdsa_sign(+Key, +Data, -Signature, Options)
%
%   Create  an ECDSA  signature for  Data with  EC private  key Key.
%   Among the most  common cases is signing a hash  that was created
%   with crypto_data_hash/3 or other predicates of this library. For
%   this reason, the  default encoding (`hex`) assumes  that Data is
%   an atom,  string, character list  or code list  representing the
%   data in hexadecimal notation. See rsa_sign/4 for an example.
%
%   Options:
%
%     - encoding(+Encoding)
%     Encoding to use for Data.  Default is `hex`.  Alternatives
%     are `octet`, `utf8` and `text`.

ecdsa_sign(private_key(ec(Private,Public0,Curve)), Data0, Signature, Options) :-
    option(encoding(Enc0), Options, hex),
    hex_encoding(Enc0, Data0, Enc, Data),
    hex_bytes(Public0, Public),
    '_crypto_ecdsa_sign'(ec(Private,Public,Curve), Data, Enc, Signature).

hex_encoding(hex, Data0, octet, Data) :- !,
    (   hex_bytes(Data0, Data)
    ->  true
    ;   domain_error(hex_encoding, Data0)
    ).
hex_encoding(Enc, Data, Enc, Data).

hex_bytes(Hs, Bytes) :-
    string_chars(Hs, Chars),
    phrase(hex_bytes(Chars), Bytes).

hex_bytes([]) --> [].
hex_bytes([H1,H2|Hs]) --> [Byte],
    { char_type(H1, xdigit(High)),
      char_type(H2, xdigit(Low)),
      Byte is High*16 + Low },
    hex_bytes(Hs).

%!  ecdsa_verify(+Key, +Data, +Signature, +Options) is semidet.
%
%   True iff Signature can be verified as the ECDSA signature for
%   Data, using the EC public key Key.
%
%   Options:
%
%     - encoding(+Encoding)
%     Encoding to use for Data.  Default is `hex`.  Alternatives
%     are `octet`, `utf8` and `text`.

ecdsa_verify(public_key(ec(Private,Public0,Curve)), Data0, Signature0, Options) :-
    option(encoding(Enc0), Options, hex),
    hex_encoding(Enc0, Data0, Enc, Data),
    hex_bytes(Public0, Public),
    hex_bytes(Signature0, Signature),
    '_crypto_ecdsa_verify'(ec(Private,Public,Curve), Data, Enc, Signature).


%!  rsa_private_decrypt(+PrivateKey, +CipherText, -PlainText, +Options) is det.
%!  rsa_private_encrypt(+PrivateKey, +PlainText, -CipherText, +Options) is det.
%!  rsa_public_decrypt(+PublicKey, +CipherText, -PlainText, +Options) is det.
%!  rsa_public_encrypt(+PublicKey, +PlainText, -CipherText, +Options) is det.
%
%   RSA Public key encryption and   decryption  primitives. A string
%   can be safely communicated by first   encrypting it and have the
%   peer decrypt it with the matching  key and predicate. The length
%   of the string is limited by  the   key  length.
%
%   Options:
%
%     - encoding(+Encoding)
%     Encoding to use for Data.  Default is `utf8`.  Alternatives
%     are `utf8` and `octet`.
%
%     - padding(+PaddingScheme)
%     Padding scheme to use.  Default is `pkcs1`.  Alternatives
%     are `pkcs1_oaep`, `sslv23` and `none`. Note that `none` should
%     only be used if you implement cryptographically sound padding
%     modes in your application code as encrypting unpadded data with
%     RSA is insecure
%
%   @see load_private_key/3, load_public_key/2 can be use to load
%   keys from a file.  The predicate load_certificate/2 can be used
%   to obtain the public key from a certificate.
%
%   @error ssl_error(Code, LibName, FuncName, Reason)   is raised if
%   there is an error, e.g., if the text is too long for the key.

%!  rsa_sign(+Key, +Data, -Signature, +Options) is det.
%
%   Create an RSA signature for Data.  Options:
%
%     - type(+Type)
%     SHA algorithm used to compute the digest.  Values are
%     `sha1` (default), `sha224`, `sha256`, `sha384` or `sha512`.
%
%     - encoding(+Encoding)
%     Encoding to use for Data.  Default is `hex`.  Alternatives
%     are `octet`, `utf8` and `text`.
%
%   This predicate can be used to compute a =|sha256WithRSAEncryption|=
%   signature as follows:
%
%     ```
%     sha256_with_rsa(PemKeyFile, Password, Data, Signature) :-
%         Algorithm = sha256,
%         read_key(PemKeyFile, Password, Key),
%         crypto_data_hash(Data, Hash, [algorithm(Algorithm),
%                                       encoding(octet)]),
%         rsa_sign(Key, Hash, Signature, [type(Algorithm)]).
%
%     read_key(File, Password, Key) :-
%         setup_call_cleanup(
%             open(File, read, In, [type(binary)]),
%             load_private_key(In, Password, Key),
%             close(In)).
%     ```
%
%   Note that a hash that is computed by crypto_data_hash/3 can be
%   directly used in rsa_sign/4 as well as ecdsa_sign/4.

rsa_sign(Key, Data0, Signature, Options) :-
    option(type(Type), Options, sha1),
    option(encoding(Enc0), Options, hex),
    hex_encoding(Enc0, Data0, Enc, Data),
    rsa_sign(Key, Type, Enc, Data, Signature).


%!  rsa_verify(+Key, +Data, +Signature, +Options) is semidet.
%
%   Verifies an RSA signature for Data.  Options:
%
%     - type(+Type)
%     SHA algorithm used to compute the digest.  Values are
%     `sha1` (default), `sha224`, `sha256`, `sha384` or `sha512`.
%
%     - encoding(+Encoding)
%     Encoding to use for Data.  Default is `hex`.  Alternatives
%     are `octet`, `utf8` and `text`.

rsa_verify(Key, Data0, Signature0, Options) :-
    option(type(Type), Options, sha1),
    option(encoding(Enc0), Options, hex),
    hex_encoding(Enc0, Data0, Enc, Data),
    hex_bytes(Signature0, Signature),
    rsa_verify(Key, Type, Enc, Data, Signature).

%!  evp_decrypt(+CipherText,
%!              +Algorithm,
%!              +Key,
%!              +IV,
%!              -PlainText,
%!              +Options).
%
%   Decrypt  the  given  CipherText,  using    the  symmetric  algorithm
%   Algorithm, key Key, and iv IV,   to  give PlainText. CipherText, Key
%   and IV should all be strings, and   PlainText is created as a string
%   as well. Algorithm should be an algorithm which your copy of OpenSSL
%   knows about. Examples are:
%
%       * aes-128-cbc
%       * aes-256-cbc
%       * des3
%
%   If the IV is not  needed  for   your  decryption  algorithm (such as
%   aes-128-ecb) then any string can be provided   as it will be ignored
%   by the underlying implementation
%
%   Options:
%
%     - encoding(+Encoding)
%     Encoding to use for Data.  Default is `utf8`.  Alternatives
%     are `utf8` and `octet`.
%
%     - padding(+PaddingScheme)
%     Padding scheme to use.  Default is `block`.  You can disable padding
%     by supplying
%     `none` here.
%
%   Example of aes-128-cbc encryption:
%
%     ```
%     ?- evp_encrypt("this is some input", 'aes-128-cbc', "sixteenbyteofkey",
%                    "sixteenbytesofiv", CipherText, []),
%        evp_decrypt(CipherText, 'aes-128-cbc',
%                    "sixteenbyteofkey", "sixteenbytesofiv",
%                    RecoveredText, []).
%     CipherText = <binary string>
%     RecoveredText = "this is some input".
%     ```

%!  evp_encrypt(+PlainText,
%!              +Algorithm,
%!              +Key,
%!              +IV,
%!              -CipherTExt,
%!              +Options).
%
%   Encrypt  the  given  PlainText,  using    the   symmetric  algorithm
%   Algorithm,  key  Key,  and  iv   IV,    to   give   CipherText.  See
%   evp_decrypt/6.

                 /*******************************
                 *          Sandboxing          *
                 *******************************/

:- multifile sandbox:safe_primitive/1.

sandbox:safe_primitive(crypto:crypto_data_hash(_,_,_)).
sandbox:safe_primitive(crypto:crypto_data_context(_,_,_)).
sandbox:safe_primitive(crypto:crypto_context_new(_,_)).
sandbox:safe_primitive(crypto:crypto_context_hash(_,_)).

                 /*******************************
                 *           MESSAGES           *
                 *******************************/

:- multifile
    prolog:error_message//1.

prolog:error_message(ssl_error(ID, _Library, Function, Reason)) -->
    [ 'SSL(~w) ~w: ~w'-[ID, Function, Reason] ].
