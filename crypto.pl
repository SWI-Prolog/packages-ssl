/*  Part of SWI-Prolog

    Author:        Matt Lilley and Markus Triska
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

:- module(crypto,
          [ evp_decrypt/6,              % +CipherText, +Algorithm, +Key, +IV, -PlainText, +Options
            evp_encrypt/6,              % +PlainText, +Algorithm, +Key, +IV, -CipherText, +Options
            rsa_private_decrypt/3,      % +Key, +Ciphertext, -Plaintext
            rsa_private_encrypt/3,      % +Key, +Plaintext, -Ciphertext
            rsa_public_decrypt/3,       % +Key, +Ciphertext, -Plaintext
            rsa_public_encrypt/3,       % +Key, +Plaintext, -Ciphertext
            rsa_private_decrypt/4,      % +Key, +Ciphertext, -Plaintext, +Enc
            rsa_private_encrypt/4,      % +Key, +Plaintext, -Ciphertext, +Enc
            rsa_public_decrypt/4,       % +Key, +Ciphertext, -Plaintext, +Enc
            rsa_public_encrypt/4,       % +Key, +Plaintext, -Ciphertext, +Enc
            rsa_sign/4,                 % +Key, +Data, -Signature, +Options
            rsa_verify/4                % +Key, +Data, -Signature, +Options
          ]).
:- use_module(library(error)).
:- use_module(library(option)).
:- use_module(library(debug)).

:- use_foreign_library(foreign(crypto4pl)).


/** <module> Cryptography and authentication library

This library provides bindings to functionality of OpenSSL that is
related to cryptography and authentication, not necessarily involving
connections, sockets or streams.

@author Matt Lilley
@author [Markus Triska](https://www.metalevel.at)
*/

%%	rsa_private_decrypt(+PrivateKey, +CipherText, -PlainText) is det.
%%      rsa_private_encrypt(+PrivateKey, +PlainText, -CipherText) is det.
%%      rsa_public_decrypt(+PublicKey, +CipherText, -PlainText) is det.
%%      rsa_public_encrypt(+PublicKey, +PlainText, -CipherText) is det.
%%	rsa_private_decrypt(+PrivateKey, +CipherText, -PlainText, +Options) is det.
%%      rsa_private_encrypt(+PrivateKey, +PlainText, -CipherText, +Options) is det.
%%      rsa_public_decrypt(+PublicKey, +CipherText, -PlainText, +Options) is det.
%%      rsa_public_encrypt(+PublicKey, +PlainText, -CipherText, +Options) is det.
%
%	RSA Public key encryption and   decryption  primitives. A string
%	can be safely communicated by first   encrypting it and have the
%	peer decrypt it with the matching  key and predicate. The length
%	of the string is limited by  the   key  length.
%
%       Options:
%
%	  - encoding(+Encoding)
%	  Encoding to use for Data.  Default is `utf8`.  Alternatives
%	  are `utf8` and `octet`.
%
%	  - padding(+PaddingScheme)
%	  Padding scheme to use.  Default is `pkcs1`.  Alternatives
%	  are `pkcs1_oaep`, `sslv23` and `none`. Note that `none` should
%         only be used if you implement cryptographically sound padding
%         modes in your application code as encrypting unpadded data with
%         RSA is insecure
%
%	@see load_private_key/3, load_public_key/2 can be use to load
%	keys from a file.  The predicate load_certificate/2 can be used
%	to obtain the public key from a certificate.
%
%	@error ssl_error(Code, LibName, FuncName, Reason)   is raised if
%	there is an error, e.g., if the text is too long for the key.

rsa_private_decrypt(PrivateKey, CipherText, PlainText) :-
	rsa_private_decrypt(PrivateKey, CipherText, PlainText, [encoding(utf8)]).

rsa_private_encrypt(PrivateKey, PlainText, CipherText) :-
	rsa_private_encrypt(PrivateKey, PlainText, CipherText, [encoding(utf8)]).

rsa_public_decrypt(PublicKey, CipherText, PlainText) :-
	rsa_public_decrypt(PublicKey, CipherText, PlainText, [encoding(utf8)]).

rsa_public_encrypt(PublicKey, PlainText, CipherText) :-
	rsa_public_encrypt(PublicKey, PlainText, CipherText, [encoding(utf8)]).

%%	rsa_sign(+Key, +Data, -Signature, +Options) is det.
%
%	Create an RSA signature for Data.  Options:
%
%	  - type(+Type)
%	  SHA algorithm used to compute the digest.  Values are the
%	  same as for sha_hash/3: `sha1` (default), `sha224`, `sha256`,
%	  `sha384` or `sha512`
%
%	  - encoding(+Encoding)
%	  Encoding to use for Data.  Default is `octet`.  Alternatives
%	  are `utf8` and `text`.
%
%	This predicate is used  to   compute  a  _sha1WithRSAEncryption_
%	signature as follows:
%
%	  ```
%	  sha1_with_rsa(PemKeyFile, KeyPassword, Data, Signature) :-
%	      DigestAlgorithm = sha1,
%	      read_key(PemKeyFile, KeyPassword, PrivateKey),
%	      sha_hash(Data, Digest, [algorithm(DigestAlgorithm)]),
%	      rsa_sign(Key, Digest, Signature, [type(DigestAlgorithm)]).
%
%	  read_key(PemKeyFile, KeyPassword, PrivateKey) :-
%	      setup_call_cleanup(
%	          open(File, read, In, [type(binary)]),
%	          load_private_key(In, Password, Key),
%	          close(In).
%	  ```

rsa_sign(Key, Data, Signature, Options) :-
	option(type(Type), Options, sha1),
	option(encoding(Enc), Options, octet),
	rsa_sign(Key, Type, Enc, Data, Signature).


%%	rsa_verify(+Key, +Data, -Signature, +Options) is det.
%
%	Verifies an RSA signature for Data.  Options:
%
%	  - type(+Type)
%	  SHA algorithm used to compute the digest.  Values are the
%	  same as for sha_hash/3: `sha1` (default), `sha224`, `sha256`,
%	  `sha384` or `sha512`
%
%	  - encoding(+Encoding)
%	  Encoding to use for Data.  Default is `octet`.  Alternatives
%	  are `utf8` and `text`.

rsa_verify(Key, Data, Signature, Options) :-
	option(type(Type), Options, sha1),
	option(encoding(Enc), Options, octet),
        rsa_verify(Key, Type, Enc, Data, Signature).

%%	evp_decrypt(+CipherText,
%%                  +Algorithm,
%%                  +Key,
%%                  +IV,
%%                  -PlainText,
%%                  +Options).
%       Decrypt the given CipherText, using the symmetric algorithm Algorithm, key Key,
%       and iv IV, to give PlainText. CipherText, Key and IV should all be strings, and
%       PlainText is created as a string as well. Algorithm should be an algorithm which
%       your copy of OpenSSL knows about. Examples are:
%           * aes-128-cbc
%           * aes-256-cbc
%           * des3
%       If the IV is not needed for your decryption algorithm (such as aes-128-ecb) then
%       any string can be provided as it will be ignored by the underlying implementation
%
%       Options:
%
%	  - encoding(+Encoding)
%	  Encoding to use for Data.  Default is `utf8`.  Alternatives
%	  are `utf8` and `octet`.
%
%	  - padding(+PaddingScheme)
%	  Padding scheme to use.  Default is `block`.  You can disable padding by supplying
%         `none` here.
%
%       Example of aes-128-cbc encryption:
%       ?- evp_encrypt("this is some input", 'aes-128-cbc', "sixteenbyteofkey",
%                      "sixteenbytesofiv", CipherText, []),
%          evp_decrypt(CipherText, 'aes-128-cbc', "sixteenbyteofkey", "sixteenbytesofiv",
%                      RecoveredText, []).
%       CipherText = <binary string>
%       RecoveredText = "this is some input".

%%	evp_encrypt(+PlainText,
%%                  +Algorithm,
%%                  +Key,
%%                  +IV,
%%                  -CipherTExt,
%%                  +Options).
%       Encrypt the given PlainText, using the symmetric algorithm Algorithm, key Key,
%       and iv IV, to give CipherText. See evp_decrypt/6.


		 /*******************************
		 *	     MESSAGES		*
		 *******************************/

:- multifile
	prolog:error_message//1.

prolog:error_message(ssl_error(ID, _Library, Function, Reason)) -->
	[ 'SSL(~w) ~w: ~w'-[ID, Function, Reason] ].
