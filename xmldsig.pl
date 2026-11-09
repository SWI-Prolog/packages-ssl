/*  Part of SWI-Prolog

    Author:        Jan Wielemaker and Matt Lilley
    E-mail:        J.Wielemaker@vu.nl
    WWW:           http://www.swi-prolog.org
    Copyright (c)  2016, CWI, Amsterdam
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

:- module(xmldsig,
          [ xmld_signed_DOM/3,                  % +DOM, -SignedDOM, +Options
            xmld_verify_signature/4             % +DOM, +Signature, -Certificate, +Options
          ]).
:- autoload(library(base64),[base64/3,base64/2]).
:- autoload(library(c14n2),[xml_write_canonical/3]).
:- autoload(library(crypto),
	    [crypto_data_hash/3,rsa_sign/4,hex_bytes/2,rsa_verify/4]).
:- use_module(library(debug),[debug/3]).
:- autoload(library(error),
	    [type_error/2,domain_error/2,existence_error/2]).
:- autoload(library(lists),[member/2,append/3,reverse/2]).
:- autoload(library(apply),[maplist/3,foldl/4]).
:- autoload(library(option),[option/3,option/2]).
:- autoload(library(sha),[sha_hash/3]).
:- autoload(library(ssl),[load_private_key/3,certificate_field/2]).
:- autoload(library(xmlenc),[load_certificate_from_base64_string/2]).

/** <module> XML Digital signature

This library deals with _XMLDSIG_, RSA signed XML documents.

@see http://www.di-mgt.com.au/xmldsig.html
@see https://www.bmt-online.org/geekisms/RSA_verify
@see http://stackoverflow.com/questions/5576777/whats-the-difference-between-nid-sha-and-nid-sha1-in-openssl

*/

xmldsig_ns('http://www.w3.org/2000/09/xmldsig#').

%!  xmld_signed_DOM(+DOM, -SignedDOM, +Options) is det.
%
%   Translate an XML DOM structure in a signed version.  Options:
%
%     - key_file(+File)
%     File holding the private key needed to sign
%     - key_password(+Password)
%     String holding the password to op the private key.
%
%   The   SignedDOM   must   be   emitted   using   xml_write/3   or
%   xml_write_canonical/3.  If  xml_write/3  is   used,  the  option
%   layout(false) is needed to avoid  changing   the  layout  of the
%   =SignedInfo= element and the signed DOM,   which  will cause the
%   signature to be invalid.

xmld_signed_DOM(DOM, SignedDOM, Options) :-
    dom_hash(DOM, ODOM, Hash, Options),
    signed_info(Hash, Signature, SDOM, KeyDOM, Options),
    signed_xml_dom(ODOM, SDOM, KeyDOM, Signature, SignedDOM, Options).


%!  dom_hash(+DOM, -ODOM, -Hash, +Options) is det.
%
%   Compute the digest for DOM.
%
%   @arg Hash is the base64  encoded   version  of  the selected SHA
%   algorithm.

dom_hash(DOM, ODOM, Hash, Options) :-
    object_c14n(DOM, ODOM, C14N),
    hash(C14N, Hash, Options).

object_c14n(DOM, ODOM, C14N) :-
    object_dom(DOM, ODOM),
    with_output_to(
        string(C14N),
        xml_write_canonical(current_output, ODOM, [])).

object_dom(DOM0,
           element(NS:'Object', ['Id'='object', xmlns=NS], DOM)) :-
    xmldsig_ns(NS),
    to_list(DOM0, DOM).

to_list(DOM, DOM) :- DOM = [_|_].
to_list(DOM, [DOM]).

hash(C14N, Hash, Options) :-
    option(hash(Algo), Options, sha256),
    sha_hash(C14N, HashCodes, [algorithm(Algo)]),
    phrase(base64(HashCodes), Base64Codes),
    string_codes(Hash, Base64Codes).

%!  signed_info(+Hash, -Signature, -SDOM, -KeyDOM, +Options)

signed_info(Hash, Signature, SDOM, KeyDOM, Options) :-
    signed_info_dom(Hash, SDOM, Options),
    with_output_to(
        string(SignedInfo),
        xml_write_canonical(current_output, SDOM, [])),
    rsa_signature(SignedInfo, Signature, KeyDOM, Options).

%!  signed_info_dom(+Hash, -SDOM, +Options) is det.
%
%   True when SDOM is the xmldsign:Signature  DOM for an object with
%   the given Hash.

signed_info_dom(Hash, SDOM, Options) :-
    SDOM = element(NS:'SignedInfo', [xmlns=NS],
                   [ '\n  ',
                     element(NS:'CanonicalizationMethod',
                             ['Algorithm'=C14NAlgo], []),
                     '\n  ',
                     element(NS:'SignatureMethod',
                             ['Algorithm'=SignatureMethod], []),
                     '\n  ',
                     Reference,
                     '\n'
                   ]),
    Reference = element(NS:'Reference', ['URI'='#object'],
                        [ '\n    ',
                          element(NS:'DigestMethod',
                                  ['Algorithm'=DigestMethod], []),
                          '\n    ',
                          element(NS:'DigestValue', [], [Hash]),
                          '\n  '
                        ]),
    xmldsig_ns(NS),
    option(hash(DigestAlgo), Options, sha256),
    option(algorithm(SignAlgo), Options, sha256),
    (   digest_method(DigestMethod, DigestAlgo)
    ->  true
    ;   domain_error(digest_algorithm, DigestAlgo)
    ),
    (   ssl_algorithm(SignatureMethod, rsa(SignAlgo))
    ->  true
    ;   domain_error(signature_algorithm, SignAlgo)
    ),
    C14NAlgo='http://www.w3.org/TR/2001/REC-xml-c14n-20010315'.

%!  rsa_signature(+SignedInfo:string, -Signature, -KeyDOM, +Options)

rsa_signature(SignedInfo, Signature, KeyDOM, Options) :-
    option(algorithm(Algorithm), Options, sha256),
    crypto_data_hash(SignedInfo, Digest, [algorithm(Algorithm)]),
    string_upper(Digest, DIGEST),
    debug(xmldsig, 'SignedInfo ~w digest = ~p', [Algorithm, DIGEST]),
    private_key(Key, Options),
    rsa_key_dom(Key, KeyDOM),
    rsa_sign(Key, Digest, String,
             [ type(Algorithm)
             ]),
    string_length(String, Len),
    debug(xmldsig, 'RSA signatute length: ~p', [Len]),
    string_codes(String, Codes),
    phrase(base64(Codes), Codes64),
    string_codes(Signature, Codes64).

private_key(Key, Options) :-
    option(key_file(File), Options),
    option(key_password(Password), Options),
    !,
    setup_call_cleanup(
        open(File, read, In, [type(binary)]),
        load_private_key(In, Password, Key),
        close(In)).
private_key(_Key, Options) :-
    \+ option(key_file(_), Options),
    !,
    throw(error(existence_error(option, key_file, Options),_)).
private_key(_Key, Options) :-
    throw(error(existence_error(option, key_password, Options),_)).



%!  rsa_key_dom(+Key, -DOM) is det.
%
%   Produce the KeyInfo node from the private key.

rsa_key_dom(Key,
            element(NS:'KeyInfo', [xmlns=NS],
                    [ element(NS:'KeyValue', [],
                              [ '\n  ',
                                element(NS:'RSAKeyValue', [],
                                        [ '\n    ',
                                          element(NS:'Modulus', [], [Modulus]),
                                          '\n    ',
                                          element(NS:'Exponent', [], [Exponent]),
                                          '\n  '
                                        ]),
                                '\n'
                              ])
                    ])) :-
    key_info(Key, Info),
    _{modulus:Modulus, exponent:Exponent} :< Info,
    xmldsig_ns(NS).


%!  key_info(+Key, -Info) is det.
%
%   Extract the RSA modulus and exponent   from a private key. These
%   are the first end  second  field  of   the  rsa  term.  They are
%   represented as hexadecimal encoded bytes. We must recode this to
%   base64.
%
%   @tbd    Provide better support from library(ssl).

key_info(private_key(Key), rsa{modulus:Modulus, exponent:Exponent}) :-
    !,
    base64_bignum_arg(1, Key, Modulus),
    base64_bignum_arg(2, Key, Exponent).
key_info(Key, _) :-
    type_error(private_key, Key).

base64_bignum_arg(I, Key, Value) :-
    arg(I, Key, HexModulesString),
    string_codes(HexModulesString, HexModules),
    hex_bytes(HexModules, Bytes),
    phrase(base64(Bytes), Bytes64),
    string_codes(Value, Bytes64).


signed_xml_dom(ObjectDOM, SDOM, KeyDOM, Signature, SignedDOM, _Options) :-
    SignedDOM = element(NS:'Signature', [xmlns=NS],
                        [ '\n', SDOM,
                          '\n', element(NS:'SignatureValue', [], [Signature]),
                          '\n', KeyDOM,
                          '\n', ObjectDOM,
                          '\n'
                        ]),
    xmldsig_ns(NS).



%!  xmld_verify_signature(+DOM, +SignatureDOM, -Certificate, +Options) is det.
%
%   Confirm  that  an  `ds:Signature`  element    contains  a  valid
%   signature. Certificate is bound to  the certificate that appears
%   in the element if the signature is valid. It is up to the caller
%   to determine if the certificate is trusted   or not.  Raises an
%   exception if the signature is not valid.
%
%   DOM is the complete document.  Each `ds:Reference` must refer to
%   exactly one element of DOM with an `ID`, `Id` or `id` attribute
%   that has the referenced value.  Options:
%
%     - references(-Elements)
%       Unify Elements with the list of elements (in DOM) whose content
%       is protected by the signature.  It is the responsibility of the
%       caller to verify that these are the elements it uses.  Notably
%       when verifying a SAML message, the content used must be (part
%       of) one of these elements to avoid _signature wrapping_ attacks.
%     - weak_algorithms(+Boolean)
%       If `true` (default `false`), accept the SHA1 and MD5 based
%       signature and digest algorithms.
%
%   *Note*: The DOM and SignatureDOM must   have been obtained using
%   the load_structure/3 option keep_prefix(true)   otherwise  it is
%   impossible to generate an identical   document  for checking the
%   signature. See also xml_write_canonical/3.

xmld_verify_signature(DOM, SignatureDOM, Certificate, Options) :-
    signature_info(DOM, SignatureDOM, SignedInfo, Algorithm, Signature,
                   PublicKey, Certificate, CanonicalizationMethod,
                   Elements, Options),
    base64(RawSignature, Signature),
    (   Algorithm = rsa(HashType)
    ->  with_output_to(string(C14N),
                       xml_write_canonical(current_output, SignedInfo,
                                           [method(CanonicalizationMethod)])),
        crypto_data_hash(C14N, Digest, [algorithm(HashType)]),
        atom_codes(RawSignature, Codes),
        hex_bytes(HexSignature, Codes),
        (   catch(rsa_verify(PublicKey, Digest, HexSignature,
                             [type(HashType)]), _, fail)
        ->  true
        ;   signature_error(invalid_signature)
        )
    ;   domain_error(supported_signature_algorithm, Algorithm)
    ),
    (   option(references(Refs), Options)
    ->  Refs = Elements
    ;   true
    ).

signature_error(Error) :-
    throw(error(xmldsig(Error), _)).

ssl_algorithm('http://www.w3.org/2000/09/xmldsig#rsa-sha1', rsa(sha1)).
ssl_algorithm('http://www.w3.org/2000/09/xmldsig#dsa-sha1', dsa(sha1)).
ssl_algorithm('http://www.w3.org/2001/04/xmldsig-more#hmac-md5', hmac(md5)).       % NB: Requires a parameter
ssl_algorithm('http://www.w3.org/2001/04/xmldsig-more#hmac-sha224', hmac(sha224)).
ssl_algorithm('http://www.w3.org/2001/04/xmldsig-more#hmac-sha256', hmac(sha256)).
ssl_algorithm('http://www.w3.org/2001/04/xmldsig-more#hmac-sha384', hmac(sha384)).
ssl_algorithm('http://www.w3.org/2001/04/xmldsig-more#hmac-sha512', hmac(sha512)).
ssl_algorithm('http://www.w3.org/2001/04/xmldsig-more#rsa-md5', rsa(md5)).
ssl_algorithm('http://www.w3.org/2001/04/xmldsig-more#rsa-sha256', rsa(sha256)).
ssl_algorithm('http://www.w3.org/2001/04/xmldsig-more#rsa-sha384', rsa(sha384)).
ssl_algorithm('http://www.w3.org/2001/04/xmldsig-more#rsa-sha512', rsa(sha512)).
ssl_algorithm('http://www.w3.org/2001/04/xmldsig-more#rsa-ripemd160', rsa(ripemd160)).
ssl_algorithm('http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1', ecdsa(sha1)).
ssl_algorithm('http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha224', ecdsa(sha224)).
ssl_algorithm('http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256', ecdsa(sha256)).
ssl_algorithm('http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384', ecdsa(sha384)).
ssl_algorithm('http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512', ecdsa(sha512)).
ssl_algorithm('http://www.w3.org/2001/04/xmldsig-more#esign-sha1', esign(sha1)).
ssl_algorithm('http://www.w3.org/2001/04/xmldsig-more#esign-sha224', esign(sha224)).
ssl_algorithm('http://www.w3.org/2001/04/xmldsig-more#esign-sha256', esign(sha256)).
ssl_algorithm('http://www.w3.org/2001/04/xmldsig-more#esign-sha384', esign(sha384)).
ssl_algorithm('http://www.w3.org/2001/04/xmldsig-more#esign-sha512', esign(sha512)).

digest_method('http://www.w3.org/2000/09/xmldsig#sha1', sha1).
digest_method('http://www.w3.org/2001/04/xmlenc#sha256', sha256).
digest_method('http://www.w3.org/2001/04/xmldsig-more#sha384', sha384).
digest_method('http://www.w3.org/2001/04/xmlenc#sha512', sha512).

weak_hash(md5).
weak_hash(sha1).

%   allowed_hash(+Hash, +Options) is semidet.

allowed_hash(Hash, Options) :-
    (   weak_hash(Hash)
    ->  option(weak_algorithms(true), Options)
    ;   true
    ).

signature_info(DOM, Signature, SignedData, Algorithm, SignatureValue,
               PublicKey, Certificate, CanonicalizationMethod,
               Elements, Options) :-
    xmldsig_ns(NSRef),
    (   memberchk(element(ns(_, NSRef):'SignatureValue', _, [RawSignatureValue]), Signature),
        memberchk(element(ns(Prefix, NSRef):'SignedInfo', SignedInfoAttributes, SignedInfo), Signature),
        memberchk(element(ns(_, NSRef):'CanonicalizationMethod', CanonicalizationMethodAttributes, _), SignedInfo),
        memberchk('Algorithm'=CanonicalizationMethod, CanonicalizationMethodAttributes),
        memberchk(element(ns(_, NSRef):'SignatureMethod', SignatureMethodAttributes, _), SignedInfo),
        memberchk('Algorithm'=XMLAlgorithm, SignatureMethodAttributes)
    ->  true
    ;   signature_error(malformed_signature)
    ),
    atom_codes(RawSignatureValue, RawSignatureCodes),
    delete_newlines(RawSignatureCodes, SignatureCodes),
    string_codes(SignatureValue, SignatureCodes),
    SignedData = element(ns(Prefix, NSRef):'SignedInfo', SignedInfoAttributes, SignedInfo),
    (   c14n_method(CanonicalizationMethod)
    ->  true
    ;   domain_error(canonicalization_method, CanonicalizationMethod)
    ),
    (   ssl_algorithm(XMLAlgorithm, Algorithm)
    ->  true
    ;   domain_error(signature_algorithm, XMLAlgorithm)
    ),
    (   Algorithm =.. [_,Hash],
        allowed_hash(Hash, Options)
    ->  true
    ;   domain_error(signature_algorithm, XMLAlgorithm)
    ),
    findall(ReferenceAttributes-Reference,
            member(element(ns(_, NSRef):'Reference', ReferenceAttributes, Reference),
                   SignedInfo),
            References),
    (   References == []
    ->  signature_error(no_reference)
    ;   true
    ),
    maplist(verify_reference(DOM, Options), References, Elements),
    (   memberchk(element(ns(_, NSRef):'KeyInfo', _, KeyInfo), Signature),
        memberchk(element(ns(_, NSRef):'X509Data', _, X509Data), KeyInfo),
        memberchk(element(ns(_, NSRef):'X509Certificate', _, [X509Certificate]), X509Data)
    ->  load_certificate_from_base64_string(X509Certificate, Certificate),
        certificate_field(Certificate, public_key(PublicKey))
    ;   existence_error(x509_certificate, Signature)
    ).

c14n_method('http://www.w3.org/TR/2001/REC-xml-c14n-20010315').
c14n_method('http://www.w3.org/2006/12/xml-c14n11').
c14n_method('http://www.w3.org/2001/10/xml-exc-c14n#').


delete_newlines([], []):- !.
delete_newlines([13|As], B):- !, delete_newlines(As, B).
delete_newlines([10|As], B):- !, delete_newlines(As, B).
delete_newlines([A|As], [A|B]):- !, delete_newlines(As, B).


%   verify_reference(+DOM, +Options, +Attributes-Reference, -Element)
%
%   Verify the digest of a ds:Reference.  Element is the referenced
%   element in DOM.

verify_reference(DOM, Options, ReferenceAttributes-Reference, Element):-
    xmldsig_ns(NSRef),
    (   memberchk('URI'=URI, ReferenceAttributes),
        atom_concat('#', Id, URI),
        Id \== ''
    ->  true
    ;   domain_error(supported_reference, ReferenceAttributes)
    ),
    resolve_reference(DOM, Id, Element, Digestible),
    (  memberchk(element(ns(_, NSRef):'Transforms', _, Transforms), Reference)
    -> findall(TransformAttributes-Transform,
               member(element(ns(_, NSRef):'Transform', TransformAttributes, Transform), Transforms),
               TransformList)
    ;  TransformList = []
    ),
    apply_transforms(TransformList, Digestible, TransformedDigestible),
    c14n_transform(TransformList, CanonicalizationMethod),
    (   memberchk(element(ns(_, NSRef):'DigestMethod', DigestMethodAttributes, _), Reference),
        memberchk(element(ns(_, NSRef):'DigestValue', _, [DigestBase64]), Reference),
        memberchk('Algorithm'=Algorithm, DigestMethodAttributes)
    ->  true
    ;   signature_error(malformed_reference)
    ),
    (   digest_method(Algorithm, DigestMethod),
        allowed_hash(DigestMethod, Options)
    ->  true
    ;   domain_error(supported_digest_method, Algorithm)
    ),
    with_output_to(string(XMLString),
                   xml_write_canonical(current_output, TransformedDigestible,
                                       [method(CanonicalizationMethod)])),
    sha_hash(XMLString, DigestBytes, [algorithm(DigestMethod)]),
    base64(ExpectedDigest, DigestBase64),
    atom_codes(ExpectedDigest, ExpectedDigestBytes),
    (  ExpectedDigestBytes == DigestBytes
    -> true
    ;  signature_error(invalid_digest)
    ).

%   c14n_transform(+Transforms, -Method)
%
%   The canonicalization used for computing the digest is the last
%   canonicalization transform or inclusive canonicalization if there
%   is none.

c14n_transform(Transforms, Method) :-
    reverse(Transforms, RevTransforms),
    member(Attributes-_, RevTransforms),
    memberchk('Algorithm'=Method, Attributes),
    c14n_method(Method),
    !.
c14n_transform(_, 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315').


%   resolve_reference(+DOM, +ID, -Element, -Digestible)
%
%   Element is the unique element in DOM with the identifier ID.
%   Digestible is Element with the namespace declarations of its
%   ancestors added such that inclusive canonicalization can be
%   applied.

resolve_reference(DOM, ID, Element, Digestible) :-
    findall(E-NS, find_id(DOM, ID, [], E, NS), Found),
    (   Found = [Element-Inherited]
    ->  inherit_ns(Inherited, Element, Digestible)
    ;   Found == []
    ->  existence_error(signed_element, ID)
    ;   signature_error(duplicate_id(ID))
    ).

find_id([element(Tag, Attributes, Children)|Siblings], ID, NS0, Element, NS) :-
    (   id_attribute(Attributes, ID),
        Element = element(Tag, Attributes, Children),
        NS = NS0
    ;   ns_decls(Attributes, Decls),
        append(Decls, NS0, NS1),
        find_id(Children, ID, NS1, Element, NS)
    ;   find_id(Siblings, ID, NS0, Element, NS)
    ).
find_id([H|Siblings], ID, NS0, Element, NS) :-
    H \= element(_,_,_),
    find_id(Siblings, ID, NS0, Element, NS).

id_attribute(Attributes, ID) :-
    member(Name=ID, Attributes),
    id_attribute_name(Name),
    !.

id_attribute_name('ID').
id_attribute_name('Id').
id_attribute_name(id).

ns_decls(Attributes, Decls) :-
    findall(Prefix-URI,
            ( member(Attr, Attributes),
              ns_decl(Attr, Prefix, URI)
            ), Decls).

ns_decl(ns('', xmlns):Prefix=URI, Prefix, URI) :- !.
ns_decl(xmlns=URI, '', URI) :- !.
ns_decl(xmlns:Prefix=URI, Prefix, URI) :- !.
ns_decl(Name=URI, Prefix, URI) :-
    atom(Name),
    atom_concat('xmlns:', Prefix, Name).

%   inherit_ns(+Inherited, +Element0, -Element)
%
%   Add the namespace declarations of the ancestors that are not
%   overruled by the element itself.  Inherited is ordered innermost
%   first.

inherit_ns([], Element, Element) :- !.
inherit_ns(Inherited, element(Tag, Attributes0, Children),
           element(Tag, Attributes, Children)) :-
    ns_decls(Attributes0, Own),
    foldl(add_inherited, Inherited, Own-Attributes0, _-Attributes).

add_inherited(Prefix-URI, Seen-Attributes0, Seen1-Attributes) :-
    (   memberchk(Prefix-_, Seen)
    ->  Seen1 = Seen,
        Attributes = Attributes0
    ;   Seen1 = [Prefix-URI|Seen],
        (   Prefix == ''
        ->  Attributes = [xmlns=URI|Attributes0]
        ;   Attributes = [ns('', xmlns):Prefix=URI|Attributes0]
        )
    ).


apply_transforms([], X, X):- !.
apply_transforms([Attributes-Children|Transforms], In, Out):-
    memberchk('Algorithm'=Algorithm, Attributes),
    (  apply_transform(Algorithm, Children, In, I1)
    -> true
    ;  existence_error(transform_algorithm, Algorithm)
    ),
    apply_transforms(Transforms, I1, Out).

apply_transform('http://www.w3.org/2001/10/xml-exc-c14n#', _, X, X).
apply_transform('http://www.w3.org/TR/2001/REC-xml-c14n-20010315', [], X, X).
apply_transform('http://www.w3.org/2006/12/xml-c14n11', [], X, X).
apply_transform('http://www.w3.org/2000/09/xmldsig#enveloped-signature', [], element(Tag, Attributes, Children), element(Tag, Attributes, NewChildren)):-
    delete_signature_element(Children, NewChildren).

delete_signature_element([element(ns(_, 'http://www.w3.org/2000/09/xmldsig#'):'Signature', _, _)|Siblings], Siblings):- !.
delete_signature_element([A|Siblings], [A|NewSiblings]):-
    delete_signature_element(Siblings, NewSiblings).


		 /*******************************
		 *           MESSAGES		*
		 *******************************/

:- multifile
    prolog:error_message//1.

prolog:error_message(xmldsig(Error)) -->
    [ 'XML signature: ' ],
    xmldsig_message(Error).

xmldsig_message(invalid_signature) -->
    [ 'invalid signature' ].
xmldsig_message(invalid_digest) -->
    [ 'digest of referenced element does not match' ].
xmldsig_message(no_reference) -->
    [ 'signature has no references' ].
xmldsig_message(duplicate_id(ID)) -->
    [ 'multiple elements with identifier ~p'-[ID] ].
xmldsig_message(malformed_signature) -->
    [ 'malformed signature element' ].
xmldsig_message(malformed_reference) -->
    [ 'malformed reference element' ].
