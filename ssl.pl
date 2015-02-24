/*  Part of SWI-Prolog

    Author:        Jan van der Steen, Matt Lilley and Jan Wielemaker,
    E-mail:        J.Wielemaker@vu.nl
    WWW:           http://www.swi-prolog.org
    Copyright (C): 2004-2015, SWI-Prolog Foundation
			      VU University Amsterdam

    This program is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License
    as published by the Free Software Foundation; either version 2
    of the License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

    As a special exception, if you link this library with other files,
    compiled with a Free Software compiler, to produce an executable, this
    library does not by itself cause the resulting executable to be covered
    by the GNU General Public License. This exception does not however
    invalidate any other reasons why the executable file might be covered by
    the GNU General Public License.
*/

:- module(ssl,
	  [ load_certificate/2,         % +Stream, -Certificate
            load_private_key/3,         % +Stream, +Password, -Key
            load_public_key/2,          % +Stream, -Key
            load_crl/2,                 % +Stream, -Crl
	    cert_accept_any/5,		% +SSL, +ProblemCertificate,
					% +AllCertificates, +FirstCertificate,
					% +Error
            rsa_private_decrypt/3,      % +Key, +Ciphertext, -Plaintext
            rsa_private_encrypt/3,      % +Key, +Plaintext, -Ciphertext
            rsa_public_decrypt/3,       % +Key, +Ciphertext, -Plaintext
            rsa_public_encrypt/3,       % +Key, +Plaintext, -Ciphertext
            ssl_context/3,		% +Role, -Config, +Options
            ssl_init/3,                 % -Config, +Role, +Options
            ssl_accept/3,               % +Config, -Socket, -Peer
            ssl_open/3,                 % +Config, -Read, -Write
            ssl_open/4,                 % +Config, +Socket, -Read, -Write
            ssl_negotiate/5,            % +Config, +PlainRead, +PlainWrite,
					%          -SSLRead,   -SSLWrite
	    ssl_exit/1,			% +Config
            ssl_session/2               % +Stream, -Session
	  ]).
:- use_module(library(socket)).
:- use_module(library(error)).
:- use_module(library(option)).

:- use_foreign_library(foreign(ssl4pl)).

:- meta_predicate
	ssl_init(-, +, :),
	ssl_context(+, -, :).

:- predicate_options(ssl_context/3, 3,
		     [ certificate_file(atom),
		       key_file(atom),
		       password(any),
		       pem_password_hook(callable),
		       cacert_file(any),
		       cert_verify_hook(callable),
		       cert(boolean),
		       peer_cert(boolean),
		       close_parent(boolean)
		     ]).
:- predicate_options(ssl_init/3, 3,
		     [ host(atom),
		       port(integer),
		       pass_to(ssl_context/3, 3)
		     ]).

/** <module> Secure Socket Layer (SSL) library

An SSL server and client can be built with the following (abstracted)
predicate calls:

	| SSL Server		| SSL Client		|
	| ssl_context/3		| ssl_context/3		|
	| tcp_socket/1		| tcp_socket/1		|
	| tcp_accept/3		| tcp_connect/2		|
	| tcp_open_socket/3	| tcp_open_socket/3	|
	| ssl_negotiate/5	| ssl_negotiate/5	|

The library is abstracted to  communication   over  streams,  and is not
reliant on those  streams  being  directly   attached  to  sockets.  The
tcp_\ldots calls here are simply the most common way to use the library.
In UNIX, pipes could just as easily be used, for example.

@see library(socket), library(http/http_open)
*/

%%	ssl_context(+Role, -SSL, :Options) is det.
%
%	Create an SSL context. The defines several properties of the SSL
%	connection such as  involved  keys,   perferred  encryption  and
%	passwords. After establishing a context,   an SSL connection can
%	be negotiated using ssl_negotiate/5, turning two arbitrary plain
%	Prolog streams into encrypted streams.  This predicate processes
%	the options below. Options are marked [S] if they only apply for
%	the server role and [C] if they only apply for the client role.
%
%	  * certificate_file(+FileName)
%	  [S] Specify where the certificate file can be found. This can
%	  be the same as the key_file(+FileName) option.
%	  * key_file(+FileName)
%	  [S] Specify where the private key can be found. This can be
%	  the same as the certificate file.
%	  * password(+Text)
%	  Specify the password the private key is protected with (if
%	  any). If you do not want to store the password you can also
%	  specify an application defined handler to return the password
%	  (see next option).
%	  * pem_password_hook(:PredicateName)
%	  In case a password is required to access the private key the
%	  supplied function will be called to fetch it. The function has
%	  the following prototype: \term{function}{+SSL, -Password}
%	  * cacert_file(+FileName)
%	  Specify a file containing certificate keys which will thus
%	  automatically be verified as trusted. Using FileName
%	  `system(root_certificates)` starts an OS specific
%	  process to obtain the system's trusted root certificates.
%	  Current implementation for `system(root_certificates)`:
%
%	    - On Windows, CertOpenSystemStore() is used to import
%	      the `"ROOT"` certificates from the OS.
%	    - On MacOSX, the trusted keys are loaded from the
%	      _SystemRootCertificates_ key chain.
%	    - Otherwise, certificates are loaded from the file
%	      =/etc/ssl/certs/ca-certificates.crt=.  This
%	      location is the default on Linux.
%
%	  It is also possible to install an application defined handler
%	  for    verifying    certificates    using      the     option
%	  `cert_verify_hook`
%	  * cert_verify_hook(:CallBack)
%	  In case a certificate cannot be verified or has some
%	  properties which makes it invalid (invalid validity date for
%	  example) the supplied function will be called to ask its
%	  opinion about the certificate. The predicate is called as
%	  follows: `call(CallBack, +SSL, +ProblemCertificate,
%	  +AllCertificates, +FirstCertificate, +Error)`. Access will be
%	  granted iff the predicate succeeds. See load_certificate/2
%	  for a description of the certificate terms.  See
%	  cert_accept_any/5 for accepting any certificate.
%	  * cert(+Boolean)
%	  Trigger the sending of our certificate as specified using the
%	  option `certificate_file` described earlier. For a
%	  server this option is automatically turned on.
%	  * peer_cert(+Boolean)
%	  Trigger the request of our peer's certificate while
%	  establishing the SSL layer. This option is automatically
%	  turned on in a client SSL socket.
%	  * close_parent(+Boolean)
%	  If `true`, close the raw streams if the SSL streams are closed.
%	  * disable_ssl_methods(+List)
%	  A list of methods to disable. Unsupported methods will be
%	  ignored. Methods include `sslv2`, `sslv2`, `sslv23`,
%	  `tlsv1`, `tlsv1_1` and `tlsv1_2`.
%	  * ssl_method(+Method)
%	  Specify the explicit Method to use when negotiating. For
%	  allowed values, see the list for `disable_ssl_methods` above.
%
%
%	@arg Role is one of `server` or `client` and denotes whether the
%	SSL  instance  will  have  a  server   or  client  role  in  the
%	established connection.

ssl_context(Role, SSL, Module:Options) :-
	select_option(ssl_method(Method), Options, O1, sslv23),
	'_ssl_context'(Role, SSL, Module:O1, Method).

%%	ssl_negotiate(+SSL,
%%		      +PlainRead, +PlainWrite,
%%		      -SSLRead, -SSLWrite) is det.
%
%	Once a connection is established and a read/write stream pair is
%	available, (PlainRead and PlainWrite),  this   predicate  can be
%	called to negotiate an SSL  session   over  the  streams. If the
%	negotiation is successful, SSLRead and SSLWrite are returned.

%%	ssl_session(+Stream, -Session) is det.
%
%	Retrieves (debugging) properties from the SSL context associated
%	with Stream. If Stream  is  not   an  SSL  stream, the predicate
%	raises  a  domain  error.  Session  is  a  list  of  properties,
%	containing the members described below.   Except  for `Version`,
%	all information are byte arrays that   are represented as Prolog
%	strings holding characters in the range 0..255.
%
%	  * ssl_version(Version)
%	  The negotiated version of the session as an integer.
%	  * session_key(Key)
%	  The key material used in SSLv2 connections (if present).
%	  * master_key(Key)
%	  The key material comprising the master secret. This is
%	  generated from the server_random, client_random and pre-master
%	  key.
%	  * client_random(Random)
%	  The random data selected by the client during handshaking.
%	  * server_random(Random)
%	  The random data selected by the server during handshaking.
%	  * session_id(SessionId)
%	  The SSLv3 session ID. Note that if ECDHE is being used (which
%	  is the default for newer versions of OpenSSL), this data will
%	  not actually be sent to the server.

%%	load_certificate(+Stream, -Certificate) is det.
%
%	Loads a certificate from a PEM- or DER-encoded stream, returning
%	a term which will unify with   the same certificate if presented
%	in cert_verify_hook. A certificate  is   a  list  containing the
%	following terms: issuer_name/1, hash/1,  signature/1, version/1,
%	notbefore/1,  notafter/1,  serial/1,   subject/1    and   key/1.
%	subject/1  and  issuer_name  are  both    lists   of  =/2  terms
%	representing the name.

%%	load_crl(+Stream, -CRL) is det.
%
%	Loads a CRL from a PEM- or  DER-encoded stream, returning a term
%	containing  terms  hash/1,   signature/1,    issuer_name/1   and
%	revocations/1,  which  is  a  list   of  revoked/2  terms.  Each
%	revoked/2 term is of the form revoked(+Serial, DateOfRevocation)


/*
  These predicates are here to support backward compatability with the previous
  incarnation of the SSL library. No changes should be required for legacy code.
*/

%%	ssl_init(-SSL, +Role, +Options) is det.
%
%	Create an SSL context.  Similar to ssl_context/3.
%
%	@deprecated   New   code   should     use    ssl_context/3   and
%	ssl_negotiate/5 to realise an SSL connection.

ssl_init(SSL, Role, Options) :-
	must_be(oneof([client,server]), Role),
	ssl_init2(Role, SSL, Options).

ssl_init2(server, SSL, Options) :-
	Options = _:Options1,
	option(port(Port), Options1),
        tcp_socket(Socket),
	tcp_setopt(Socket, reuseaddr),
        tcp_bind(Socket, Port),
        tcp_listen(Socket, 5),
        catch(ssl_context(server, SSL, Options),
              Exception,
              ( tcp_close_socket(Socket),
                throw(Exception))),
        Socket = '$socket'(S),
        ssl_put_socket(SSL, S).
ssl_init2(client, SSL, Options) :-
	Options = _:Options1,
        option(port(Port), Options1),
        option(host(Host), Options1),
        tcp_socket(Socket),
	tcp_setopt(Socket, reuseaddr),
        tcp_connect(Socket, Host:Port),
        catch(ssl_context(client, SSL, Options),
              Exception,
              ( tcp_close_socket(Socket),
                throw(Exception))),
        Socket = '$socket'(S),
        ssl_put_socket(SSL, S).


%%	ssl_accept(+SSL, -Socket, -Peer) is det.
%
%	(Server) Blocks until a connection is made   to  the host on the
%	port specified by the  SSL  object.   Socket  and  Peer are then
%	returned.
%
%	@deprecated   New   code    should     use    tcp_accept/3   and
%	ssl_negotiate/5.

ssl_accept(SSL, Socket, Peer) :-
        ssl_get_socket(SSL, S),
        tcp_accept('$socket'(S), Socket, Peer).

%%	ssl_open(+SSL, -Read, -Write) is det.
%
%	(Client) Connect to the  host  and   port  specified  by the SSL
%	object, negotiate an SSL connection and   return  Read and Write
%	streams if successful.
%
%	@deprecated New code should use ssl_negotiate/5.

ssl_open(SSL, In, Out) :-
        ssl_get_socket(SSL, S),
        tcp_open_socket('$socket'(S), Read, Write),
        ssl_negotiate(SSL, Read, Write, In, Out).

%%	ssl_open(+SSL, +Socket, -Read, -Write) is det.
%
%	Given the Socket  returned  from   ssl_accept/3,  negotiate  the
%	connection on the accepted socket  and   return  Read  and Write
%	streams if successful.
%
%	@deprecated New code should use ssl_negotiate/5.

ssl_open(SSL, Socket, In, Out):-
        tcp_open_socket(Socket, Read, Write),
        ssl_negotiate(SSL, Read, Write, In, Out).

%%	cert_accept_any(+SSL,
%%			+ProblemCertificate, +AllCertificates, +FirstCertificate,
%%			+Error) is det.
%
%	Implementation  for  the  hook   `cert_verify_hook(:Hook)`  that
%	accepts _any_ certificate. This is   intended for http_open/3 if
%	no certificate verification is desired as illustrated below.
%
%	  ==
%	    http_open('https:/...', In,
%	              [ cert_verify_hook(cert_accept_any)
%	              ])
%	  ==

cert_accept_any(_SSL,
		_ProblemCertificate, _AllCertificates, _FirstCertificate,
		_Error).
