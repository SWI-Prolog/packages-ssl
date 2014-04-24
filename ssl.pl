/*  Part of SWI-Prolog

    Author:        Jan van der Steen, Matt Lilley and Jan Wielemaker,
    E-mail:        J.Wielemaker@vu.nl
    WWW:           http://www.swi-prolog.org
    Copyright (C): 2004-2014, SWI-Prolog Foundation
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
		     [ host(atom),
		       port(integer),
		       certificate_file(atom),
		       key_file(atom),
		       password(any),
		       pem_password_hook(callable),
		       cacert_file(atom),
		       cert_verify_hook(callable),
		       cert(boolean),
		       peer_cert(boolean),
		       close_parent(boolean)
		     ]).
:- predicate_options(ssl_init/3, 3, [pass_to(ssl_context/3, 3)]).

/** <module> Secure Socket Layer library
*/

ssl_context(Role, SSL, Options) :-	% Prolog to exploit meta-predicate
	'_ssl_context'(Role, SSL, Options).

/*
  These predicates are here to support backward compatability with the previous
  incarnation of the SSL library. No changes should be required for legacy code.
*/

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


ssl_accept(SSL, Socket, Peer):-
        ssl_get_socket(SSL, S),
        tcp_accept('$socket'(S), Socket, Peer).

ssl_open(SSL, Socket, In, Out):-
        tcp_open_socket(Socket, Read, Write),
        ssl_negotiate(SSL, Read, Write, In, Out).

ssl_open(SSL, In, Out):-
        ssl_get_socket(SSL, S),
        tcp_open_socket('$socket'(S), Read, Write),
        ssl_negotiate(SSL, Read, Write, In, Out).
