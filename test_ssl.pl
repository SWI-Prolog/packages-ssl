/*  $Id$

    Part of SWI-Prolog

    Author:        Jan Wielemaker
    E-mail:        jan@swi.psy.uva.nl
    WWW:           http://www.swi-prolog.org
    Copyright (C): 1985-2004, University of Amsterdam

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

/* doesn't work when called from ../swipl.sh??
:- module(test_ssl,
	  [ test_ssl/0,
	    test_ssl/1,
	    ssl_server/0
	  ]).
*/

:- asserta(user:file_search_path(library, '.')).
:- asserta(user:file_search_path(library, '../clib')).
:- asserta(user:file_search_path(foreign, '.')).
:- asserta(user:file_search_path(foreign, '../clib')).

:- use_module(library(ssl)).
:- use_module(library(debug)).
:- use_module(library(readutil)).

%:- debug(connection).
%:- debug(data).
%:- debug(_).

:- dynamic
	option/1,			% Options to test
	copy_error/1.

test_ssl :-
	make_server(SSL),
	thread_create(server_loop(SSL), Id, []),
	client,
	thread_join(Id, Status),
	Status == true.

test_ssl(N) :-
	(   between(1, N, _),
	    test_ssl,
	    put('.'), flush_output,
	    fail
	;   true
	).

ssl_server :-
	make_server(SSL),
        server_loop(SSL).

		 /*******************************
		 *	       SERVER		*
		 *******************************/

:- dynamic
	stop_server/0.

make_server(SSL) :-
	ssl_init(SSL, server,
		 [ host('localhost'),
                   port(1111),
                   cert(true),
                   peer_cert(true),
		   cacert_file('etc/demoCA/cacert.pem'),
		   certificate_file('etc/server/server-cert.pem'),
		   key_file('etc/server/server-key.pem'),
		   cert_verify_hook(get_cert_verify),
%		   password('apenoot1'),
		   pem_password_hook(get_server_pwd)
		 ]).

server_loop(SSL) :-
	ssl_accept(SSL, Socket, Peer),
	debug(connection, 'Connection from ~p', [Peer]),
	ssl_open(SSL, Socket, In, Out),
	(   option(timeout(T))
	->  set_stream(In, timeout(T))
	;   true
	),
	catch(copy_client(In, Out), E,
	      assert(copy_error(E))),
	close(In),
	close(Out),
	(   retract(stop_server)
	->  ssl_exit(SSL)
	;   server_loop(SSL)
	).

copy_client(In, Out) :-
	read_line_to_codes(In, Line),
	(   Line == end_of_file
	->  true
	;   debug(data, 'SERVER: Got ~s~n', [Line]),
	    sleep(1.5),
	    debug(data, 'SERVER: writing ~s~n', [Line]),
	    format(Out, '~s~n', [Line]),
	    flush_output(Out),
	    (	atom_codes(bye, Line)
	    ->	assert(stop_server)
	    ;	true
	    ),
	    copy_client(In, Out)
	).

get_server_pwd(_SSL, apenoot1) :-
	debug(passwd, 'Returning password from server passwd hook', []).

get_cert_verify(_SSL, Certificate, Error) :-
	debug(certificate,
	      'Certificate: ~w, error: ~w', [Certificate, Error]).


		 /*******************************
		 *	       CLIENT		*
		 *******************************/

client :-
	ssl_init(SSL, client,
		 [ host('localhost'),
                   port(1111),
		   cert(true),
		   peer_cert(true),
		   cacert_file('etc/demoCA/cacert.pem'),
		   certificate_file('etc/client/client-cert.pem'),
		   key_file('etc/client/client-key.pem'),
%		   password('apenoot2'),
		   pem_password_hook(get_client_pwd)
		 ]),
	client_loop(SSL),
        ssl_exit(SSL).

client_loop(SSL) :-
	ssl_open(SSL, In, Out),
        set_stream(In, timeout(1)),
	Message = 'Hello world',
	write_server(Message, In, Out),
	(   option(timeout(T))
	->  Wait is T*2,
	    sleep(Wait)
	;   true
	),
	write_server(bye, In, Out),
	close(In),
	close(Out).

write_server(Message, In, Out) :-
	debug(data, 'CLIENT: writing: ~q~n', [Message]),
	write(Out, Message), nl(Out),
	flush_output(Out),
	sleep(0.1),
	catch(read_from_server(In, Message),
	      E,
	      debug(data, 'CLIENT: exception: ~q~n', [E])),
	(   var(E)
	->  true
	;   read_from_server(In, Message)
        ).

read_from_server(In, Message) :-
	debug(data, 'CLIENT: attempting to read reply from stream~n', []),
	read_line_to_codes(In, Line),
	(   Line == end_of_file
	->  true
	;   atom_codes(Reply, Line),
	    debug(data, 'CLIENT: Got ~q~n', [Reply]),
	    (	Reply == Message
	    ->	true
	    ;	format(user_error, 'CLIENT: ERROR: Sent ~q, Got ~q~n',
		       [Message, Reply])
	    )
	).

user:get_client_pwd(_SSL, apenoot2) :-
	debug(passwd, 'Returning password from client passwd hook', []).
