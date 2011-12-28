%%
%% %CopyrightBegin%
%%
%% Copyright Ericsson AB 1999-2011. All Rights Reserved.
%%
%% The contents of this file are subject to the Erlang Public License,
%% Version 1.1, (the "License"); you may not use this file except in
%% compliance with the License. You should have received a copy of the
%% Erlang Public License along with this software. If not, it can be
%% retrieved online at http://www.erlang.org/.
%%
%% Software distributed under the License is distributed on an "AS IS"
%% basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See
%% the License for the specific language governing rights and limitations
%% under the License.
%%
%% %CopyrightEnd%
%%

%%
%% copied from OTP R15B lib/crypto/src/crypto.erl 
%%

-module(crypto_aux).

-export([start/0, stop/0]).

-export([sha256/1, sha256_init/0, sha256_update/2, sha256_final/1]).

-define(nif_stub,nif_stub_error(?LINE)).

-on_load(on_load/0).

start() ->
    application:start(crypto_aux).

stop() ->
    application:stop(crypto_aux).

%
%% SHA256
%%
-spec sha256(iodata()) -> binary().
-spec sha256_init() -> binary().
-spec sha256_update(binary(), iodata()) -> binary().
-spec sha256_final(binary()) -> binary().

sha256(Data) ->
    case sha256_nif(Data) of
	notsup -> erlang:error(notsup);
	Bin -> Bin
    end.
sha256_init() ->
    case sha256_init_nif() of
	notsup -> erlang:error(notsup);
	Bin -> Bin
    end.
sha256_update(Context, Data) ->
    case sha256_update_nif(Context, Data) of
	notsup -> erlang:error(notsup);
	Bin -> Bin
    end.
sha256_final(Context) ->
    case sha256_final_nif(Context) of
	notsup -> erlang:error(notsup);
	Bin -> Bin
    end.

sha256_nif(_Data) -> ?nif_stub.
sha256_init_nif() -> ?nif_stub.
sha256_update_nif(_Context, _Data) -> ?nif_stub.
sha256_final_nif(_Context) -> ?nif_stub.

-define(CRYPTO_NIF_VSN,0).

on_load() ->
    LibBaseName = "crypto_aux",
    PrivDir = code:priv_dir(crypto_aux),
    LibName = case erlang:system_info(build_type) of
		  opt ->
		      LibBaseName;
		  Type ->
		      LibTypeName = LibBaseName ++ "."  ++ atom_to_list(Type),
		      case (filelib:wildcard(
			      filename:join(
				[PrivDir,
				 "lib",
				 LibTypeName ++ "*"])) /= []) orelse
			  (filelib:wildcard(
			     filename:join(
			       [PrivDir,
				"lib", 
				erlang:system_info(system_architecture),
				LibTypeName ++ "*"])) /= []) of
			  true -> LibTypeName;
			  false -> LibBaseName
		      end
	      end,
    Lib = filename:join([PrivDir, "lib", LibName]),
    io:format("~n~n~n~p~n~n~n", [Lib]),
    Status = case erlang:load_nif(Lib, ?CRYPTO_NIF_VSN) of
		 ok -> ok;
		 {error, {load_failed, _}}=Error1 ->
		     ArchLibDir = 
			 filename:join([PrivDir, "lib", 
					erlang:system_info(system_architecture)]),
		     Candidate =
			 filelib:wildcard(filename:join([ArchLibDir,LibName ++ "*" ])),
		     case Candidate of
			 [] -> Error1;
			 _ ->
			     ArchLib = filename:join([ArchLibDir, LibName]),
			     erlang:load_nif(ArchLib, ?CRYPTO_NIF_VSN)
		     end;
		 Error1 -> Error1
	     end,
    case Status of
	ok -> ok;
	{error, {E, Str}} ->
	    error_logger:error_msg("Unable to load crypto_aux library. Failed with error:~n\"~p, ~s\"~n"
				   "OpenSSL might not be installed on this system.~n",[E,Str]),
	    Status
    end.

nif_stub_error(Line) ->
    erlang:nif_error({nif_not_loaded,module,?MODULE,line,Line}).
