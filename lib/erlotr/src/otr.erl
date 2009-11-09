%%
%% Purpose: Off-the-Record Messaging
%%          (http://www.cypherpunks.ca/otr/Protocol-v2-3.1.0.html)
%%          interface module
%%

-module(otr).

-author("Stefan Grundmann <sg2342@googlemail.com>").

-copyright("Copyright 2009 Stefan Grundmann").

-export([create_context/1, start/0]).

start() ->
    application:start(crypto),
    application:start(erlotr).

create_context(Opts) ->
    {ok, Supervisor, Parser, Fsm} = otr_ctx_sup:start(Opts),
    CF = fun (M) ->
		 case is_process_alive(Supervisor) of
		   false -> erlang:error(noproc);
		   true ->
		       case M of
			 {user, stop_otr} -> otr_fsm:consume(Fsm, M);
			 {user, start_otr} -> otr_fsm:consume(Fsm, M);
			 {user, {message, _}} -> otr_fsm:consume(Fsm, M);
			 {control, stop} -> otr_ctx_sup:stop(Supervisor);
			 {net, S} -> otr_parser_fsm:consume(Parser, S);
			 {smp, _Cmd} -> erlang:error(not_implemented);
			 _ -> erlang:error({unknown_command, M})
		       end
		 end
	 end,
    {ok, CF}.
