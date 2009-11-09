%%
%% Purpose: Off-the-Record Messaging
%%          (http://www.cypherpunks.ca/otr/Protocol-v2-3.1.0.html)
%%          otr cotext supervisor
%%

-module(otr_ctx_sup).

-author("Stefan Grundmann <sg2342@googlemail.com>").

-copyright("Copyright 2009 Stefan Grundmann").

-behaviour(supervisor).

-export([init/1, start_link/1]).

-export([start/1, stop/1]).

start(Args) ->
    {ok, Pid} = otr_sup:start_child(Args),
    CL = supervisor:which_children(Pid),
    {otr_fsm, FsmPid, _, _} = lists:keyfind(otr_fsm, 1, CL),
    {otr_parser_fsm, ParserPid, _, _} =
	lists:keyfind(otr_parser_fsm, 1, CL),
    EmitFun = fun (M) ->
		      otr_fsm:consume(FsmPid, {net, M})
	      end,
    ok = otr_parser_fsm:set_emit_fun(ParserPid, EmitFun),

    {ok, Pid, ParserPid, FsmPid}.

stop(Pid) -> otr_sup:stop_child(Pid).

start_link(Args) ->
    supervisor:start_link(?MODULE, [Args]).

init([Args]) ->
    Parser = {otr_parser_fsm,
	      {otr_parser_fsm, start_link, []}, permanent, 5000,
	      worker, [otr_parser_fsm]},
    Fsm = {otr_fsm, {otr_fsm, start_link, [Args]},
	   permanent, 5000, worker, [otr_fsm]},
    {ok, {{one_for_all, 0, 1}, [Parser, Fsm]}}.
