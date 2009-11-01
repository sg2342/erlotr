-module(otr_parser_fsm).

-author("Stefan Grundmann <sg2342@googlemail.com>").

-include("otr.hrl").

% gen_fsm callbacks
-export([code_change/4, handle_event/3, handle_info/3,
	 handle_sync_event/4, init/1, terminate/3]).

% states
-export([idle/2, need_more_fragments/2]).

% api
-export([consume/2, set_emit_fun/2, start_link/0]).

-record(s, {emit, frag}).

start_link() -> gen_fsm:start_link(?MODULE, [], []).

set_emit_fun(Pid, Emit) ->
    gen_fsm:sync_send_all_state_event(Pid,
				      {set_emit_fun, Emit}).

consume(Pid, M) -> gen_fsm:send_event(Pid, M).

%F{{{ fsm states
idle(Message, State) ->
    case parse_emit(Message, State#s.emit) of
      #otr_msg_fragment{k = 1, n = N} = F when N > 1 ->
	  {next_state, need_more_fragments, State#s{frag = F}};
      _ -> {next_state, idle, State}
    end.

need_more_fragments(Message, State) ->
    #otr_msg_fragment{k = Ks, n = Ns, f = Fs} =
	State#s.frag,
    K = Ks + 1,
    case parse_emit(Message, State#s.emit) of
      #otr_msg_fragment{k = 1, n = N} = F when N > 1 ->
	  {next_state, need_more_fragments, State#s{frag = F}};
      #otr_msg_fragment{k = Ns, n = Ns} = F
	  when Ns == K ->
	  parse_emit_fragmented(Fs ++ F#otr_msg_fragment.f,
				State#s.emit),
	  {next_state, idle, State#s{frag = undefined}};
      #otr_msg_fragment{k = K, n = Ns} = F ->
	  NewFrag = F#otr_msg_fragment{f =
					   Fs ++ F#otr_msg_fragment.f},
	  {next_state, need_more_fragments,
	   State#s{frag = NewFrag}};
      _ -> {next_state, idle, State#s{frag = undefined}}
    end.

%}}}F

%F{{{ gen_fsm callbacks

init([]) -> {ok, wait_emit_fun, #s{}}.

handle_info(Info, StateName, StateData) ->
    {stop, {StateName, undefined_info, Info}, StateData}.

handle_event(Event, StateName, StateData) ->
    {stop, {StateName, undefined_event, Event}, StateData}.

handle_sync_event({set_emit_fun, Emit}, _From,
		  wait_emit_fun, _) ->
    {reply, ok, idle, #s{emit = Emit}};
handle_sync_event(Event, _From, StateName, StateData) ->
    {stop, {StateName, undefined_sync_event, Event},
     StateData}.

terminate(_Reason, _StateName, _State) -> ok.

code_change(_OldVsn, StateName, StateData, _Extra) ->
    {ok, StateName, StateData}.

%}}}F

%F{{{ internal functions

parse_emit_fragmented(Message, Emit) ->
    case otr_message:parse(Message) of
      {ok, #otr_msg_fragment{}} ->
      Emit({error, fragmented_fragment});
      plain -> Emit({error, fragmented_plain});
      {error, E} ->  Emit({error, E});
      {ok, OtrMsg} -> Emit(OtrMsg)
    end.

parse_emit(Message, Emit) ->
    case otr_message:parse(Message) of
      {ok, #otr_msg_fragment{} = F} -> F;
      plain -> Emit({plain, Message});
      {ok, OtrMsg} -> Emit(OtrMsg);
      {error, E} -> Emit({error, E})
    end.

%}}}

