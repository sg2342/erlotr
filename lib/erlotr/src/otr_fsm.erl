%%
%% Purpose: Off-the-Record Messaging
%%          (http://www.cypherpunks.ca/otr/Protocol-v2-3.1.0.html)
%%          message state machine
%%

-module(otr_fsm).

-author("Stefan Grundmann <sg2342@googlemail.com>").

-copyright("Copyright 2009 Stefan Grundmann").

-include("otr_internal.hrl").

-include("otr.hrl").

% gen_fsm callbacks
-export([code_change/4, handle_event/3, handle_info/3,
	 handle_sync_event/4, init/1, terminate/3]).

% states
-export([encrypted/2, finished/2, plaintext/2]).

% api
-export([consume/2, start_link/1]).

-record(s,
	{emit_user, emit_net, require_encryption,
	 whitespace_start_ake, error_start_ake, 
	 max_fragment_size, send_whitespace_tag, 
	 got_plaintext = false, pt = [], ake, ssid, dsa,
	 mcgs,
	 their_dsa_fp
	}). 

start_link(Opts) ->
    gen_fsm:start_link(?MODULE, Opts, []).

consume(Pid, M) -> gen_fsm:send_event(Pid, M).

%F{{{ states
plaintext({ake, {encrypted, TheirKM}},
	  #s{pt = PT} = State) ->
    NState = ake_completed(State, TheirKM),
    lists:foreach(fun(M) -> send_data_msg(NState, M) end, PT),
    {next_state, encrypted, NState#s{pt = []}};
%F{{{ plaintext({user ....
plaintext({user, start_otr}, State) ->
    emit_net(State, otr_msg_query),
    {next_state, plaintext, State};
plaintext({user, stop_otr}, State) ->
    {next_state, plaintext, State};
plaintext({user, {message, M}},
	  #s{require_encryption = true} = State) ->
    emit_net(State, otr_msg_query),
    {next_state, plaintext, State#s{pt = [M | State#s.pt]}};
plaintext({user, {message, M}},
	  #s{send_whitespace_tag = true} = State) ->
    emit_net(State, #otr_msg_tagged_ws{s = M}),
    {next_state, plaintext, State};
plaintext({user, {message, M}}, State) ->
    emit_net(State, {plain, M}),
    {next_state, plaintext, State};%}}}F
%F{{{ plaintext({net
plaintext({net, {plain, M}}, State) ->
    emit_user(State, {message, M, []}),
    {next_state, plaintext, State};
plaintext({net, #otr_msg_tagged_ws{s = M}}, State) ->
    emit_user(State, {message, M}),
    {ok, Ake} = init_ake(State),
    otr_ake_fsm:consume(Ake, {cmd, start}),
    {next_state, plaintext, State#s{ake = Ake}};
plaintext({net, #otr_msg_error{s = M}},
	  #s{error_start_ake = true} = State) ->
    emit_net(State, otr_msg_query),
    emit_user(State, {error_net, M}),
    {next_state, plaintext, State};
plaintext({net, #otr_msg_error{s = M}}, State) ->
    emit_user(State, {error_net, M}),
    {next_state, plaintext, State};
plaintext({net, #otr_msg_data{}}, State) ->
    emit_user(State,
	      {error, unreadable_encrypted_received}),
    emit_net(State,
	     #otr_msg_error{s = ?OTRL_ERRCODE_MSG_NOT_IN_PRIVATE}),
    {next_state, plaintext, State};
plaintext({net, M}, State) ->
    handle_ake_message(M, plaintext, State).  %}}}F

encrypted({ake, {encrypted, TheirKM}}, State) ->
    {next_state, encrypted, ake_completed(State, TheirKM)};
%F{{{ encrypted({user
encrypted({user, start_otr}, State) ->
    emit_net(State, otr_msg_query),
    {next_state, encrypted, State};
encrypted({user, stop_otr}, State) ->
    %TODO: Send a Data Message, encoding a message with an empty hunamn-readable part and TLV type 1
    {next_state, plaintext, State};
encrypted({user, {message, M}}, State) ->
    ok = send_data_msg(State, M),
    %TODO: Encrypt the message and send it as data message, store the plaintext for possible retransmission
    {next_state, encrypted, State};  %}}}F
%F{{{ encrypted({net
encrypted({net, {plain, M}}, State) ->
    emit_user(State, {message, M, [warning_unencrypted]}),
    {next_state, encrypted, State};
encrypted({net, #otr_msg_tagged_ws{s = M}},
	  #s{whitespace_start_ake = true} = State) ->
    emit_user(State, {message, M, [warning_unencrypted]}),
    {ok, Ake} = init_ake(State),
    otr_ake_fsm:consume(Ake, {cmd, start}),
    {next_state, encrypted, State#s{ake = Ake}};
encrypted({net, #otr_msg_tagged_ws{s = M}}, State) ->
    emit_user(State, {message, M, [warning_unencrypted]}),
    {next_state, encrypted, State};
encrypted({net, #otr_msg_error{s = M}}, State) ->
    emit_user(State, {error_net, M}),
    State#s.error_start_ake andalso
      emit_net(State, otr_msg_query),
    {next_state, encrypted, State};
encrypted({net, #otr_msg_data{} = M}, State) ->
    recv_data_msg(State, M),
    {next_state, encrypted, State};
encrypted({net, M}, State) ->
    handle_ake_message(M, encrypted, State).%}}}F

finished({ake, {encrypted, TheirKM}}, State) ->
    {next_state, encrypted, ake_completed(State, TheirKM)};
%F{{{ finished({user ...
finished({user, start_otr}, State) ->
    emit_net(State, otr_msg_query),
    {next_state, encrypted, State};
finished({user, stop_otr}, State) ->
    {next_state, plaintext, State#s{got_plaintext = false}};
finished({user, {message, M}}, State) ->
    emit_user(State,
	      {info, message_can_not_be_sent_this_time}),
    {next_state, finished,
     State#s{pt = [M | State#s.pt]}};  %}}}F
%F{{{ finished({net
finished({net, {plain, M}}, State) ->
    emit_user(State, {message, M, [warning_unencrypted]}),
    {next_state, finished, State};
finished({net, #otr_msg_tagged_ws{s = M}},
	 #s{whitespace_start_ake = true} = State) ->
    emit_user(State, {message, M, [warning_unencrypted]}),
    {ok, Ake} = init_ake(State),
    otr_ake_fsm:consume(Ake, {cmd, start}),
    {next_state, finished, State#s{ake = Ake}};
finished({net, #otr_msg_tagged_ws{s = M}}, State) ->
    emit_user(State, {message, M, [warning_unencrypted]}),
    {next_state, finished, State};
finished({net, #otr_msg_error{s = M}}, State) ->
    emit_user(State, {error_net, M}),
    State#s.error_start_ake andalso
      emit_net(State, otr_msg_query),
    {next_state, finished, State};
finished({net, #otr_msg_data{}}, State) ->
    emit_user(State,
	      {error, unreadable_encrypted_received}),
    emit_net(State,
	     #otr_msg_error{s = ?OTRL_ERRCODE_MSG_NOT_IN_PRIVATE}),
    {next_state, finished, State};
finished({net, M}, State) ->
    handle_ake_message(M, finished, State).%}}}F

%}}}F

%F{{{ gen_fsm callbacks

init(Opts) ->
    State = #s{emit_user = proplists:get_value(emit_user, Opts),
       emit_net = proplists:get_value(emit_net, Opts),
       require_encryption =
	   proplists:get_bool(require_encryption, Opts),
       whitespace_start_ake =
	   proplists:get_bool(whitespace_start_ake, Opts),
       error_start_ake =
	   proplists:get_bool(error_start_ake, Opts),
       send_whitespace_tag =
	   proplists:get_bool(send_whitespace_tag, Opts),
       dsa = 
	   proplists:get_value(dsa, Opts),
       max_fragment_size =
	   proplists:get_value(max_fragment_size, Opts,
			       ?DEFAULT_MAX_FRAG_SIZE)},
    {ok, Mcgs} = otr_mcgs:start_link(),
    {ok, plaintext, State#s{mcgs = Mcgs}}.

handle_info(Info, StateName, StateData) ->
    {stop, {StateName, undefined_info, Info}, StateData}.

handle_event({ake_to_net, M}, StateName, State) ->
    emit_net(State, M), {next_state, StateName, State};
handle_event(Event, StateName, StateData) ->
    {stop, {StateName, undefined_event, Event}, StateData}.

handle_sync_event(Event, _From, StateName, StateData) ->
    {stop, {StateName, undefined_sync_event, Event},
     StateData}.

terminate(_Reason, _StateName, _State) -> ok.

code_change(_OldVsn, StateName, StateData, _Extra) ->
    {ok, StateName, StateData}.

%}}}F

%F{{{ internal functions

send_data_msg(State, M) ->
    {ok, EncM} = otr_mcgs:encrypt(State#s.mcgs, M),
    emit_net(State, EncM),
    ok.

recv_data_msg(State, M) ->
    case otr_mcgs:decrypt(State#s.mcgs, M) of
	{ok, {DecM, TLV}} -> emit_user(State, {message, DecM}); %TODO : tlv
	{rejected, _ } -> emit_net(State, #otr_msg_error{s = "Foo"})
    end.

%F{{{ handle_ake_message/3
handle_ake_message(otr_msg_query, StateName, State) ->
    {ok, Ake} = init_ake(State),
    otr_ake_fsm:consume(Ake, {cmd, start}),
    {next_state, StateName, State#s{ake = Ake}};
handle_ake_message(#otr_msg_dh_commit{} = M, StateName,
		   State) ->
    {ok, Ake} = init_ake(State),
    otr_ake_fsm:consume(Ake, M),
    {next_state, StateName, State#s{ake = Ake}};
handle_ake_message(#otr_msg_dh_key{}, StateName,
		   #s{ake = undefined} = State) ->
    {next_state, StateName, State};
handle_ake_message(#otr_msg_dh_key{} = M, StateName,
		   #s{ake = Ake} = State) ->
    otr_ake_fsm:consume(Ake, M),
    {next_state, StateName, State#s{ake = Ake}};
handle_ake_message(#otr_msg_reveal_signature{},
		   StateName, #s{ake = undefined} = State) ->
    {next_state, StateName, State};
handle_ake_message(#otr_msg_reveal_signature{} = M,
		   StateName, #s{ake = Ake} = State) ->
    otr_ake_fsm:consume(Ake, M),
    {next_state, StateName, State#s{ake = Ake}};
handle_ake_message(#otr_msg_signature{}, StateName,
		   #s{ake = undefined} = State) ->
    {next_state, StateName, State};
handle_ake_message(#otr_msg_signature{} = M, StateName,
		   #s{ake = Ake} = State) ->
    otr_ake_fsm:consume(Ake, M),
    {next_state, StateName, State#s{ake = Ake}}.%}}}F

ake_completed(#s{mcgs = Mcgs, ake = Ake} = State,
	    {OurKeyId, OurKey, TheirKeyId, Y, FP, SSID}) ->
    unlink(Ake),
    exit(Ake, shutdown),
    case State#s.their_dsa_fp of
      undefined ->
	  emit_user(State,
		    {info, {encrypted_new_dsa_fp, FP, SSID}});
      FP -> emit_user(State, {info, {encrypted, SSID}});
      _ ->
	  emit_user(State,
		    {info, {encrypted_changed_dsa_fp, FP, SSID}})
    end,
    ok = otr_mcgs:set_keys(Mcgs, {OurKeyId, OurKey, TheirKeyId, Y}),
    State#s{ake = undefined, ssid = SSID, their_dsa_fp = FP}.


init_ake(#s{ake = undefined, mcgs = Mcgs, dsa = DSA}) ->
    {ok, {KeyId, DhKey}} = otr_mcgs:get_key(Mcgs),
    Self = self(),
    EmitToFsm = fun (X) -> otr_fsm:consume(Self, {ake, X})
		end,
    EmitToNet = fun (X) ->
			gen_fsm:send_all_state_event(Self, {ake_to_net, X})
		end,
    otr_ake_fsm:start_link(KeyId, DhKey, DSA, EmitToFsm,
			   EmitToNet);
init_ake(#s{ake = Ake}) -> {ok, Ake}.

emit_user(#s{emit_user = F, require_encryption = true},
	  {message, M}) ->
    F({message, M, [warning_unencrypted]});
emit_user(#s{emit_user = F}, M) -> F(M).

emit_net(#s{emit_net = F, max_fragment_size = FSz},
	 M) ->
    case otr_message:encode(M, FSz) of
      {ok, Data} -> F(Data);
      {fragmented, FL} -> lists:foreach(F, FL)
    end.


%}}}F

