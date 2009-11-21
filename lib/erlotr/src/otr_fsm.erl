%%
%% Purpose: Off-the-Record Messaging
%%          (http://www.cypherpunks.ca/otr/Protocol-v2-3.1.0.html)
%%          message state machine
%%

-module(otr_fsm).

-author("Stefan Grundmann <sg2342@googlemail.com>").

-copyright("Copyright 2009 Stefan Grundmann").

-include("otr_internal.hrl").

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
	 got_plaintext = false, pt = [], ake, smp, ssid, dsa,
	 mcgs, heartbeat_timeout, last_data_msg, their_dsa_fp,
	 min_enc_size}).

start_link(Opts) ->
    gen_fsm:start_link(?MODULE, Opts, []).

consume(Pid, M) -> gen_fsm:send_event(Pid, M).

%F{{{ states
plaintext({ake, {encrypted, TheirKM}},
	  #s{pt = PT} = State) ->
    NState = ake_completed(State, TheirKM),
    lists:foreach(fun (M) ->
			  send_data_msg(NState, {M, [], 0})
		  end,
		  lists:reverse(PT)),
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
plaintext({net, #otr_msg_error{s = M}}, State) ->
    handle_error_message(plaintext, State, M);
plaintext({net, #otr_msg_tagged_ws{s = M}}, State) ->
    handle_tagged_ws_message(plaintext, State, M);
plaintext({net, #otr_msg_data{}}, State) ->
    emit_user(State,
	      {error, unreadable_encrypted_received}),
    emit_net(State,
	     #otr_msg_error{s = ?ERR_MSG_UNEXPECTED}),
    {next_state, plaintext, State};
plaintext({net, {error, {encoded_m, _}}}, State) ->
    emit_user(State, {error, malformed_message_received}),
    {next_state, plaintext, State};
plaintext({net, M}, State) ->
    handle_ake_message(M, plaintext, State).  %}}}F

encrypted({ake, {encrypted, TheirKM}}, State) ->
    {next_state, encrypted, ake_completed(State, TheirKM)};
%F{{{ encrypted({smp...
encrypted({smp, user_abort}, State) ->
    {ok, {emit, E}} = otr_smp_fsm:user_abort(State#s.smp),
    {next_state, encrypted,
     send_data_msg(State, {[], E, 0})};
encrypted({smp, {user_start, Question, Answer}},
	  State) ->
    case otr_smp_fsm:user_start(State#s.smp, list_to_binary(Question),
				list_to_binary(Answer))
	of
      {error, smp_underway} -> {smp, {error, smp_underway}};
      {ok, {emit, E}} ->
	  {next_state, encrypted,
	   send_data_msg(State, {[], E, 0})}
    end;
encrypted({smp, {user_start, Secret}}, State) ->
    case otr_smp_fsm:user_start(State#s.smp, list_to_binary(Secret)) of
      {error, smp_underway} -> {smp, {error, smp_underway}};
      {ok, {emit, E}} ->
	  {next_state, encrypted,
	   send_data_msg(State, {[], E, 0})}
    end;
encrypted({smp, {user_secret, Secret}},
	  #s{smp = Smp} = State) ->
    case otr_smp_fsm:user_secret(Smp,
				 list_to_binary(Secret))
	of
      {error, unexpected_user_secret} ->
	  emit_user(State,
		    {smp, {error, unexpected_user_secret}}),
	  {next_state, encrypted, State};
      {ok, {emit, E}} ->
	  {next_state, encrypted,
	   send_data_msg(State, {[], E, 0})}
    end;
%}}}F
%F{{{ encrypted({user
encrypted({user, start_otr}, State) ->
    emit_net(State, otr_msg_query),
    {next_state, encrypted, State};
encrypted({user, stop_otr}, State) ->
    {next_state, plaintext,
     send_data_msg(State, {[], [disconnected], 1})};
encrypted({user, {message, M}}, State) ->
    NState = send_data_msg(State, {M, [], 0}),
    %TODO: store the plaintext for possible retransmission
    {next_state, encrypted, NState};  %}}}F
%F{{{ encrypted({net
encrypted({net, {error, {encoded_m, _}}}, State) ->
    emit_user(State, {error, malformed_message_received}),
    {next_state, encrypted, State};
encrypted({net, {plain, M}}, State) ->
    emit_user(State, {message, M, [warning_unencrypted]}),
    {next_state, encrypted, State};
encrypted({net, #otr_msg_tagged_ws{s = M}}, State) ->
    handle_tagged_ws_message(encrypted, State, M);
encrypted({net, #otr_msg_error{s = M}}, State) ->
    handle_error_message(encrypted, State, M);
encrypted({net, #otr_msg_data{} = M}, State) ->
    NState = heartbeat(State),
    handle_data_message(NState, M);
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
finished({net, {error, {encoded_m, _}}}, State) ->
    emit_user(State, {error, malformed_message_received}),
    {next_state, finished, State};
finished({net, {plain, M}}, State) ->
    emit_user(State, {message, M, [warning_unencrypted]}),
    {next_state, finished, State};
finished({net, #otr_msg_tagged_ws{s = M}}, State) ->
    handle_tagged_ws_message(finished, State, M);
finished({net, #otr_msg_error{s = M}}, State) ->
    handle_error_message(finished, State, M);
finished({net, #otr_msg_data{}}, State) ->
    emit_user(State,
	      {error, unreadable_encrypted_received}),
    emit_net(State,
	     #otr_msg_error{s = ?ERR_MSG_UNEXPECTED}),
    {next_state, finished, State};
finished({net, M}, State) ->
    handle_ake_message(M, finished, State).%}}}F

%}}}F

%F{{{ gen_fsm callbacks

init(Opts) ->
    State = #s{emit_user =
		   proplists:get_value(emit_user, Opts),
	       emit_net = proplists:get_value(emit_net, Opts),
	       require_encryption =
		   proplists:get_bool(require_encryption, Opts),
	       whitespace_start_ake =
		   proplists:get_bool(whitespace_start_ake, Opts),
	       error_start_ake =
		   proplists:get_bool(error_start_ake, Opts),
	       send_whitespace_tag =
		   proplists:get_bool(send_whitespace_tag, Opts),
	       dsa = proplists:get_value(dsa, Opts),
	       max_fragment_size =
		   proplists:get_value(max_fragment_size, Opts,
				       ?DEFAULT_MAX_FRAG_SIZE),
	       min_enc_size =
		   proplists:get_value(min_enc_size, Opts, 0),
	       heartbeat_timeout =
		   proplists:get_value(heartbeat_timeout, Opts, infinity)},
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

handle_data_message(State, M) ->
    case otr_mcgs:decrypt(State#s.mcgs, M) of
      {ok, {[], TLV}} -> handle_tlv(State, TLV);
      {ok, {DecM, TLV}} ->
	  emit_user(State, {message, DecM}),
	  handle_tlv(State, TLV);
      {rejected, _, ignore_unreadable} ->
	  {next_state, encrypted, State};
      {rejected, _, _} ->
	  emit_user(State,
		    {error, malforment_encrypted_received}),
	  emit_net(State, #otr_msg_error{s = ?ERR_MSG_MALFORMED}),
	  {next_state, encrypted, State}
    end.

%F{{{ heartbeat/1

heartbeat(#s{heartbeat_timeout = infinity} = State) ->
    State;
heartbeat(#s{last_data_msg = undefined} = State) ->
    State#s{last_data_msg = now()};
heartbeat(State) ->
    Now = now(),
    case timer:now_diff(Now, State#s.last_data_msg) div 1000
	   > State#s.heartbeat_timeout
	of
      true -> send_data_msg(State, {[], [], 1});
      false -> State
    end.

%}}}F

enter_finished(State) ->
    emit_user(State, {info, finished}),
    unlink(State#s.mcgs),
    exit(State#s.mcgs, shutdown),
    unlink(State#s.smp),
    exit(State#s.smp, shutdown),
    {ok, Mcgs} = otr_mcgs:start_link(),
    {ok, Smp} = otr_smp_fsm:start_link(),
    {next_state, finished, State#s{mcgs = Mcgs, smp = Smp}}.

%F{{{ handle_tlv/2

handle_tlv(State, error) ->
    emit_user(State, {info, error_in_tlv}),
    {next_state, encrypted, State};
handle_tlv(State, TLV) ->
    case lists:member(disconnected, TLV) of
      true -> enter_finished(State);
      false ->
	  NTLV = [V1 || V1 <- TLV, handle_tlv_1(V1)],
	  {next_state, encrypted, handle_smp(State, NTLV)}
    end.

handle_tlv_1({padding, _}) -> false;
handle_tlv_1(_) -> true.

%}}}F

handle_smp(State, []) -> State;
handle_smp(State, [X | Rest]) ->
    handle_smp(handle_smp_1(State, X), Rest).

handle_smp_1(#s{smp = Smp} = State,
	     {smp_msg_1q, Q, V}) ->
    case otr_smp_fsm:smp_msg(Smp, {smp_msg_1, V}) of
      {error, Error} ->
	  emit_user(State, {smp, {error, Error}});
      {ok, need_user_secret} ->
	  emit_user(State,
		    {smp, need_answer_for_question, binary_to_list(Q)})
    end,
    State;
handle_smp_1(#s{smp = Smp} = State, M) ->
    Emit = case otr_smp_fsm:smp_msg(Smp, M) of
	     {error, Error} ->
		 emit_user(State, {smp, {error, Error}}), [];
	     {ok, need_user_secret} ->
		 emit_user(State, {smp, need_shared_secret}), [];
	     {ok, {emit, E}} -> E;
	     {verification_succeeded, {emit, E}} ->
		 emit_user(State, {smp, verification_succeeded}), E;
	     {verification_failed, {emit, E}} ->
		 emit_user(State, {smp, verification_failed}), E
	   end,
    case Emit of
      [] -> State;
      G -> send_data_msg(State, {[], G, 0})
    end.

send_data_msg(#s{min_enc_size = Mes} = State,
	      {M, TLV, Flags})
    when Mes /= 0, length(M) < Mes ->
    NTLV = [{padding, Mes - length(M)} | TLV],
    {ok, EncM} = otr_mcgs:encrypt(State#s.mcgs,
				  {M, NTLV, Flags}),
    emit_net(State, EncM),
    State#s{last_data_msg = now()};
send_data_msg(State, {M, TLV, Flags}) ->
    {ok, EncM} = otr_mcgs:encrypt(State#s.mcgs,
				  {M, TLV, Flags}),
    emit_net(State, EncM),
    State#s{last_data_msg = now()}.

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

handle_tagged_ws_message(StateName,
			 #s{whitespace_start_ake = true} = State, M) ->
    case StateName of
      plaintext -> emit_user(State, {message, M});
      _ ->
	  emit_user(State, {message, M, [warning_unencrypted]})
    end,
    {ok, Ake} = init_ake(State),
    otr_ake_fsm:consume(Ake, {cmd, start}),
    {next_state, StateName, State#s{ake = Ake}};
handle_tagged_ws_message(StateName, State, M) ->
    case StateName of
      plaintext -> emit_user(State, {message, M});
      _ ->
	  emit_user(State, {message, M, [warning_unencrypted]})
    end,
    {next_state, StateName, State}.

handle_error_message(StateName,
		     #s{error_start_ake = true} = State, M) ->
    emit_user(State, {error_net, M}),
    emit_net(State, otr_msg_query),
    {next_state, StateName, State};
handle_error_message(StateName, State, M) ->
    emit_user(State, {error_net, M}),
    {next_state, StateName, State}.

ake_completed(#s{mcgs = Mcgs, ake = Ake} = State,
	      {OurKeyId, OurKey, TheirKeyId, TheirY, FP, SSID}) ->
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
    ok = otr_mcgs:set_keys(Mcgs,
			   {OurKeyId, OurKey, TheirKeyId, TheirY}),
    OurFP = otr_crypto:dsa_fingerprint(State#s.dsa),
    (init_smp(State, OurFP, FP, SSID))#s{ake = undefined,
					 ssid = SSID, their_dsa_fp = FP}.

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

init_smp(#s{smp = undefined} = State, InitiatorFP,
	 ResponderFP, SessionID) ->
    {ok, Smp} = otr_smp_fsm:start_link(InitiatorFP,
				       ResponderFP, SessionID),
    State#s{smp = Smp};
init_smp(#s{smp = OldSmp} = State, InitiatorFP,
	 ResponderFP, SessionID) ->
    unlink(OldSmp),
    exit(OldSmp, shutdown),
    {ok, Smp} = otr_smp_fsm:start_link(InitiatorFP,
				       ResponderFP, SessionID),
    State#s{smp = Smp}.

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

