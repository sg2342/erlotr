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

-record(dm_keys,
	{tx_key, tx_mac, rx_key, rx_mac, rx_ctr = 0,
	 tx_ctr = 0}).

-record(s,
	{emit_user, emit_net, require_encryption,
	 whitespace_start_ake, error_start_ake, dm_keys = [],
	 max_fragment_size, send_whitespace_tag, otr_ctx,
	 got_plaintext = false, pt = [], ake, ssid}).

start_link(Opts) ->
    gen_fsm:start_link(?MODULE, Opts, []).

consume(Pid, M) -> gen_fsm:send_event(Pid, M).

%F{{{ states

plaintext({ake, {encrypted, TheirKM}},
	  #s{pt = []} = State) ->
    ake_completed(TheirKM, State);
plaintext({ake, {encrypted, TheirKM}},
	  #s{pt = PT} = State) ->
    {_, _, NState} = ake_completed(TheirKM, State),
    % TODO send pt array
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
    ake_completed(TheirKM, State);
%F{{{ encrypted({user
encrypted({user, start_otr}, State) ->
    emit_net(State, otr_msg_query),
    {next_state, encrypted, State};
encrypted({user, stop_otr}, State) ->
    %TODO: Send a Data Message, encoding a message with an empty hunamn-readable part and TLV type 1
    {next_state, plaintext, State};
encrypted({user, {message, M}}, State) ->
    {ok, NState} = send_data_msg(State, M),
    %TODO: Encrypt the message and send it as data message, store the plaintext for possible retransmission
    {next_state, encrypted, NState};  %}}}F
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
    {ok, NState} = recv_data_msg(State, M),
    {next_state, encrypted, State};
encrypted({net, M}, State) ->
    handle_ake_message(M, encrypted, State).%}}}F

finished({ake, {encrypted, TheirKM}}, State) ->
    ake_completed(TheirKM, State);
%F{{{ finished({user ...
finished({user, start_otr}, State) ->
    emit_net(State, otr_msg_query),
    {next_state, encrypted, State};
finished({user, stop_otr}, State) ->
    {next_state, plaintext, State#s{got_plaintext = false}};
finished({user, {message, M}}, State) ->
    emit_user(State,
	      {info, message_can_not_be_sent_this_time}),
    %TODO: store the plaintext message for possible retransmission
    {next_state, finished, State};  %}}}F
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
    {ok, plaintext, make_dh_keys(process_opts(Opts))}.

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

recv_data_msg(#s{otr_ctx = Ctx} = State, M) ->
    {ok, DmK} = get_dmk(State,
			M#otr_msg_data.recipient_keyid,
			M#otr_msg_data.sender_keyid),
    Ctr = M#otr_msg_data.ctr_init,
    PlainText =
	otr_crypto:aes_ctr_128_decrypt(DmK#dm_keys.rx_key, Ctr,
				       M#otr_msg_data.enc_data),
    emit_user(State,
	      {message, lists:delete(0, binary_to_list(PlainText))}),
    {ok, State}.

send_data_msg(#s{otr_ctx = Ctx} = State, M) ->
    OId = Ctx#otr_ctx.our_keyid - 1,
    TId = Ctx#otr_ctx.their_keyid,
    {ok, DmK} = get_dmk(State, OId, TId),
    Ctr = DmK#dm_keys.tx_ctr + 1,
    EncM =
	otr_crypto:aes_ctr_128_encrypt(DmK#dm_keys.tx_key,
				       <<Ctr:64>>, M),
    Y = element(2, Ctx#otr_ctx.our_dh),
    MpiY = otr_util:mpint(Y),
    Mac = otr_crypto:sha1HMAC(DmK#dm_keys.tx_mac,
			      <<2:16, 3:8, 0:8, OId:32, TId:32, MpiY/binary,
				Ctr:64, (size(EncM)):32, EncM/binary>>),
    NDmK = DmK#dm_keys{tx_ctr = Ctr},
    DmKL = lists:keystore({OId, TId}, 1, State#s.dm_keys,
			  {{OId, TId}, NDmK}),
    DataMessage = #otr_msg_data{flags = 0,
				sender_keyid = OId, recipient_keyid = TId,
				dhy = Y, enc_data = EncM, ctr_init = <<Ctr:64>>,
				mac = Mac, old_mac_keys = <<>>},
    emit_net(State, DataMessage),
    {ok, State#s{dm_keys = DmKL}}.

get_dmk(State, OurKeyId, TheirKeyId) ->
    case lists:keyfind({OurKeyId, TheirKeyId}, 1,
		       State#s.dm_keys)
	of
      false -> compute_dmk(State, OurKeyId, TheirKeyId);
      {{OurKeyId, TheirKeyId}, V} -> {ok, V}
    end.

compute_dmk(#s{otr_ctx = Ctx} = State, OurKeyId,
	    TheirKeyId) ->
    case get_dh_keys(Ctx, OurKeyId, TheirKeyId) of
      error -> error;
      {ok, {OurPriv, OurPub}, TheirPub} ->
	  SecBytes = otr_util:mpint(otr_crypto:dh_agree(OurPriv,
							TheirPub)),
	  {TxB, RxB} = if OurPub > TheirPub -> {1, 2};
			  true -> {2, 1}
		       end,
	  <<TxKey:16/binary, _/binary>> = otr_crypto:sha1(<<TxB,
							    SecBytes/binary>>),
	  <<RxKey:16/binary, _/binary>> = otr_crypto:sha1(<<RxB,
							    SecBytes/binary>>),
	  {ok,
	   #dm_keys{tx_key = TxKey, rx_key = RxKey,
		    tx_mac = otr_crypto:sha1(TxKey),
		    rx_mac = otr_crypto:sha1(RxKey)}}
    end.

%F{{{ get_dh_keys/3
get_dh_keys(#otr_ctx{their_keyid = T, our_keyid = O} =
		Ctx,
	    O, T) ->
    {ok, Ctx#otr_ctx.our_dh, Ctx#otr_ctx.their_y};
get_dh_keys(#otr_ctx{their_keyid = T, our_keyid = O} =
		Ctx,
	    OO, T)
    when OO == O - 1 ->
    {ok, Ctx#otr_ctx.our_prevous_dh, Ctx#otr_ctx.their_y};
get_dh_keys(#otr_ctx{their_keyid = T, our_keyid = O,
		     their_previous_y = Y} =
		Ctx,
	    O, TT)
    when (TT == T - 1) and (Y /= undefined) ->
    {ok, Ctx#otr_ctx.our_dh, Y};
get_dh_keys(#otr_ctx{their_keyid = T, our_keyid = O,
		     their_previous_y = Y} =
		Ctx,
	    OO, TT)
    when (TT == T - 1) and (OO == O - 1) and
	   (Y /= undefined) ->
    {ok, Ctx#otr_ctx.our_prevous_dh, Y};
get_dh_keys(_, _, _) -> error.%}}}F

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

%F{{{ ake_completed/2
ake_completed({KeyId, Y, FP, SSID},
	      #s{otr_ctx = Ctx, ake = Ake} = State) ->
    unlink(Ake),
    exit(Ake, shutdown),
    case Ctx#otr_ctx.their_dsa_fp of
      undefined ->
	  emit_user(State,
		    {info, {encrypted_new_dsa_fp, FP, SSID}});
      FP -> emit_user(State, {info, {encrypted, SSID}});
      _ ->
	  emit_user(State,
		    {info, {encrypted_changed_dsa_fp, FP, SSID}})
    end,
    if (KeyId == Ctx#otr_ctx.their_keyid) and
	 (Y == Ctx#otr_ctx.their_y) ->
	   {next_state, encrypted,
	    State#s{ake = undefined, ssid = SSID}};
       (KeyId == Ctx#otr_ctx.their_keyid - 1) and
	 (Y == Ctx#otr_ctx.their_previous_y)
	 and (Ctx#otr_ctx.their_y /= undefined) ->
	   {next_state, encrypted,
	    State#s{ake = undefined, ssid = SSID}};
       true ->
	   {next_state, encrypted,
	    State#s{ake = undefined, ssid = SSID,
		    otr_ctx =
			Ctx#otr_ctx{their_dsa_fp = FP,
				    their_previous_y = undefined,
				    their_keyid = KeyId,
				    their_y = Y}}}%}}}F
    end.

%F{{{ make_dh_keys/1
make_dh_keys(#s{otr_ctx = Ctx} = State) ->
    if (Ctx#otr_ctx.our_keyid < 2) or
	 (Ctx#otr_ctx.our_dh == undefined)
	 or (Ctx#otr_ctx.our_prevous_dh == undefined) ->
	   NCtx = Ctx#otr_ctx{our_keyid = 2,
			      our_dh = otr_crypto:dh_gen_key(),
			      our_prevous_dh = otr_crypto:dh_gen_key()},
	   State#s{otr_ctx = NCtx};
       true -> State%}}}F
    end.

%F{{{ init_ake/1
init_ake(#s{ake = undefined, otr_ctx = Ctx}) ->
    KeyId = Ctx#otr_ctx.our_keyid - 1,
    DhKey = Ctx#otr_ctx.our_prevous_dh,
    DsaKey = Ctx#otr_ctx.dsa_key,
    Self = self(),
    EmitToFsm = fun (X) -> otr_fsm:consume(Self, {ake, X})
		end,
    EmitToNet = fun (X) ->
			gen_fsm:send_all_state_event(Self, {ake_to_net, X})
		end,
    otr_ake_fsm:start_link(KeyId, DhKey, DsaKey, EmitToFsm,
			   EmitToNet);
init_ake(#s{ake = Ake}) -> {ok, Ake}. %}}}F

%F{{{ emit_.../2
emit_user(#s{emit_user = F, require_encryption = true},
	  {message, M}) ->
    F({message, M, [warning_unencrypted]});
emit_user(#s{emit_user = F}, M) -> F(M).

emit_net(#s{emit_net = F, max_fragment_size = FSz},
	 M) ->
    case otr_message:encode(M, FSz) of
      {ok, Data} -> F(Data);
      {fragmented, FL} -> lists:foreach(F, FL)%}}}F
    end.

%F{{{ process_opts/1
process_opts(O) ->
    #s{emit_user = proplists:get_value(emit_user, O),
       emit_net = proplists:get_value(emit_net, O),
       require_encryption =
	   proplists:get_bool(require_encryption, O),
       whitespace_start_ake =
	   proplists:get_bool(whitespace_start_ake, O),
       error_start_ake =
	   proplists:get_bool(error_start_ake, O),
       send_whitespace_tag =
	   proplists:get_bool(send_whitespace_tag, O),
       otr_ctx = proplists:get_value(otr_ctx, O),
       max_fragment_size =
	   proplists:get_value(max_fragment_size, O,
			       ?DEFAULT_MAX_FRAG_SIZE)}.%}}}F

%}}}F

