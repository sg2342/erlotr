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
	 max_fragment_size, send_whitespace_tag, otr_ctx,
	 got_plaintext = false, pt = [], ake}).

start_link(Opts) ->
    gen_fsm:start_link(?MODULE, Opts, []).

consume(Pid, M) -> gen_fsm:send_event(Pid, M).

%F{{{ states

plaintext({ake, {encrypted, {KeyIdy, GX, PubKeyFP}}}, State) ->
    %TODO
    % check fingerpring, id, pubkey ....
    % bla
    emit_user(State, {status, {encrypted, PubKeyFP}}),
    {next_state, encrypted, State};
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

encrypted({ake, {encrypted, {KeyIdy, GX, PubKeyFP}}}, State) ->
    %TODO
    % check fingerpring, id, pubkey ....
    % bla
    emit_user(State, {status, {keys_changed, PubKeyFP}}),
    {next_state, encrypted, State};
%F{{{ encrypted({user
encrypted({user, start_otr}, State) ->
    emit_net(State, otr_msg_query),
    {next_state, encrypted, State};
encrypted({user, stop_otr}, State) ->
    %TODO: Send a Data Message, encoding a message with an empty hunamn-readable part and TLV type 1
    {next_state, plaintext, State};
encrypted({user, {message, M}}, State) ->
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
    %%% TODO
    {next_state, encrypted, State};
encrypted({net, M}, State) ->
    handle_ake_message(M, encrypted, State).%}}}F

finished({ake, {encrypted, {KeyIdy, GX, PubKeyFP}}}, State) ->
    %TODO
    % check fingerpring, id, pubkey ....
    % bla
    emit_user(State, {status, {keys_changed, PubKeyFP}}),
    {next_state, encrypted, State};
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

make_dh_keys(#s{otr_ctx = Ctx} = State) ->
    if (Ctx#otr_ctx.our_keyid < 2) or
	 (Ctx#otr_ctx.our_dh_key == undefined)
	 or (Ctx#otr_ctx.our_prevous_dh_key == undefined) ->
	   NCtx = Ctx#otr_ctx{our_keyid = 2,
			      our_dh_key = otr_crypto:dh_gen_key(),
			      our_prevous_dh_key = otr_crypto:dh_gen_key()},
	   State#s{otr_ctx = NCtx};
       true -> State
    end.

init_ake(#s{ake = undefined, otr_ctx = Ctx}) ->
    KeyId = Ctx#otr_ctx.our_keyid - 1,
    DhKey = Ctx#otr_ctx.our_prevous_dh_key,
    DsaKey = Ctx#otr_ctx.dsa_key,
    Self = self(),
    EmitToFsm = fun (X) -> otr_fsm:consume(Self, {ake, X})
		end,
    EmitToNet = fun (X) ->
			gen_fsm:send_all_state_event(Self, {ake_to_net, X})
		end,
    otr_ake_fsm:start_link(KeyId, DhKey, DsaKey, EmitToFsm,
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

