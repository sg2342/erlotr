-module(otr_fsm).

-author("Stefan Grundmann <sg2342@googlemail.com>").

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
	 send_whitespace_tag, got_plaintext = false, pt, auth}).

start_link(Opts) ->
    gen_fsm:start_link(?MODULE, Opts, []).

consume(Pid, M) -> gen_fsm:send_event(Pid, M).

%F{{{ states
%F{{{ plaintext({user ....
plaintext({user, start_otr}, State) ->
    emit_net(State, otr_msg_query),
    {next_state, plaintext, State};
plaintext({user, stop_ort}, State) ->
    {next_state, plaintext, State};
plaintext({user, {message, M}},
	  #s{require_encryption = true} = State) ->
    emit_net(State, otr_msg_query),
    {next_state, plaintext, State#s{pt = [m | State#s.pt]}};
plaintext({user, {message, M}},
	  #s{send_whitespace_tag = true} = State) ->
    emit_net(State, #otr_msg_tagged_ws{s = M}),
    {next_state, plaintext, State}; %}}}F
%F{{{ plaintext({net
plaintext({net, {plain, M}}, State) ->
    emit_user(State, {message, M, []}),
    {next_state, plaintext, State};
plaintext({net, #otr_msg_tagged_ws{s = M}}, State) ->
    emit_user(State, {message, M}),
    {next_state, plaintext,
     emit_dh_commit(State, State#s.whitespace_start_ake)};
plaintext({net, otr_msg_query}, State) ->
    {next_state, plaintext, emit_dh_commit(State, true)};
plaintext({net, #otr_msg_error{s = M}}, State) ->
    emit_user(State, {error_net, M}),
    State#s.error_start_ake andalso
      emit_net(State, otr_msg_query),
    {next_state, plaintext, State};
plaintext({net, #otr_msg_dh_commit{} = M}, State) ->
    {next_state, plaintext,
     consume_otr_msg_dh_commit(M, State)};
plaintext({net, #otr_msg_dh_key{} = M}, State) ->
    {next_state, plaintext,
     consume_otr_msg_dh_key(M, State)};
plaintext({net, #otr_msg_reveal_signature{} = M},
	  State) ->
    {next_state, plaintext,
     consume_otr_msg_reveal_signature(M, State)};
plaintext({net, #otr_msg_signature{} = M}, State) ->
    {NextStateName, NState} = consume_otr_msg_signature(M,
							plaintext, State),
    {next_state, NextStateName, NState};
plaintext({net, #otr_msg_data{}}, State) ->
    emit_user(State,
	      {error, unreadable_encrypted_received}),
    emit_net(State,
	     #otr_msg_error{s = ?OTRL_ERRCODE_MSG_NOT_IN_PRIVATE}),
    {next_state, plaintext, State}.%}}}F

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
    emit_user(State, {message, M}),
    {next_state, encrypted, State};
encrypted({net, #otr_msg_tagged_ws{s = M}}, State) ->
    emit_user(State, {message, M}),
    {next_state, encrypted,
     emit_dh_commit(State, State#s.whitespace_start_ake)};
encrypted({net, otr_msg_query}, State) ->
    {next_state, encrypted, emit_dh_commit(State, true)};
encrypted({net, #otr_msg_error{s = M}}, State) ->
    emit_user(State, {error_net, M}),
    State#s.error_start_ake andalso
      emit_net(State, otr_msg_query),
    {next_state, encrypted, State};
encrypted({net, #otr_msg_dh_commit{} = M}, State) ->
    {next_state, encrypted,
     consume_otr_msg_dh_commit(M, State)};
encrypted({net, #otr_msg_dh_key{} = M}, State) ->
    {next_state, encrypted,
     consume_otr_msg_dh_key(M, State)};
encrypted({net, #otr_msg_reveal_signature{} = M},
	  State) ->
    {next_state, encrypted,
     consume_otr_msg_reveal_signature(M, State)};
encrypted({net, #otr_msg_signature{} = M}, State) ->
    {NextStateName, NState} = consume_otr_msg_signature(M,
							encrypted, State),
    {next_state, NextStateName, NState};
encrypted({net, #otr_msg_data{} = M}, State) ->
    consume_otr_msg_data(M, State).%}}}F

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
    emit_user(State, {message, M}),
    {next_state, finished, State};
finished({net, #otr_msg_tagged_ws{s = M}}, State) ->
    emit_user(State, {message, M}),
    {next_state, finished,
     emit_dh_commit(State, State#s.whitespace_start_ake)};
finished({net, otr_msg_query}, State) ->
    {next_state, finished, emit_dh_commit(State, true)};
finished({net, #otr_msg_error{s = M}}, State) ->
    emit_user(State, {error_net, M}),
    State#s.error_start_ake andalso
      emit_net(State, otr_msg_query),
    {next_state, finished, State};
finished({net, #otr_msg_dh_commit{} = M}, State) ->
    {next_state, finished,
     consume_otr_msg_dh_commit(M, State)};
finished({net, #otr_msg_dh_key{} = M}, State) ->
    {next_state, finished,
     consume_otr_msg_dh_key(M, State)};
finished({net, #otr_msg_reveal_signature{} = M},
	 State) ->
    {next_state, finished,
     consume_otr_msg_reveal_signature(M, State)};
finished({net, #otr_msg_signature{} = M}, State) ->
    {NextStateName, NState} = consume_otr_msg_signature(M,
							finished, State),
    {next_state, NextStateName, NState};
finished({net, #otr_msg_data{}}, State) ->
    emit_user(State,
	      {error, unreadable_encrypted_received}),
    emit_net(State,
	     #otr_msg_error{s = ?OTRL_ERRCODE_MSG_NOT_IN_PRIVATE}),
    {next_state, finished, State}.%}}}F

%}}}F

%F{{{ gen_fsm callbacks

init(Opts) -> {ok, plaintext, #s{}}.

handle_info(Info, StateName, StateData) ->
    {stop, {StateName, undefined_info, Info}, StateData}.

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

consume_otr_msg_signature(#otr_msg_signature{} = M,
			  StateName, State) ->
    % If authstate is AUTHSTATE_AWAITING_SIG:
    % Decrypt the encrypted signature, and verify the signature and the MACs. If everything checks out:
    % Transition authstate to AUTHSTATE_NONE.
    % Transition msgstate to MSGSTATE_ENCRYPTED.
    % If there is a recent stored message, encrypt it and send it as a Data Message.
    % Otherwise, ignore the message.
    % If authstate is AUTHSTATE_NONE, AUTHSTATE_AWAITING_DHKEY, AUTHSTATE_AWAITING_REVEALSIG, or AUTHSTATE_V1_SETUP:
    % Ignore the message.
    {StateName, State}.

consume_otr_msg_reveal_signature(#otr_msg_reveal_signature{} =
				     M,
				 State) ->
    % If authstate is AUTHSTATE_AWAITING_REVEALSIG:
    % Use the received value of r to decrypt the value of gx received in the D-H Commit Message, and verify the hash therein. Decrypt the encrypted signature, and verify the signature and the MACs. If everything checks out:
    % Reply with a Signature Message.
    % Transition authstate to AUTHSTATE_NONE.
    % Transition msgstate to MSGSTATE_ENCRYPTED.
    % If there is a recent stored message, encrypt it and send it as a Data Message.
    % Otherwise, ignore the message.
    % If authstate is AUTHSTATE_NONE, AUTHSTATE_AWAITING_DHKEY, AUTHSTATE_AWAITING_SIG, or AUTHSTATE_V1_SETUP:
    % Ignore the message.
    State.

consume_otr_msg_dh_key(#otr_msg_dh_key{} = M, State) ->
    % If authstate is AUTHSTATE_AWAITING_DHKEY:
    % Reply with a Reveal Signature Message and transition authstate to AUTHSTATE_AWAITING_SIG.
    % If authstate is AUTHSTATE_AWAITING_SIG:
    % If this D-H Key message is the same the one you received earlier (when you entered AUTHSTATE_AWAITING_SIG):
    % Retransmit your Reveal Signature Message.
    % Otherwise:
    % Ignore the message.
    % If authstate is AUTHSTATE_NONE, AUTHSTATE_AWAITING_REVEALSIG, or AUTHSTATE_V1_SETUP:
    % Ignore the message.
    State.

consume_otr_msg_dh_commit(#otr_msg_dh_commit{} = M,
			  State) ->
    % If ALLOW_V2 is not set, ignore this message. Otherwise:
    % If authstate is AUTHSTATE_NONE:
    % Reply with a D-H Key Message, and transition authstate to AUTHSTATE_AWAITING_REVEALSIG.
    % If authstate is AUTHSTATE_AWAITING_DHKEY:
    % This is the trickiest transition in the whole protocol. It indicates that you have already sent a D-H Commit message to your correspondent, but that he either didn't receive it, or just didn't receive it yet, and has sent you one as well. The symmetry will be broken by comparing the hashed gx you sent in your D-H Commit Message with the one you received, considered as 32-byte unsigned big-endian values.
    % If yours is the higher hash value:
    % Ignore the incoming D-H Commit message, but resend your D-H Commit message.
    % Otherwise:
    % Forget your old gx value that you sent (encrypted) earlier, and pretend you're in AUTHSTATE_NONE; i.e. reply with a D-H Key Message, and transition authstate to AUTHSTATE_AWAITING_REVEALSIG.
    % If authstate is AUTHSTATE_AWAITING_REVEALSIG:
    % Retransmit your D-H Key Message (the same one as you sent when you entered AUTHSTATE_AWAITING_REVEALSIG). Forget the old D-H Commit message, and use this new one instead. There are a number of reasons this might happen, including:
    % Your correspondent simply started a new AKE.
    % Your correspondent resent his D-H Commit message, as specified above.
    % On some networks, like AIM, if your correspondent is logged in multiple times, each of his clients will send a D-H Commit Message in response to a Query Message; resending the same D-H Key Message in response to each of those messages will prevent compounded confusion, since each of his clients will see each of the D-H Key Messages you send. [And the problem gets even worse if you are each logged in multiple times.]
    % If authstate is AUTHSTATE_AWAITING_SIG or AUTHSTATE_V1_SETUP:
    % Reply with a new D-H Key message, and transition authstate to AUTHSTATE_AWAITING_REVEALSIG.
    State.

consume_otr_msg_data(#otr_msg_data{} = M, State) ->
    % Verify the information (MAC, keyids, ctr value, etc.) in the message.
    % If the verification succeeds:
    % Decrypt the message and display the human-readable part (if non-empty) to the user.
    % Update the D-H encryption keys, if necessary.
    % If you have not sent a message to this correspondent in some (configurable) time, send a "heartbeat" message, consisting of a Data Message encoding an empty plaintext. The heartbeat message should have the IGNORE_UNREADABLE flag set.
    % If the received message contains a TLV type 1, forget all encryption keys for this correspondent, and transition msgstate to MSGSTATE_FINISHED.
    % Otherwise, inform the user that an unreadable encrypted message was received, and reply with an Error Message.
    {next_state, encrypted, State}.

emit_dh_commit(State, false) -> State;
emit_dh_commit(State, true) ->
    % TODO send D-H Commit Message
    State#s{auth = authstate_awaiting_dhkey}.

%F{{{ emit_...
emit_user(#s{emit_user = F, require_encryption = true},
	  {message, M}) ->
    F({message, M, [warning_unencrypted]});
emit_user(#s{emit_user = F}, M) -> F(M).

emit_net(#s{emit_net = F}, M) ->
    {ok, Data} = otr_message:encode(M),
    F(Data). %  XXX fragmentation code
	                                                                            %}}}F
										    %}}}F

