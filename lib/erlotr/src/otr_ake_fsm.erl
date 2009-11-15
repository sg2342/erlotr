%%
%% Purpose: Off-the-Record Messaging
%%          (http://www.cypherpunks.ca/otr/Protocol-v2-3.1.0.html)
%%          Authenticated Key Exchange State Machine
%%

-module(otr_ake_fsm).

-author("Stefan Grundmann <sg2342@googlemail.com>").

-copyright("Copyright 2009 Stefan Grundmann").

-include("otr_internal.hrl").

-behaviour(gen_fsm).

% gen_fsm callbacks
-export([code_change/4, handle_event/3, handle_info/3,
	 handle_sync_event/4, init/1, terminate/3]).

% states
-export([awaiting_dhkey/2, awaiting_revealsig/2,
	 awaiting_sig/2, none/2]).

% api
-export([consume/2, start_link/5]).

-record(s,
	{emit_fsm, emit_net, dsa_key, r, key_id, dh_key,
	 dh_pubkey, cm1m2, msg_dh_commit, msg_reveal_sig}).

start_link(KeyId, DhKey, DsaKey, EmitToFsm,
	   EmitToNet) ->
    gen_fsm:start_link(?MODULE,
		       [KeyId, DhKey, DsaKey, EmitToFsm, EmitToNet], []).

consume(Pid, M) -> gen_fsm:send_event(Pid, M).

%F{{{ states

%F{{{ none/2
none({cmd, start}, State) -> send_dh_commit(State);
none(#otr_msg_dh_commit{} = M, State) ->
    process_dh_commit(State, M);
%F{{{ none/2 ignored messages
none(#otr_msg_dh_key{}, State) ->
    {next_state, none, State};
none(#otr_msg_reveal_signature{}, State) ->
    {next_state, none, State};
none(#otr_msg_signature{}, State) ->
    {next_state, none, State}.

%}}}F %}}}F

%F{{{ awaiting_dhkey/2
awaiting_dhkey({cmd, start}, State) ->
    send_dh_commit(prune_state(State));
awaiting_dhkey(#otr_msg_dh_commit{hash_gx = HashGx1},
	       #s{msg_dh_commit =
		      #otr_msg_dh_commit{hash_gx = HashGx2} = M} =
		   State)
    when HashGx2 > HashGx1 ->
    emit_net(State, M), {next_state, awaiting_dhkey, State};
awaiting_dhkey(#otr_msg_dh_commit{} = M, State) ->
    process_dh_commit(prune_state(State), M);
awaiting_dhkey(#otr_msg_dh_key{gy = GY}, State)
    when (GY < 2) or (GY > (?DH_MODULUS) - 2) ->
    send_dh_commit(State);
awaiting_dhkey(#otr_msg_dh_key{} = M, State) ->
    {X, Gx} = State#s.dh_key,
    Gy = M#otr_msg_dh_key.gy,
    [CX, _, M1X, M2X, _, _, _] = CM1M2 =
				     compute_keys(otr_crypto:dh_agree(X, Gy)),
    KeyId = State#s.key_id,
    {ok, EncSig, Mac} = enc_sig_and_mac([CX, M1X, M2X], Gx,
					Gy, KeyId, State#s.dsa_key),
    MsgRevealSig = #otr_msg_reveal_signature{r = State#s.r,
					     enc_sig = EncSig, mac = Mac},
    emit_net(State, MsgRevealSig),
    {next_state, awaiting_sig,
     State#s{msg_reveal_sig = MsgRevealSig, cm1m2 = CM1M2,
	     msg_dh_commit = undefined, dh_pubkey = Gy}};
%F{{{ awaiting_dhkey/2 ignored messages
awaiting_dhkey(#otr_msg_reveal_signature{}, State) ->
    {next_state, awaiting_dhkey, State};
awaiting_dhkey(#otr_msg_signature{}, State) ->
    {next_state, awaiting_dhkey, State}.%}}}F%}}}F

%F{{{ awaiting_revealsig/2
awaiting_revealsig({cmd, start}, State) ->
    send_dh_commit(prune_state(State));
awaiting_revealsig(#otr_msg_dh_commit{} = M, State) ->
    emit_net(State,
	     #otr_msg_dh_key{gy = element(2, State#s.dh_key)}),
    {next_state, awaiting_revealsig,
     State#s{msg_dh_commit = M}};
awaiting_revealsig(#otr_msg_reveal_signature{} = M,
		   State) ->
    case check_commit_msg(State,
			  M#otr_msg_reveal_signature.r)
	of
      {error,
       illegal_dh_pubkey} -> % protocol requires to ignore the message
	  {next_state, awaiting_revealsig, State};
      {error,
       hash_mismatch} -> % protocol requires to ignore the message
	  {next_state, awaiting_revealsig, State};
      {ok, Gx} ->
	  {Y, Gy} = State#s.dh_key,
	  CM1M2 = compute_keys(otr_crypto:dh_agree(Y, Gx)),
	  [CX, CY, M1X, M2X, M1Y, M2Y, SSID] = CM1M2,
	  case check_mac_and_dec_sig([CX, M1X, M2X], Gx, Gy,
				     M#otr_msg_reveal_signature.enc_sig,
				     M#otr_msg_reveal_signature.mac)
	      of
	    {error, _} -> {next_state, awaiting_revealsig, State};
	    {ok, KeyIdx, PubKeyFP} ->
		KeyIdy = State#s.key_id,
		{ok, ES, Mac} = enc_sig_and_mac([CY, M1Y, M2Y], Gy, Gx,
						KeyIdy, State#s.dsa_key),
		emit_net(State,
			 #otr_msg_signature{enc_sig = ES, mac = Mac}),
		emit_fsm(State,
			 {encrypted,
			  {State#s.key_id, State#s.dh_key, KeyIdx, Gx, PubKeyFP,
			   SSID}}),
		{next_state, none, prune_state(State)}
	  end
    end;
%F{{{ awaiting_revealsig/2 ignored message
awaiting_revealsig(#otr_msg_dh_key{}, State) ->
    {next_state, awaiting_revealsig, State};
awaiting_revealsig(#otr_msg_signature{}, State) ->
    {next_state, awaiting_revealsig, State}.

%}}}F%}}}F

%F{{{ awaiting_sig/2
awaiting_sig({cmd, start}, State) ->
    send_dh_commit(prune_state(State));
awaiting_sig(#otr_msg_dh_commit{} = M, State) ->
    process_dh_commit(prune_state(State), M);
awaiting_sig(#otr_msg_dh_key{gy = GY},
	     #s{dh_pubkey = GY} = State) ->
    emit_net(State, State#s.msg_reveal_sig),
    {next_state, awaiting_sig, State};
awaiting_sig(#otr_msg_signature{} = M, State) ->
    GY = State#s.dh_pubkey,
    {_, GX} = State#s.dh_key,
    [_, CY, _, _, M1Y, M2Y, SSID] = State#s.cm1m2,
    case check_mac_and_dec_sig([CY, M1Y, M2Y], GY, GX,
			       M#otr_msg_signature.enc_sig,
			       M#otr_msg_signature.mac)
	of
      {error, _} -> {next_state, awaiting_sig, State};
      {ok, KeyIdy, PubKeyFP} ->
	  emit_fsm(State,
		   {encrypted,
		    {State#s.key_id, State#s.dh_key, KeyIdy, GY, PubKeyFP,
		     SSID}}),
	  {next_state, none, prune_state(State)}
    end;
%F{{{ awaiting_sig/2 ignored messages
awaiting_sig(#otr_msg_dh_key{}, State) ->
    {next_state, awaiting_sig, State};
awaiting_sig(#otr_msg_reveal_signature{}, State) ->
    {next_state, awaiting_sig, State}.%}}}F%}}}F

%}}}F

%F{{{ gen_fsm callbacks

init([KeyId, DhKey, DsaKey, EmitToFsm, EmitToNet]) ->
    {ok, none,
     #s{key_id = KeyId, dh_key = DhKey, dsa_key = DsaKey,
	emit_net = EmitToNet, emit_fsm = EmitToFsm}}.

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

send_dh_commit(State) ->
    R = crypto:rand_bytes(16),
    {_, Gx} = State#s.dh_key,
    MpiGx = otr_util:mpint(Gx),
    EncGx = otr_crypto:aes_ctr_128_encrypt(R, <<0:64>>,
					   MpiGx),
    HashGx = otr_crypto:sha256(MpiGx),
    MsgDhCommit = #otr_msg_dh_commit{enc_gx = EncGx,
				     hash_gx = HashGx},
    emit_net(State, MsgDhCommit),
    {next_state, awaiting_dhkey,
     State#s{r = R, msg_dh_commit = MsgDhCommit}}.

make_m(M1, G1, G2, KeyId, PK) ->
    [MpiG1, MpiG2] = [otr_util:mpint(V) || V <- [G1, G2]],
    otr_crypto:sha256HMAC(M1,
			  <<MpiG1/binary, MpiG2/binary, PK/binary, KeyId:32>>).

check_mac_and_dec_sig([C, M1, M2], G1, G2, ES, Mac) ->
    case otr_crypto:sha256HMAC(M2,
			       <<(size(ES)):32, ES/binary>>)
	of
      <<Mac:20/binary, _/binary>> ->
	  Sig = otr_crypto:aes_ctr_128_decrypt(C, <<0:64>>, ES),
	  PKz = size(ES) - 44,
	  <<PK:PKz/binary, KeyId:32, R:160, S:160>> = Sig,
	  M = make_m(M1, G1, G2, KeyId, PK),
	  case unpack_pubkey(PK) of
	    error -> {error, invalid_dsa_pubkey};
	    {ok, PubKey} ->
		case otr_crypto:dsa_verify(PubKey, M, {R, S}) of
		  false -> {error, dsa_verify};
		  true ->
		      <<0:16, HashThis/binary>> = PK,
		      {ok, KeyId, otr_crypto:sha1(HashThis)}
		end
	  end;
      _ -> {error, mac_missmatch}
    end.

enc_sig_and_mac([C, M1, M2], G1, G2, KeyId, DsaKey) ->
    PK = pack_pubkey(DsaKey),
    M = make_m(M1, G1, G2, KeyId, PK),
    {R, S} = otr_crypto:dsa_sign(DsaKey, M),
    ES = otr_crypto:aes_ctr_128_encrypt(C, <<0:64>>,
					<<PK/binary, KeyId:32, R:160, S:160>>),
    <<Mac:20/binary, _/binary>> = otr_crypto:sha256HMAC(M2,
							<<(size(ES)):32,
							  ES/binary>>),
    {ok, ES, Mac}.

check_commit_msg(State, R) ->
    CM = State#s.msg_dh_commit,
    EncGx = CM#otr_msg_dh_commit.enc_gx,
    MpiGx = otr_crypto:aes_ctr_128_decrypt(R, <<0:64>>,
					   EncGx),
    HashGx = CM#otr_msg_dh_commit.hash_gx,
    case otr_crypto:sha256(MpiGx) of
      HashGx ->
	  Gx = otr_util:erlint(MpiGx),
	  if (Gx >= 2) and (Gx =< (?DH_MODULUS) - 2) -> {ok, Gx};
	     true -> {error, illegal_dh_pubkey}
	  end;
      _ -> {error, hash_mismatch}
    end.

unpack_pubkey(<<0:16, MpiPz:32, MpiP:MpiPz/binary,
		MpiQz:32, MpiQ:MpiQz/binary, MpiGz:32,
		MpiG:MpiGz/binary, MpiYz:32, MpiY:MpiYz/binary>>) ->
    Pub = [otr_util:erlint(<<(size(V1)):32, V1/binary>>)
	   || V1 <- [MpiP, MpiQ, MpiG, MpiY]],
    {ok, Pub};
unpack_pubkey(_) -> error.

pack_pubkey([P, Q, G, _, Y]) ->
    [MpiP, MpiQ, MpiG, MpiY] = [otr_util:mpint(V)
				|| V <- [P, Q, G, Y]],
    <<0:16, MpiP/binary, MpiQ/binary, MpiG/binary,
      MpiY/binary>>.

compute_keys(S) ->
    MpiS = otr_util:mpint(S),
    SSID = otr_crypto:sha256(<<0, MpiS/binary>>),
    <<CX:16/binary, CY:16/binary>> = otr_crypto:sha256(<<1,
							 MpiS/binary>>),
    M1X = otr_crypto:sha256(<<2, MpiS/binary>>),
    M2X = otr_crypto:sha256(<<3, MpiS/binary>>),
    M1Y = otr_crypto:sha256(<<4, MpiS/binary>>),
    M2Y = otr_crypto:sha256(<<5, MpiS/binary>>),
    [CX, CY, M1X, M2X, M1Y, M2Y, SSID].

process_dh_commit(State, M) ->
    {_, Gy} = State#s.dh_key,
    MsgDhKey = #otr_msg_dh_key{gy = Gy},
    emit_net(State, MsgDhKey),
    {next_state, awaiting_revealsig,
     State#s{msg_dh_commit = M}}.

prune_state(State) ->
    #s{emit_net = State#s.emit_net,
       emit_fsm = State#s.emit_fsm, dsa_key = State#s.dsa_key,
       dh_key = State#s.dh_key, key_id = State#s.key_id}.

emit_net(#s{emit_net = EmitNet}, M) -> EmitNet(M).

emit_fsm(#s{emit_fsm = EmitFsm}, M) -> EmitFsm(M).

%}}}F

