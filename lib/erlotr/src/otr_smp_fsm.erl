%%
%% Purpose: Off-the-Record Messaging
%%          (http://www.cypherpunks.ca/otr/Protocol-v2-3.1.0.html)
%%          Socialist Millionaires' Protocol state machine
%%

-module(otr_smp_fsm).

-author("Stefan Grundmann <sg2342@googlemail.com>").

-copyright("Copyright 2009 Stefan Grundmann").

-include("otr_internal.hrl").

-behaviour(gen_fsm).

% gen_fsm callbacks
-export([code_change/4, handle_event/3, handle_info/3,
	 handle_sync_event/4, init/1, terminate/3]).

% states
-export([expect1/3, expect2/3, expect3/3, expect4/3,
	 wait_user_secret/3]).

% api
-export([smp_msg/2, start_link/3, user_abort/1,
	 user_secret/2, user_start/2]).

-record(s,
	{initiator_fp, responder_fp, session_id, x, a2, a3, g2,
	 g3, b2, b3, pb, qb, g3a}).

start_link(InitiatorFP, ResponderFP, SessionID) ->
    gen_fsm:start_link(?MODULE,
		       [InitiatorFP, ResponderFP, SessionID], []).

user_abort(Pid) ->
    gen_fsm:sync_send_all_state_event(Pid, user_abort).

user_start(Pid, UserInput) ->
    gen_fsm:sync_send_all_state_event(Pid,
				      {user_start, UserInput}).

user_secret(Pid, UserInput) ->
    gen_fsm:sync_send_event(Pid, {user_secret, UserInput}).

smp_msg(Pid, M) ->
    gen_fsm:sync_send_event(Pid, {smp_msg, M}).

%F{{{ states

%F{{{ expect1/3
expect1({user_secret, _}, _From, State) ->
    {reply, {error, unexpected_user_secret}, expected1,
     State};
expect1({smp_msg,
	 {smp_msg_1, [G2A, C2, D2, G3A, C3, D3]}},
	_From, State) ->
    case check_knowledge(C2, D2, 2, G2A, 1) and
	   check_knowledge(C3, D3, 2, G3A, 2)
	of
      false ->
	  do_abort({error, proof_checking_failed}, State);
      true ->
	  [B2, B3] = generators(2),
	  G2 = crypto:mod_exp(G2A, B2, ?DH_MODULUS),
	  G3 = crypto:mod_exp(G3A, B3, ?DH_MODULUS),
	  {reply, {ok, need_user_secret}, wait_user_secret,
	   State#s{g3a = G3A, g2 = G2, g3 = G3, b2 = B2, b3 = B3}}
    end;
expect1({smp_msg, smp_abort}, _From, State) ->
    do_abort({error, net_aborted}, State);
expect1({smp_msg, _}, _From, State) ->
    do_abort({error, unexpected_smp_msg}, State).

%}}}F

wait_user_secret({smp_msg, smp_abort}, _From, State) ->
    do_abort({error, net_aborted}, State);
wait_user_secret({smp_msg, _}, _From, State) ->
    do_abort({error, unexpected_smp_msg}, State);
wait_user_secret({user_secret, UserInput}, _From,
		 #s{b2 = B2, b3 = B3, g2 = G2, g3 = G3} = State) ->
    Y = compute_x(State, UserInput),
    G2B = crypto:mod_exp(2, B2, ?DH_MODULUS),
    G3B = crypto:mod_exp(2, B3, ?DH_MODULUS),
    {C2, D2} = proof_knowledge(2, B2, 3),
    {C3, D3} = proof_knowledge(2, B3, 4),
    [R4] = generators(1),
    Pb = crypto:mod_exp(G3, R4, ?DH_MODULUS),
    Qb = mod(crypto:mod_exp(2, R4, ?DH_MODULUS) *
	       crypto:mod_exp(G2, Y, ?DH_MODULUS),
	     ?DH_MODULUS),
    {Cp, D5, D6} = proof_eq_coords(2, G2, G3, Y, R4, 5),
    {reply,
     {ok,
      {emit,
       [{smp_msg_2,
	 [G2B, C2, D2, G3B, C3, D3, Pb, Qb, Cp, D5, D6]}]}},
     expect3, State#s{pb = Pb, qb = Qb}}.

expect2(_M, _From, State) ->
    {stop, {invalid_message, _M}, State}.

expect3(_M, _From, State) ->
    {stop, {invalid_message, _M}, State}.

expect4(_M, _From, State) ->
    {stop, {invalid_message, _M}, State}.

%}}}F

%F{{{ gen_fsm callbacks

init([InitiatorFP, ResponderFP, SessionID]) ->
    {ok, expect1,
     #s{initiator_fp = InitiatorFP,
	responder_fp = ResponderFP, session_id = SessionID}}.

handle_info(Info, StateName, StateData) ->
    {stop, {StateName, undefined_info, Info}, StateData}.

handle_event(Event, StateName, StateData) ->
    {stop, {StateName, undefined_event, Event}, StateData}.

handle_sync_event({user_start, UserInput}, _From,
		  expect1, State) ->
    X = compute_x(State, UserInput),
    [A2, A3] = generators(2),
    G2A = crypto:mod_exp(2, A2, ?DH_MODULUS),
    G3A = crypto:mod_exp(2, A3, ?DH_MODULUS),
    {C2, D2} = proof_knowledge(2, A2, 1),
    {C3, D3} = proof_knowledge(2, A3, 2),
    {reply,
     {ok, {emit, [{smp_msg_1, [G2A, C2, D2, G3A, C3, D3]}]}},
     expect2, State#s{x = X, a2 = A2, a3 = A3}};
handle_sync_event({user_start, _}, _From, StateName,
		  State) ->
    {reply, {error, smp_underway}, StateName, State};
handle_sync_event(user_abort, _From, _StateName,
		  State) ->
    do_abort(State).

terminate(_Reason, _StateName, _State) -> ok.

code_change(_OldVsn, StateName, StateData, _Extra) ->
    {ok, StateName, StateData}.

%}}}F

%F{{{ internal functions
generators(N) -> do_generators(N, []).

do_generators(0, Acc) -> Acc;
do_generators(N, Acc) ->
    do_generators(N - 1,
		  [otr_util:erlint(<<192:32,
				     (crypto:rand_bytes(192))/binary>>)
		   | Acc]).

do_abort(State) ->
    do_abort({ok, {emit, [smp_abort]}}, State).

do_abort(Reply, State) ->
    {reply, Reply, expect1,
     #s{initiator_fp = State#s.initiator_fp,
	responder_fp = State#s.responder_fp,
	session_id = State#s.session_id}}.

compute_x(#s{initiator_fp = Ifp, responder_fp = Rfp,
	     session_id = SId},
	  UserInput) ->
    otr_util:erlint(<<32:32,
		     (otr_crypto:sha256(<<1:8, Ifp/binary, Rfp/binary,
					  SId/binary,
					  UserInput/binary>>))/binary>>).

mod(X, Y) when X >= 0 -> X rem Y;
mod(X, Y) when X < 0 -> Y + X rem Y.

hash_int(V, I) ->
    Bin = otr_util:mpint(I),
    otr_util:erlint(<<32:32,
		      (otr_crypto:sha256(<<V:8, Bin/binary>>))/binary>>).

hash_int(V, I, J) ->
    Bin = <<(otr_util:mpint(I))/binary,
	    (otr_util:mpint(J))/binary>>,
    otr_util:erlint(<<32:32,
		      (otr_crypto:sha256(<<V:8, Bin/binary>>))/binary>>).

proof_knowledge(G, X, V) ->
    R = otr_util:erlint(<<192:32,
			  (crypto:rand_bytes(192))/binary>>),
    C = hash_int(V, crypto:mod_exp(G, R, ?DH_MODULUS)),
    Q = ((?DH_MODULUS) - 1) div 2,
    {C, mod(R - mod(X * C, Q), Q)}.

check_knowledge(C, D, G, X, V) ->
    GD = crypto:mod_exp(G, D, ?DH_MODULUS),
    XC = crypto:mod_exp(X, C, ?DH_MODULUS),
    C == hash_int(V, mod(GD * XC, ?DH_MODULUS)).

proof_eq_coords(G1, G2, G3, Y, R, V) ->
    [R1, R2] = generators(2),
    T1 = crypto:mod_exp(G3, R1, ?DH_MODULUS),
    T2 = mod(crypto:mod_exp(G1, R1, ?DH_MODULUS) *
	       crypto:mod_exp(G2, R2, ?DH_MODULUS),
	     ?DH_MODULUS),
    C = hash_int(V, T1, T2),
    Q = ((?DH_MODULUS) - 1) div 2,
    D1 = mod(R2 - mod(R * C, Q), Q),
    D2 = mod(R2 - mod(Y * C, Q), Q),
    {C, D1, D2}.

    %}}}F

