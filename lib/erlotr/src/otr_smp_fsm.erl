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

-define(CG(X), (X >= 2) and (X =< (?DH_MODULUS) - 2)).

-define(CO(X),
	(X >= 1) and (X =< ((?DH_MODULUS) - 1) div 2)).

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
	 g3, b2, b3, pb, qb, g3a, g3b, pab, qab, ra}).

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
expect1({smp_msg,
	 {smp_msg_1, [G2A, C2, D2, G3A, C3, D3]}},
	_From, State)
    when ?CG(G2A), ?CG(G3A), ?CO(D2), ?CO(D3) ->
    case check_knowledge(C2, D2, 2, G2A, 1) and
	   check_knowledge(C3, D3, 2, G3A, 2)
	of
      false ->
	  do_abort({error, proof_checking_failed}, State);
      true ->
	  B2 = otr_crypto:rand_int(192),
	  B3 = otr_crypto:rand_int(192),
	  G2 = mod_exp(G2A, B2),
	  G3 = mod_exp(G3A, B3),
	  {reply, {ok, need_user_secret}, wait_user_secret,
	   State#s{g3a = G3A, g2 = G2, g3 = G3, b2 = B2, b3 = B3}}
    end;
expect1({user_secret, _}, _From, State) ->
    {reply, {error, unexpected_user_secret}, expect1,
     State};
expect1({smp_msg, smp_abort}, _From, State) ->
    do_abort({error, net_aborted}, State);
expect1({smp_msg, _}, _From, State) ->
    do_abort({error, unexpected_smp_msg}, State).

%}}}F

%F{{{ wait_user_secret/3

wait_user_secret({smp_msg, smp_abort}, _From, State) ->
    do_abort({error, net_aborted}, State);
wait_user_secret({smp_msg, _}, _From, State) ->
    do_abort({error, unexpected_smp_msg}, State);
wait_user_secret({user_secret, UserInput}, _From,
		 #s{b2 = B2, b3 = B3, g2 = G2, g3 = G3} = State) ->
    Y = compute_x(State, UserInput),
    G2B = mod_exp(2, B2),
    G3B = mod_exp(2, B3),
    {C2, D2} = proof_knowledge(2, B2, 3),
    {C3, D3} = proof_knowledge(2, B3, 4),
    R = otr_crypto:rand_int(192),
    Pb = mod_exp(G3, R),
    Qb = mod(mod_exp(2, R) * mod_exp(G2, Y)),
    {Cp, D5, D6} = proof_eq_coords(2, G2, G3, Y, R, 5),
    {reply,
     {ok,
      {emit,
       [{smp_msg_2,
	 [G2B, C2, D2, G3B, C3, D3, Pb, Qb, Cp, D5, D6]}]}},
     expect3, State#s{pb = Pb, qb = Qb}}.

%}}}F

%F{{{ expect2
expect2({smp_msg,
	 {smp_msg_2,
	  [G2B, C2, D2, G3B, C3, D3, Pb, Qb, Cpin, D5in, D6in]}},
	_From, #s{a2 = A2, a3 = A3, x = X} = State)
    when ?CG(G2B), ?CG(G3B), ?CG(Pb), ?CG(Qb), ?CO(D2),
	 ?CO(D3), ?CO(D5in), ?CO(D6in) ->
    G2 = mod_exp(G2B, A2),
    G3 = mod_exp(G3B, A3),
    case check_knowledge(C2, D2, 2, G2B, 3) and
	   check_knowledge(C3, D3, 2, G3B, 4)
	   and
	   check_eq_coords(Cpin, D5in, D6in, Pb, Qb, 2, G2, G3, 5)
	of
      false ->
	  do_abort({error, proof_checking_failed}, State);
      true ->
	  S = otr_crypto:rand_int(192),
	  Pa = mod_exp(G3, S),
	  Qa = mod(mod_exp(2, S) * mod_exp(G2, X)),
	  {Cp, D5, D6} = proof_eq_coords(2, G2, G3, X, S, 6),
	  Pab = mod(Pa * mod_inv(Pb)),
	  Qab = mod(Qa * mod_inv(Qb)),
	  Ra = mod_exp(Qab, A3),
	  {Cr, D7} = proof_eq_logs(2, Qab, A3, 7),
	  {reply,
	   {ok,
	    {emit,
	     [{smp_msg_3, [Pa, Qa, Cp, D5, D6, Ra, Cr, D7]}]}},
	   expect4,
	   State#s{g3b = G3B, pab = Pab, qab = Qab, ra = Ra}}
    end;
expect2({user_secret, _}, _From, State) ->
    {reply, {error, unexpected_user_secret}, expect2,
     State};
expect2({smp_msg, smp_abort}, _From, State) ->
    do_abort({error, net_aborted}, State);
expect2({smp_msg, _}, _From, State) ->
    do_abort({error, unexpected_smp_msg}, State).

%}}}F

%F{{{ expect3
expect3({smp_msg,
	 {smp_msg_3, [Pa, Qa, Cp, D5, D6, Ra, Crin, D7in]}},
	_From,
	#s{g2 = G2, g3 = G3, qb = Qb, pb = Pb, b3 = B3,
	   g3a = G3a} =
	    State)
    when ?CG(Pa), ?CG(Qa), ?CG(Ra), ?CO(D5), ?CO(D6),
	 ?CO(D7in) ->
    Qab = mod(Qa * mod_inv(Qb)),
    case check_eq_coords(Cp, D5, D6, Pa, Qa, 2, G2, G3, 6)
	   and check_eq_logs(Crin, D7in, Qab, Ra, 2, G3a, 7)
	of
      false ->
	  do_abort({error, proof_checking_failed}, State);
      true ->
	  Rb = mod_exp(Qab, B3),
	  Rab = mod_exp(Ra, B3),
	  Pab = mod(Pa * mod_inv(Pb)),
	  {Cr, D7} = proof_eq_logs(2, Qab, B3, 8),
	  Res = case Pab == Rab of
		  false -> verification_failed;
		  true -> verification_succeeded
		end,
	  {reply, {Res, {emit, [{smp_msg_4, [Rb, Cr, D7]}]}},
	   expect1, cleaned_state(State)}
    end;
expect3({user_secret, _}, _From, State) ->
    {reply, {error, unexpected_user_secret}, expect3,
     State};
expect3({smp_msg, smp_abort}, _From, State) ->
    do_abort({error, net_aborted}, State);
expect3({smp_msg, _}, _From, State) ->
    do_abort({error, unexpected_smp_msg}, State).

%}}}F

%F{{{ expect4
expect4({smp_msg, {smp_msg_4, [Rb, Cr, D7]}}, _From,
	#s{g3b = G3b, pab = Pab, qab = Qab, a3 = A3} = State)
    when ?CG(Rb), ?CO(D7) ->
    case check_eq_logs(Cr, D7, Qab, Rb, 2, G3b, 8) of
      false ->
	  do_abort({error, proof_checking_failed}, State);
      true ->
	  Rab = mod_exp(Rb, A3),
	  Res = case Pab == Rab of
		  false -> verification_failed;
		  true -> verification_succeeded
		end,
	  {reply, {Res, {emit, []}}, expect1,
	   cleaned_state(State)}
    end;
expect4({user_secret, _}, _From, State) ->
    {reply, {error, unexpected_user_secret}, expect4,
     State};
expect4({smp_msg, smp_abort}, _From, State) ->
    do_abort({error, net_aborted}, State);
expect4({smp_msg, _}, _From, State) ->
    do_abort({error, unexpected_smp_msg}, State).

%}}}F

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
    A2 = otr_crypto:rand_int(192),
    A3 = otr_crypto:rand_int(192),
    G2A = mod_exp(2, A2),
    G3A = mod_exp(2, A3),
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

do_abort(State) ->
    do_abort({ok, {emit, [smp_abort]}}, State).

do_abort(Reply, State) ->
    {reply, Reply, expect1, cleaned_state(State)}.

cleaned_state(State) ->
    #s{initiator_fp = State#s.initiator_fp,
       responder_fp = State#s.responder_fp,
       session_id = State#s.session_id}.

compute_x(#s{initiator_fp = Ifp, responder_fp = Rfp,
	     session_id = SId},
	  UserInput) ->
    do_hash(1,
	    <<1:8, Ifp/binary, Rfp/binary, SId/binary,
	      UserInput/binary>>).

mod(X) -> otr_crypto:mod(X, ?DH_MODULUS).

mod_q(X) ->
    otr_crypto:mod(X, ((?DH_MODULUS) - 1) div 2).

mod_inv(X) -> otr_crypto:mod_inv(X, ?DH_MODULUS).

mod_exp(G, X) -> otr_crypto:mod_exp(G, X, ?DH_MODULUS).

hash_int(V, I) -> do_hash(V, otr_util:mpint(I)).

hash_int(V, I, J) ->
    do_hash(V,
	    <<(otr_util:mpint(I))/binary,
	      (otr_util:mpint(J))/binary>>).

do_hash(V, Bin) ->
    otr_util:erlint(<<32:32,
		      (otr_crypto:sha256(<<V:8, Bin/binary>>))/binary>>).

proof_knowledge(G, X, V) ->
    R = otr_crypto:rand_int(192),
    C = hash_int(V, mod_exp(G, R)),
    {C, mod_q(R - mod_q(X * C))}.

check_knowledge(C, D, G, X, V) ->
    C == hash_int(V, mod(mod_exp(G, D) * mod_exp(X, C))).

proof_eq_coords(G1, G2, G3, X, R, V) ->
    R1 = otr_crypto:rand_int(192),
    R2 = otr_crypto:rand_int(192),
    T1 = mod_exp(G3, R1),
    T2 = mod(mod_exp(G1, R1) * mod_exp(G2, R2)),
    C = hash_int(V, T1, T2),
    D1 = mod_q(R1 - mod_q(R * C)),
    D2 = mod_q(R2 - mod_q(X * C)),
    {C, D1, D2}.

check_eq_coords(C, D1, D2, P, Q, G1, G2, G3, V) ->
    Tmp1 = mod(mod_exp(G3, D1) * mod_exp(P, C)),
    Tmp2 = mod(mod(mod_exp(G1, D1) * mod_exp(G2, D2)) *
		 mod_exp(Q, C)),
    C == hash_int(V, Tmp1, Tmp2).

proof_eq_logs(G1, Qab, X, V) ->
    R = otr_crypto:rand_int(192),
    C = hash_int(V, mod_exp(G1, R), mod_exp(Qab, R)),
    D = mod_q(R - mod_q(X * C)),
    {C, D}.

check_eq_logs(C, D, Qab, R, G1, G3o, V) ->
    Tmp1 = mod(mod_exp(G1, D) * mod_exp(G3o, C)),
    Tmp2 = mod(mod_exp(Qab, D) * mod_exp(R, C)),
    C == hash_int(V, Tmp1, Tmp2).

%}}}F

