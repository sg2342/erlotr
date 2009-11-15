%%
%% Purpose: Off-the-Record Messaging
%%          (http://www.cypherpunks.ca/otr/Protocol-v2-3.1.0.html)
%%          data message crypto, key management
%%

-module(otr_mcgs).

-author("Stefan Grundmann <sg2342@googlemail.com>").

-copyright("Copyright 2009 Stefan Grundmann").

-behaviour(gen_server).

-include("otr_internal.hrl").

% gen_server callbacks
-export([code_change/3, handle_call/3, handle_cast/2,
	 handle_info/2, init/1, terminate/2]).

% api
-export([start_link/0]).
-export([decrypt/2, encrypt/2, get_key/1, set_keys/2]).

-record(s,
	{dh, previous_dh, y, previous_y, our_id, their_id,
	 dmk = [], reveal_macs = <<>>}).

-record(dmk,
	{rx_ctr = 0, tx_ctr = 0, rx_mac, tx_mac, rx_key, tx_key}).

start_link() -> gen_server:start_link(?MODULE, [], []).

encrypt(Pid, {M, TLV, Flags}) ->
    gen_server:call(Pid, {encrypt, {M, TLV, Flags}});
encrypt(Pid, {M, TLV}) ->
    gen_server:call(Pid, {encrypt, {M, TLV, 0}});
encrypt(Pid, M) ->
    gen_server:call(Pid, {encrypt, {M, [], 0}}).

decrypt(Pid, M) -> gen_server:call(Pid, {decrypt, M}).

set_keys(Pid, M) -> gen_server:call(Pid, {set_keys, M}).

get_key(Pid) -> gen_server:call(Pid, get_key).

%F{{{ gen_server callbacks
init([]) ->
    {ok,
     #s{dh = otr_crypto:dh_gen_key(),
	previous_dh = otr_crypto:dh_gen_key(), our_id = 2}}.

handle_call(get_key, _From, State) ->
    {reply, {ok, {State#s.our_id - 1, State#s.previous_dh}},
     State};
handle_call({set_keys, {OurKeyId, _, TheirKeyId, Y}},
	    _From, State)
    when OurKeyId == State#s.our_id - 1, Y == State#s.y,
	 TheirKeyId == State#s.their_id ->
    {reply, ok, State};
handle_call({set_keys, {OurKeyId, _, TheirKeyId, Y}},
	    _From, State)
    when OurKeyId == State#s.our_id - 1,
	 TheirKeyId == State#s.their_id - 1,
	 Y == State#s.previous_y ->
    {reply, ok, State};
handle_call({set_keys, {OurKeyId, _, TheirKeyId, Y}},
	    _From, State)
    when OurKeyId == State#s.our_id - 1 ->
    {reply, ok,
     State#s{y = Y, their_id = TheirKeyId,
	     previous_y = undefined, dmk = [],
	     reveal_macs =
		 add_reveal_macs(State#s.reveal_macs, State#s.dmk)}};
handle_call({set_keys,
	     {OurKeyId, OurDh, TheirKeyId, Y}},
	    _From, State) ->
    {reply, ok,
     State#s{y = Y, their_id = TheirKeyId,
	     previous_y = undefined, dh = otr_crypto:dh_gen_key(),
	     previous_dh = OurDh, our_id = OurKeyId + 1, dmk = [],
	     reveal_macs =
		 add_reveal_macs(State#s.reveal_macs, State#s.dmk)}};
handle_call({encrypt, {M, TLV, Flags}}, _From, State) ->
    K = {OId, TId} = {State#s.our_id - 1, State#s.their_id},
    {ok, Dmk} = get_dmk(State, OId, TId),
    Ctr = Dmk#dmk.tx_ctr + 1,
    EncD = otr_crypto:aes_ctr_128_encrypt(Dmk#dmk.tx_key,
					  <<Ctr:64>>, otr_tlv:encode({M, TLV})),
    DM = #otr_msg_data{flags = Flags, sender_keyid = OId,
		       enc_data = EncD, recipient_keyid = TId,
		       ctr_init = <<Ctr:64>>,
		       dhy = element(2, State#s.dh)},
    Mac = otr_crypto:sha1HMAC(Dmk#dmk.tx_mac,
			      otr_message:encode_data_for_hmac(DM)),
    {reply,
     {ok,
      DM#otr_msg_data{mac = Mac,
		      old_mac_keys = State#s.reveal_macs}},
     State#s{reveal_macs = <<>>,
	     dmk =
		 lists:keystore(K, 1, State#s.dmk,
				{K, Dmk#dmk{tx_ctr = Ctr}})}};
handle_call({decrypt,
	     #otr_msg_data{recipient_keyid = OId, sender_keyid = TId,
			   ctr_init = <<Ctr:64>>} =
		 M},
	    _From, State) ->
    case get_dmk(State, OId, TId) of
      error -> {reply, {rejected, no_keys}, State};
      {ok, Dmk} ->
	  Mac = otr_crypto:sha1HMAC(Dmk#dmk.rx_mac,
				   otr_message:encode_data_for_hmac(M)),
	  if Mac /= M#otr_msg_data.mac ->
		 {reply, {rejected, mac_missmatch}, State};
	     Ctr =< Dmk#dmk.rx_ctr ->
		 {reply, {rejected, ctr_to_low}, State};
	     true ->
		 Data = otr_crypto:aes_ctr_128_decrypt(Dmk#dmk.rx_key,
						       <<Ctr:64>>,
						       M#otr_msg_data.enc_data),
		 DhY = M#otr_msg_data.dhy,
		 K = {OId, TId},
		 NS0 = rotate_keys(State, OId, TId, DhY),
		 Dmk0 = Dmk#dmk{rx_ctr = Ctr},
		 NS1 = NS0#s{dmk =
				 lists:keystore(K, 1, NS0#s.dmk, {K, Dmk0})},
		 {reply, {ok, otr_tlv:decode(Data)}, NS1}
	  end
    end;
handle_call(_Call, _From, _State) ->
    % {reply, Reply, NewState}
    {stop, {undefined_call, _Call}, _State}.

handle_info(_Info, _State) ->
    {stop, {undefined_info, _Info}, _State}.

handle_cast(_Cast, _State) ->
    {stop, {undefined_cast, _Cast}, _State}.

terminate(_Reason, _State) -> ok.

code_change(_OldVsn, State, _Extra) -> {ok, State}.

%}}}F

%F{{{ internal functions

rotate_keys(State, OId, TId, Y) ->
    rotate_their_keys(rotate_our_keys(State, OId), TId, Y).

rotate_our_keys(#s{our_id = OId} = State, OId) ->
    F0 = fun ({{O, _}, _}) -> O == OId - 1 end,
    {OldDmk, Dmk} = lists:partition(F0, State#s.dmk),
    State#s{our_id = OId + 1, previous_dh = State#s.dh,
	    dh = otr_crypto:dh_gen_key(), dmk = Dmk,
	    reveal_macs =
		add_reveal_macs(State#s.reveal_macs, OldDmk)};
rotate_our_keys(State, _) -> State.

rotate_their_keys(#s{their_id = TId} = State, TId, Y) ->
    F0 = fun ({{_, T}, _}) -> T == TId - 1 end,
    {OldDmk, Dmk} = lists:partition(F0, State#s.dmk),
    State#s{their_id = TId + 1, previous_y = State#s.y,
	    y = Y, dmk = Dmk,
	    reveal_macs =
		add_reveal_macs(State#s.reveal_macs, OldDmk)};
rotate_their_keys(State, _, _) -> State.

add_reveal_macs(RvM, Dmk) ->
    lists:foldr(fun ({_, D}, Acc) ->
			if D#dmk.rx_ctr == 0 -> Acc;
			   true -> <<(D#dmk.rx_mac)/binary, Acc/binary>>
			end
		end,
		RvM, Dmk).

get_dmk(State, OurId, TheirId) ->
    case lists:keyfind({OurId, TheirId}, 1, State#s.dmk) of
      {{_, _}, Dmk} -> {ok, Dmk};
      false -> make_dmk(State, OurId, TheirId)
    end.

make_dmk(State, OurId, TheirId) ->
    case get_dh_keys(State, OurId, TheirId) of
      error -> error;
      {ok, {OurPriv, OurPub}, TheirPub} ->
	  SecB = otr_util:mpint(otr_crypto:dh_agree(OurPriv,
						    TheirPub)),
	  {TxB, RxB} = if OurPub > TheirPub -> {1, 2};
			  true -> {2, 1}
		       end,
	  <<TxK:16/binary, _/binary>> = otr_crypto:sha1(<<TxB,
							  SecB/binary>>),
	  <<RxK:16/binary, _/binary>> = otr_crypto:sha1(<<RxB,
							  SecB/binary>>),
	  {ok,
	   #dmk{tx_key = TxK, rx_key = RxK,
		tx_mac = otr_crypto:sha1(TxK),
		rx_mac = otr_crypto:sha1(RxK)}}
    end.

get_dh_keys(#s{their_id = T, our_id = O} = State, O,
	    T) ->
    {ok, State#s.dh, State#s.y};
get_dh_keys(#s{their_id = T, our_id = O} = State, OO, T)
    when OO == O - 1 ->
    {ok, State#s.previous_dh, State#s.y};
% TODO: about the follwoing 2 cases: 
%       i'm not sure if the protocoll even allows to reach a
%       state where these keys might be requested...
%       but since we have them...
get_dh_keys(#s{their_id = T, our_id = O} = State, O, TT)
    when (TT == T - 1) and State#s.previous_y /=
	   undefined ->
    {ok, State#s.dh, State#s.previous_y};
get_dh_keys(#s{their_id = T, our_id = O} = State, OO,
	    TT)
    when (TT == T - 1) and (State#s.previous_y /= undefined)
	   and (OO == O - 1) ->
    {ok, State#s.previous_dh, State#s.previous_y};
get_dh_keys(_, _, _) -> error.

%}}}F

