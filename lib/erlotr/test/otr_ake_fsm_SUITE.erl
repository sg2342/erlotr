-module(otr_ake_fsm_SUITE).

-author("Stefan Grundmann <sg2342@googlemail.com>").

-compile(export_all).

-include("ct.hrl").

-include("otr_internal.hrl").

-include("DSATestVectors.hrl").

-include("MessageTestVectors.hrl").

init_per_suite(Config) ->
    case application:start(crypto) of
      ok ->
	  ct:comment("crypto application started"),
	  [{stop_crypto, true} | Config];
      {error, {already_started, crypto}} -> Config
    end.

end_per_suite(Config) ->
    case proplists:lookup(stop_crypto, Config) of
      {stop_crypto, true} ->
	  application:stop(crypto),
	  ct:comment("crypto application stopped");
      _ -> ok
    end,
    Config.

all() ->
    [none_start, none_dh_commit, none_ignored,
     awaiting_dhkey_dh_commit_1, awaiting_dhkey_dh_commit_2,
     awaiting_dhkey_dh_key_1, awaiting_dhkey_dh_key_2, awaiting_dhkey_ignored,
     awaiting_revealsig_dh_commit,
     awaiting_revealsig_revealsig_1,
     awaiting_revealsig_revealsig_2,
     awaiting_revealsig_ignored, cover].

%F{{{ init_per_testcase/2
init_per_testcase(_TestCase, Config) ->
    setup_ake(Config, []).%}}}F

%F{{{ end_per_testcase/2
end_per_testcase(_TestCase, Config) ->
    case ?config(ake, Config) of
      undefined -> ok;
      Ake ->
	  unlink(Ake),
	  catch exit(Ake, shutdown),
	  false = is_process_alive(Ake)
    end.

%}}}F

%F{{{ testcases

%F{{{ none_...
none_start(Config) ->
    ct:comment("process start command while in state "
	       "[none]"),
    Ake = (?config(ake, Config)),
    otr_ake_fsm:consume(Ake, {cmd, start}),
    ok = receive
	   {to_net, #otr_msg_dh_commit{}} -> ok
	   after 500 -> timeout
	 end.

none_dh_commit(Config) ->
    ct:comment("process DH_COMMIT message while in state "
	       "[none]"),
    Ake = (?config(ake, Config)),
    {_, M} = (?MessageTestVector1),
    otr_ake_fsm:consume(Ake, M),
    ok = receive
	   {to_net, #otr_msg_dh_key{}} -> ok after 500 -> timeout
	 end.

none_ignored(Config) ->
    ct:comment("ignore DH_KEY, REVEAL_SIGNATURE, SIGNATURE "
	       "messages while in state [none]"),
    Ake = (?config(ake, Config)),
    otr_ake_fsm:consume(Ake, #otr_msg_dh_key{}),
    otr_ake_fsm:consume(Ake, #otr_msg_reveal_signature{}),
    otr_ake_fsm:consume(Ake, #otr_msg_signature{}),
    ok = receive _ -> notok after 500 -> ok end.

%}}}F

%F{{{ awaiting_dhkey_...
awaiting_dhkey_dh_commit_1(Config) ->
    ct:comment("process DH_COMMIT message while in state "
	       "[awaiting_dhkey], when Hash of the processed "
	       "message is lower than that of the  previously "
	       "emited one"),
    Ake = (?config(ake, Config)),
    otr_ake_fsm:consume(Ake, {cmd, start}),
    {ok, M} = receive
		{to_net, #otr_msg_dh_commit{} = X} -> {ok, X}
		after 500 -> timeout
	      end,
    <<Hash:256>> = M#otr_msg_dh_commit.hash_gx,
    otr_ake_fsm:consume(Ake,
			M#otr_msg_dh_commit{hash_gx = <<(Hash - 1):256>>}),
    ok = receive
	   {to_net, M} -> ok after 1500 -> timeout
	 end.

awaiting_dhkey_dh_commit_2(Config) ->
    ct:comment("process DH_COMMIT message while in state "
	       "[awaiting_dhkey], when Hash of the processed "
	       "message is higher than that of the  "
	       "previously emited one"),
    Ake = (?config(ake, Config)),
    otr_ake_fsm:consume(Ake, {cmd, start}),
    {ok, M} = receive
		{to_net, #otr_msg_dh_commit{} = X} -> {ok, X}
		after 500 -> timeout
	      end,
    <<Hash:256>> = M#otr_msg_dh_commit.hash_gx,
    otr_ake_fsm:consume(Ake,
			M#otr_msg_dh_commit{hash_gx = <<(Hash + 1):256>>}),
    ok = receive
	   {to_net, #otr_msg_dh_key{}} -> ok after 1500 -> timeout
	 end.

awaiting_dhkey_dh_key_1(Config) ->
    ct:comment("process DH_KEY message while in state "
	       "[awaiting_dhkey]"),
    Ake = (?config(ake, Config)),
    otr_ake_fsm:consume(Ake, {cmd, start}),
    ok = receive
	   {to_net, #otr_msg_dh_commit{}} -> ok
	   after 500 -> timeout
	 end,
    {_, M} = (?MessageTestVector2),
    otr_ake_fsm:consume(Ake, M),
    ok = receive
	   {to_net, #otr_msg_reveal_signature{}} -> ok
	   after 500 -> timeout
	 end.

awaiting_dhkey_dh_key_2(Config) ->
    ct:comment("process DH_KEY message while in state "
	       "[awaiting_dhkey] when the received pulic key is illegal"),
    Ake = (?config(ake, Config)),
    otr_ake_fsm:consume(Ake, {cmd, start}),
    ok = receive
	   {to_net, #otr_msg_dh_commit{}} -> ok
	   after 500 -> timeout
	 end,
    M = #otr_msg_dh_key{gy = 1},
    otr_ake_fsm:consume(Ake, M),
    ok = receive
	   {to_net, #otr_msg_dh_commit{}} -> ok
	   after 500 -> timeout
	 end.
awaiting_dhkey_ignored(Config) ->
    ct:comment("ignore REVEAL_SIGNATURE, SIGNATURE messages "
	       "while in state [awaiting_dhkey]"),
    Ake = (?config(ake, Config)),
    otr_ake_fsm:consume(Ake, {cmd, start}),
    ok = receive
	   {to_net, #otr_msg_dh_commit{}} -> ok
	   after 500 -> timeout
	 end,
    otr_ake_fsm:consume(Ake, #otr_msg_reveal_signature{}),
    otr_ake_fsm:consume(Ake, #otr_msg_signature{}),
    ok = receive _ -> notok after 500 -> ok end.

%}}}F

%F{{{ awaiting_revealsig_...
awaiting_revealsig_dh_commit(Config) ->
    ct:comment("process DH_COMMIT message while in state "
	       "[awaiting_revealsig]"),
    Ake = (?config(ake, Config)),
    {_, M} = (?MessageTestVector1),
    otr_ake_fsm:consume(Ake, M),
    {ok, K} = receive
		{to_net, #otr_msg_dh_key{} = X} -> {ok, X}
		after 500 -> timeout
	      end,
    {_, R} = (?MessageTestVector1),
    otr_ake_fsm:consume(Ake, R),
    ok = receive {to_net, K} -> ok after 500 -> timeout end.

awaiting_revealsig_revealsig_1(Config) ->
    ct:comment("process REVEALSIG message while in state "
	       "[awaiting_revealsig], when the gx hash "
	       "in the DH_COMMIT message  submitted "
	       "before does not check out"),
    Ake = (?config(ake, Config)),
    {_, M} = (?MessageTestVector1),
    otr_ake_fsm:consume(Ake, M),
    ok = receive
	   {to_net, #otr_msg_dh_key{}} -> ok after 500 -> timeout
	 end,
    {_, R} = (?MessageTestVector3),
    Rinvalid = R#otr_msg_reveal_signature{r = <<0:128>>},
    otr_ake_fsm:consume(Ake, Rinvalid),
    ok = receive _ -> notok after 500 -> ok end.

awaiting_revealsig_revealsig_2(Config) ->
    ct:comment("process REVEALSIG message while in state "
	       "[awaiting_revealsig], when decrypting "
	       "the signature fails"),
    Ake = (?config(ake, Config)),
    {_, M} = (?MessageTestVector1),
    otr_ake_fsm:consume(Ake, M),
    ok = receive
	   {to_net, #otr_msg_dh_key{}} -> ok after 500 -> timeout
	 end,
    {_, R} = (?MessageTestVector3),
    otr_ake_fsm:consume(Ake, R),
    ok = receive _ -> notok after 500 -> ok end.

awaiting_revealsig_ignored(Config) ->
    ct:comment("ignore DH_KEY, SIGNATURE messages while "
	       "in state [awaiting_revealsig]"),
    Ake = (?config(ake, Config)),
    {_, M} = (?MessageTestVector1),
    otr_ake_fsm:consume(Ake, M),
    ok = receive
	   {to_net, #otr_msg_dh_key{}} -> ok after 500 -> timeout
	 end,
    otr_ake_fsm:consume(Ake, #otr_msg_dh_key{}),
    otr_ake_fsm:consume(Ake, #otr_msg_signature{}),
    ok = receive _ -> notok after 500 -> ok end.

%}}}F

cover(_Config) ->
    ct:comment("achive 100% coverage: call code_change/4, "
	       "terminate/3 and the handle_... functions "
	       "that are meant to fail"),
    ok = otr_ake_fsm:terminate(x, y, z),
    {ok, b, c} = otr_ake_fsm:code_change(a, b, c, d),
    {stop, {b, undefined_info, a}, c} =
	otr_ake_fsm:handle_info(a, b, c),
    {stop, {b, undefined_event, a}, c} =
	otr_ake_fsm:handle_event(a, b, c),
    {stop, {c, undefined_sync_event, a}, d} =
	otr_ake_fsm:handle_sync_event(a, b, c, d),
    ok.

%}}}F

%F{{{ internal functions
setup_ake(Config, _Opts) ->
    Self = self(),
    {DsaKey, _, _, _} = (?DSATestVector1),
    KeyId = 1,
    DhKey = otr_crypto:dh_gen_key(),
    EmitFsm = fun (X) -> Self ! {to_fsm, X} end,
    EmitNet = fun (X) -> Self ! {to_net, X} end,
    {ok, Ake} = otr_ake_fsm:start_link(KeyId, DhKey, DsaKey, EmitFsm,
				       EmitNet),
    [{ake, Ake} | Config].%}}}F

