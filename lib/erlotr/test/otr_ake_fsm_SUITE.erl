-module(otr_ake_fsm_SUITE).

-author("Stefan Grundmann <sg2342@googlemail.com>").

-compile(export_all).

-include("ct.hrl").

-include("otr_internal.hrl").

-include("DSATestVectors.hrl").

-include("MessageTestVectors.hrl").

init_per_suite(Config) ->
    NConfig = case application:start(crypto) of
		ok ->
		    ct:comment("crypto application started"),
		    [{stop_crypto, true} | Config];
		{error, {already_started, crypto}} -> Config
	      end,
    DhKey1 = otr_crypto:dh_gen_key(),
    DhKey2 = otr_crypto:dh_gen_key(),
    [{dh_key1, DhKey1}, {dh_key2, DhKey2} | NConfig].

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
     awaiting_dhkey_start, awaiting_dhkey_dh_commit_1,
     awaiting_dhkey_dh_commit_2, awaiting_dhkey_dh_key_1,
     awaiting_dhkey_dh_key_2, awaiting_dhkey_ignored,
     awaiting_revealsig_start, awaiting_revealsig_dh_commit,
     awaiting_revealsig_revealsig_1,
     awaiting_revealsig_revealsig_2,
     awaiting_revealsig_revealsig_3,
     awaiting_revealsig_ignored, awaiting_sig_start,
     awaiting_sig_dh_commit, awaiting_sig_dh_key,
     awaiting_sig_ignored, awaiting_sig_sig1,
     awaiting_sig_sig2, awaiting_sig_sig3, complete_ake,
     cover].

%F{{{ init_per_testcase/2

init_per_testcase(awaiting_sig_start, Config) ->
    setup_2ake(Config, []);
init_per_testcase(awaiting_sig_dh_commit, Config) ->
    setup_2ake(Config, []);
init_per_testcase(awaiting_sig_dh_key, Config) ->
    setup_2ake(Config, []);
init_per_testcase(awaiting_sig_ignored, Config) ->
    setup_2ake(Config, []);
init_per_testcase(awaiting_sig_sig1, Config) ->
    setup_2ake(Config, []);
init_per_testcase(awaiting_sig_sig2, Config) ->
    setup_2ake(Config, []);
init_per_testcase(awaiting_sig_sig3, Config) ->
    setup_2ake(Config, []);
init_per_testcase(awaiting_revealsig_revealsig_3,
		  Config) ->
    DhKeyIllegal = {2, 1},
    NConfig = [{dh_key1, DhKeyIllegal}
	       | lists:keydelete(dh_key1, 1, Config)],
    setup_2ake(NConfig, []);
init_per_testcase(complete_ake, Config) ->
    setup_2ake(Config, []);
init_per_testcase(_TestCase, Config) ->
    setup_ake(Config, []).%}}}F

%F{{{ end_per_testcase/2
end_per_testcase(_TestCase, Config) ->
    F = fun (X) ->
		case ?config(X, Config) of
		  undefined -> ok;
		  Ake ->
		      unlink(Ake),
		      catch exit(Ake, shutdown),
		      false = is_process_alive(Ake)
		end
	end,
    lists:foreach(F, [ake, ake1, ake2]),
    Config.%}}}F

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
awaiting_dhkey_start(Config) ->
    ct:comment("process start command while in state "
	       "[awaiting_dhkey]"),
    Ake = (?config(ake, Config)),
    otr_ake_fsm:consume(Ake, {cmd, start}),
    {ok, M} = receive
		{to_net, #otr_msg_dh_commit{} = X} -> {ok, X}
		after 500 -> timeout
	      end,
    <<Hash:256>> = M#otr_msg_dh_commit.hash_gx,
    otr_ake_fsm:consume(Ake, {cmd, start}),
    {ok, N} = receive
		{to_net, #otr_msg_dh_commit{} = Y} -> {ok, Y}
		after 500 -> timeout
	      end,
    <<Hash:256>> = N#otr_msg_dh_commit.hash_gx.

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
	       "[awaiting_dhkey] when the received pulic "
	       "key is illegal"),
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
awaiting_revealsig_start(Config) ->
    ct:comment("process start command while in state "
	       "[awaiting_revealsig]"),
    Ake = (?config(ake, Config)),
    {_, M} = (?MessageTestVector1),
    otr_ake_fsm:consume(Ake, M),
    {ok, _K} = receive
		 {to_net, #otr_msg_dh_key{} = X} -> {ok, X}
		 after 500 -> timeout
	       end,
    otr_ake_fsm:consume(Ake, {cmd, start}),
    ok = receive
	   {to_net, #otr_msg_dh_commit{}} -> ok
	   after 500 -> timeout
	 end.

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

awaiting_revealsig_revealsig_3(Config) ->
    ct:comment("process REVELSIG message while in state "
	       "[awaiting_revealsig], when the DH key "
	       "used by the peer was illegal"),
    Ake1 = (?config(ake1, Config)),
    Ake2 = (?config(ake2, Config)),
    Inject1 = fun (X) -> otr_ake_fsm:consume(Ake1, X) end,
    Receive1 = fun () ->
		       receive {to_net1, X} -> {ok, X} after 500 -> timeout end
	       end,
    Inject2 = fun (X) -> otr_ake_fsm:consume(Ake2, X) end,
    Receive2 = fun () ->
		       receive {to_net2, X} -> {ok, X} after 500 -> timeout end
	       end,
    Inject1({cmd, start}),
    {ok, DhCommit} = Receive1(),
    Inject2(DhCommit),
    {ok, DhKey} = Receive2(),
    Inject1(DhKey),
    {ok, RevealSignature} = Receive1(),
    Inject2(RevealSignature),
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

%F{{{ awaiting_sig
awaiting_sig_start(Config) ->
    ct:comment("process start command while in state "
	       "[awaiting_sig]"),
    Ake1 = (?config(ake1, Config)),
    Ake2 = (?config(ake2, Config)),
    Inject1 = fun (X) -> otr_ake_fsm:consume(Ake1, X) end,
    Receive1 = fun () ->
		       receive {to_net1, X} -> {ok, X} after 500 -> timeout end
	       end,
    Inject2 = fun (X) -> otr_ake_fsm:consume(Ake2, X) end,
    Receive2 = fun () ->
		       receive {to_net2, X} -> {ok, X} after 500 -> timeout end
	       end,
    Inject1({cmd, start}),
    {ok, DhCommit} = Receive1(),
    Inject2(DhCommit),
    {ok, DHKey} = Receive2(),
    Inject1(DHKey),
    {ok, _RevealSignature} = Receive1(),
    Inject1({cmd, start}),
    {ok, #otr_msg_dh_commit{}} = Receive1().

awaiting_sig_dh_commit(Config) ->
    ct:comment("process DH_COMMIT message while in state "
	       "[awaiting_sig]"),
    Ake1 = (?config(ake1, Config)),
    Ake2 = (?config(ake2, Config)),
    Inject1 = fun (X) -> otr_ake_fsm:consume(Ake1, X) end,
    Receive1 = fun () ->
		       receive {to_net1, X} -> {ok, X} after 500 -> timeout end
	       end,
    Inject2 = fun (X) -> otr_ake_fsm:consume(Ake2, X) end,
    Receive2 = fun () ->
		       receive {to_net2, X} -> {ok, X} after 500 -> timeout end
	       end,
    Inject1({cmd, start}),
    {ok, DhCommit} = Receive1(),
    Inject2(DhCommit),
    {ok, DHKey} = Receive2(),
    Inject1(DHKey),
    {ok, _RevealSignature} = Receive1(),
    Inject1(DhCommit),
    {ok, #otr_msg_dh_key{}} = Receive1().

awaiting_sig_dh_key(Config) ->
    ct:comment("process DH_KEY message while in state "
	       "[awaiting_sig], when the DDH pub key "
	       "in this message is the identical to "
	       "that received before"),
    Ake1 = (?config(ake1, Config)),
    Ake2 = (?config(ake2, Config)),
    Inject1 = fun (X) -> otr_ake_fsm:consume(Ake1, X) end,
    Receive1 = fun () ->
		       receive {to_net1, X} -> {ok, X} after 500 -> timeout end
	       end,
    Inject2 = fun (X) -> otr_ake_fsm:consume(Ake2, X) end,
    Receive2 = fun () ->
		       receive {to_net2, X} -> {ok, X} after 500 -> timeout end
	       end,
    Inject1({cmd, start}),
    {ok, DhCommit} = Receive1(),
    Inject2(DhCommit),
    {ok, DHKey} = Receive2(),
    Inject1(DHKey),
    {ok, RevealSignature} = Receive1(),
    Inject1(DHKey),
    {ok, RevealSignature} = Receive1().

awaiting_sig_ignored(Config) ->
    ct:comment("ignore DH_KEY and REVEAL_SIGNATURE messages "
	       "when in state [awaiting_sig]"),
    Ake1 = (?config(ake1, Config)),
    Ake2 = (?config(ake2, Config)),
    Inject1 = fun (X) -> otr_ake_fsm:consume(Ake1, X) end,
    Receive1 = fun () ->
		       receive {to_net1, X} -> {ok, X} after 500 -> timeout end
	       end,
    Inject2 = fun (X) -> otr_ake_fsm:consume(Ake2, X) end,
    Receive2 = fun () ->
		       receive {to_net2, X} -> {ok, X} after 500 -> timeout end
	       end,
    Inject1({cmd, start}),
    {ok, DhCommit} = Receive1(),
    Inject2(DhCommit),
    {ok, DHKey} = Receive2(),
    Inject1(DHKey),
    {ok, _RevealSignature} = Receive1(),
    Inject1(#otr_msg_dh_key{gy = otr_util:mpint(0)}),
    ok = receive _ -> notok after 500 -> ok end,
    Inject1(#otr_msg_reveal_signature{}),
    ok = receive _ -> notok after 500 -> ok end,
    ok.

awaiting_sig_sig1(Config) ->
    ct:comment("process SIGNATURE message in state [awaiting_"
	       "sig], \n    MAC of the SIGNATURE message "
	       "is wrong"),
    Ake1 = (?config(ake1, Config)),
    Ake2 = (?config(ake2, Config)),
    Inject1 = fun (X) -> otr_ake_fsm:consume(Ake1, X) end,
    Receive1 = fun () ->
		       receive {to_net1, X} -> {ok, X} after 500 -> timeout end
	       end,
    Inject2 = fun (X) -> otr_ake_fsm:consume(Ake2, X) end,
    Receive2 = fun () ->
		       receive {to_net2, X} -> {ok, X} after 500 -> timeout end
	       end,
    Inject1({cmd, start}),
    {ok, DhCommit} = Receive1(),
    Inject2(DhCommit),
    {ok, DhKey} = Receive2(),
    Inject1(DhKey),
    {ok, #otr_msg_reveal_signature{} = RevealSignature} =
	Receive1(),
    Inject2(RevealSignature),
    {ok, Signature} = Receive2(),
    ok = receive
	   {to_fsm2, _} -> ok after 500 -> timeout
	 end,
    Inject1(Signature#otr_msg_signature{mac = <<0:20>>}),
    ok = receive _ -> notok after 500 -> ok end.

awaiting_sig_sig2(Config) ->
    ct:comment("process SIGNATURE message in state [awaiting_"
	       "sig], when extraction of the dsa pubkey "
	       "fails"),
    Ake1 = (?config(ake1, Config)),
    Ake2 = (?config(ake2, Config)),
    Inject1 = fun (X) -> otr_ake_fsm:consume(Ake1, X) end,
    Receive1 = fun () ->
		       receive {to_net1, X} -> {ok, X} after 500 -> timeout end
	       end,
    Inject2 = fun (X) -> otr_ake_fsm:consume(Ake2, X) end,
    Receive2 = fun () ->
		       receive {to_net2, X} -> {ok, X} after 500 -> timeout end
	       end,
    Inject1({cmd, start}),
    {ok, DhCommit} = Receive1(),
    Inject2(DhCommit),
    {ok, DhKey} = Receive2(),
    Inject1(DhKey),
    {ok, RevealSignature} = Receive1(),
    {_, DhPub1} = (?config(dh_key1, Config)),
    {DhPriv2, _} = (?config(dh_key2, Config)),
    S = otr_crypto:dh_agree(DhPriv2, DhPub1),
    MpiS = otr_util:mpint(S),
    <<CX:16/binary, _:16/binary>> = otr_crypto:sha256(<<1,
							MpiS/binary>>),
    M2X = otr_crypto:sha256(<<3, MpiS/binary>>),
    Sig = otr_crypto:aes_ctr_128_decrypt(CX, <<0:64>>,
					 RevealSignature#otr_msg_reveal_signature.enc_sig),
    <<X:32, RSig/binary>> = Sig,
    NSig = <<(X + 1):32, RSig/binary>>,
    EncSig = otr_crypto:aes_ctr_128_decrypt(CX, <<0:64>>,
					    NSig),
    <<Mac:20/binary, _/binary>> = otr_crypto:sha256HMAC(M2X,
							<<(size(EncSig)):32,
							  EncSig/binary>>),
    Inject2(RevealSignature#otr_msg_reveal_signature{enc_sig
							 = EncSig,
						     mac = Mac}),
    ok = receive _ -> notok after 500 -> ok end.

awaiting_sig_sig3(Config) ->
    ct:comment("process SIGNATURE message in state [awaiting_"
	       "sig], when signature does not verify"),
    Ake1 = (?config(ake1, Config)),
    Ake2 = (?config(ake2, Config)),
    Inject1 = fun (X) -> otr_ake_fsm:consume(Ake1, X) end,
    Receive1 = fun () ->
		       receive {to_net1, X} -> {ok, X} after 500 -> timeout end
	       end,
    Inject2 = fun (X) -> otr_ake_fsm:consume(Ake2, X) end,
    Receive2 = fun () ->
		       receive {to_net2, X} -> {ok, X} after 500 -> timeout end
	       end,
    Inject1({cmd, start}),
    {ok, DhCommit} = Receive1(),
    Inject2(DhCommit),
    {ok, DhKey} = Receive2(),
    Inject1(DhKey),
    {ok, RevealSignature} = Receive1(),
    {_, DhPub1} = (?config(dh_key1, Config)),
    {DhPriv2, _} = (?config(dh_key2, Config)),
    S = otr_crypto:dh_agree(DhPriv2, DhPub1),
    MpiS = otr_util:mpint(S),
    <<CX:16/binary, _:16/binary>> = otr_crypto:sha256(<<1,
							MpiS/binary>>),
    M2X = otr_crypto:sha256(<<3, MpiS/binary>>),
    Sig = otr_crypto:aes_ctr_128_decrypt(CX, <<0:64>>,
					 RevealSignature#otr_msg_reveal_signature.enc_sig),
    RSigZ = size(Sig) - 4,
    <<RSig:RSigZ/binary, X:32>> = Sig,
    NSig = <<RSig/binary, (X + 1):32>>,
    EncSig = otr_crypto:aes_ctr_128_decrypt(CX, <<0:64>>,
					    NSig),
    <<Mac:20/binary, _/binary>> = otr_crypto:sha256HMAC(M2X,
							<<(size(EncSig)):32,
							  EncSig/binary>>),
    Inject2(RevealSignature#otr_msg_reveal_signature{enc_sig
							 = EncSig,
						     mac = Mac}),
    ok = receive _ -> notok after 500 -> ok end.

    %}}}F

complete_ake(Config) ->
    ct:comment("complete Authenticated Key Exchange"),
    Ake1 = (?config(ake1, Config)),
    Ake2 = (?config(ake2, Config)),
    DhPub1 = (?config(dh_pub1, Config)),
    DhPub2 = (?config(dh_pub2, Config)),
    DsaFP1 = (?config(dsa_fp1, Config)),
    DsaFP2 = (?config(dsa_fp2, Config)),
    KeyId1 = (?config(key_id1, Config)),
    KeyId2 = (?config(key_id2, Config)),
    Inject1 = fun (X) -> otr_ake_fsm:consume(Ake1, X) end,
    Receive1 = fun () ->
		       receive {to_net1, X} -> {ok, X} after 500 -> timeout end
	       end,
    Inject2 = fun (X) -> otr_ake_fsm:consume(Ake2, X) end,
    Receive2 = fun () ->
		       receive {to_net2, X} -> {ok, X} after 500 -> timeout end
	       end,
    Inject1({cmd, start}),
    {ok, DhCommit} = Receive1(),
    Inject2(DhCommit),
    {ok, DhKey} = Receive2(),
    Inject1(DhKey),
    {ok, RevealSignature} = Receive1(),
    Inject2(RevealSignature),
    {ok, Signature} = Receive2(),
    {ok, SSID} = receive
	   {to_fsm2, {encrypted, {KeyId1, DhPub1, DsaFP1, S1}}} -> {ok, S1}
	   after 500 -> timeout
	 end,
    Inject1(Signature),
    {ok, SSID} = receive
	   {to_fsm1, {encrypted, {KeyId2, DhPub2, DsaFP2, S2}}} -> {ok, S2}
	   after 500 -> timeout
	 end,
    ok.

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
setup_2ake(Config, _Opts) ->
    Self = self(),
    PubKeyFp = fun ([P, Q, G, _, Y]) ->
		       [MpiP, MpiQ, MpiG, MpiY] = [otr_util:mpint(V)
						   || V <- [P, Q, G, Y]],
		       otr_crypto:sha1(<<MpiP/binary, MpiQ/binary, MpiG/binary,
					 MpiY/binary>>)
	       end,
    DsaKey1 = (?DSAKey1),
    DsaKey2 = (?DSAKey2),
    KeyId1 = 23,
    KeyId2 = 42,
    DhKey1 = {_, DhPub1} = (?config(dh_key1, Config)),
    DhKey2 = {_, DhPub2} = (?config(dh_key2, Config)),
    EmitFsm1 = fun (X) -> Self ! {to_fsm1, X} end,
    EmitNet1 = fun (X) -> Self ! {to_net1, X} end,
    EmitFsm2 = fun (X) -> Self ! {to_fsm2, X} end,
    EmitNet2 = fun (X) -> Self ! {to_net2, X} end,
    {ok, Ake1} = otr_ake_fsm:start_link(KeyId1, DhKey1,
					DsaKey1, EmitFsm1, EmitNet1),
    {ok, Ake2} = otr_ake_fsm:start_link(KeyId2, DhKey2,
					DsaKey2, EmitFsm2, EmitNet2),
    [{ake1, Ake1}, {ake2, Ake2}, {dh_pub1, DhPub1},
     {dsa_fp1, PubKeyFp(DsaKey1)},
     {dsa_fp2, PubKeyFp(DsaKey2)}, {dh_pub2, DhPub2},
     {key_id1, KeyId1}, {key_id2, KeyId2}
     | Config].

setup_ake(Config, _Opts) ->
    Self = self(),
    {DsaKey, _, _, _} = (?DSATestVector1),
    KeyId = 1,
    DhKey = (?config(dh_key1, Config)),
    EmitFsm = fun (X) -> Self ! {to_fsm, X} end,
    EmitNet = fun (X) -> Self ! {to_net, X} end,
    {ok, Ake} = otr_ake_fsm:start_link(KeyId, DhKey, DsaKey,
				       EmitFsm, EmitNet),
    [{ake, Ake} | Config].%}}}F

