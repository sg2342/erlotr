-module(otr_smp_fsm_SUITE).

-author("Stefan Grundmann <sg2342@googlemail.com>").

-compile(export_all).

-include("ct.hrl").

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
    [user_abort, user_start_1, user_start_2, user_start_3,
     e1_user_secret, e1_smp_inv, e1_smp_abort, e1_smp_1_1,
     e1_smp_1_2, wus_smp_abort, wus_smp_inv, wus_user_secret,
     e2_user_secret, e2_smp_inv, e2_smp_abort, e2_smp_2_1,
     e2_smp_2_2, e3_user_secret, e3_smp_inv, e3_smp_abort,
     e3_smp_3_1, e3_smp_3_2, e3_smp_3_3, e4_user_secret,
     e4_smp_inv, e4_smp_abort, e4_smp_4_1, e4_smp_4_2,
     e4_smp_4_3, cover].

init_per_testcase(_TestCase, Config) ->
    start_smp_fsm(Config).

end_per_testcase(_TestCase, Config) ->
    stop_smp_fsm(Config).


e1_user_secret(_Config) ->
    ct:comment("user supplied secret while in state "
	       "[expect1]"),
    {error, unexpected_user_secret} =
	otr_smp_fsm:user_secret(smp1, <<"some secret">>).

e1_smp_abort(_Config) ->
    ct:comment("smp_abort from net while in state [expect1]"),
    {error, net_aborted} = otr_smp_fsm:smp_msg(smp1,
					       smp_abort).

e1_smp_inv(_Config) ->
    ct:comment("smp msg that is not smp_msg_1 from net "
	       "while in state [expect1]"),
    {error, unexpected_smp_msg} = otr_smp_fsm:smp_msg(smp1,
						      {smp_msg_3, []}).

e1_smp_1_1(_Config) ->
    ct:comment("smp_msg_1 from net while in state [expect1]"),
    {ok, {emit, [M]}} = otr_smp_fsm:user_start(smp1,
					       <<"s">>),
    {ok, need_user_secret} = otr_smp_fsm:smp_msg(smp2, M).

e1_smp_1_2(_Config) ->
    ct:comment("smp_msg_1 from net while in state [expect1] "
	       "when the knowledge proof fails the check"),
    {ok, {emit, [M]}} = otr_smp_fsm:user_start(smp1,
					       <<"secret">>),
    {smp_msg_1, [GA2, C2, D2, GS3, C3, D3]} = M,
    N = {smp_msg_1, [GA2, C2, D2, GS3, C3, D3 + 1]},
    {error, proof_checking_failed} =
	otr_smp_fsm:smp_msg(smp2, N).



wus_smp_abort(_Config) ->
    ct:comment("smp_abort from net while in state [wait_user_"
	       "secret]"),
    {ok, {emit, [M]}} = otr_smp_fsm:user_start(smp2,
					       <<"s">>),
    {ok, need_user_secret} = otr_smp_fsm:smp_msg(smp1, M),
    {error, net_aborted} = otr_smp_fsm:smp_msg(smp1,
					       smp_abort).

wus_smp_inv(_Config) ->
    ct:comment("smp msg (/= smp_abort) from net while "
	       "in state [wait_user_secret]"),
    {ok, {emit, [M]}} = otr_smp_fsm:user_start(smp2,
					       <<"s">>),
    {ok, need_user_secret} = otr_smp_fsm:smp_msg(smp1, M),
    {error, unexpected_smp_msg} = otr_smp_fsm:smp_msg(smp1,
						      M).

wus_user_secret(_Config) ->
    ct:comment("secret input from user when in state "
	       "[wait_user_secret]"),
    {ok, {emit, [M]}} = otr_smp_fsm:user_start(smp2,
					       <<"s">>),
    {ok, need_user_secret} = otr_smp_fsm:smp_msg(smp1, M),
    {ok, {emit, [{smp_msg_2, _}]}} =
	otr_smp_fsm:user_secret(smp1, <<"s">>).




e2_user_secret(_Config) ->
    ct:comment("user supplied secret while in state "
	       "[expect2]"),
    {ok, {emit, [_]}} = otr_smp_fsm:user_start(smp1,
					       <<"s">>),
    {error, unexpected_user_secret} =
	otr_smp_fsm:user_secret(smp1, <<"some secret">>).

e2_smp_abort(_Config) ->
    ct:comment("smp_abort from net while in state [expect2]"),
    {ok, {emit, [_]}} = otr_smp_fsm:user_start(smp1,
					       <<"s">>),
    {error, net_aborted} = otr_smp_fsm:smp_msg(smp1,
					       smp_abort).

e2_smp_inv(_Config) ->
    ct:comment("smp msg that is not smp_msg_2 from net "
	       "while in state [expect2]"),
    {ok, {emit, [_]}} = otr_smp_fsm:user_start(smp1,
					       <<"s">>),
    {error, unexpected_smp_msg} = otr_smp_fsm:smp_msg(smp1,
						      {smp_msg_3, []}).

e2_smp_2_1(_Config) ->
    ct:comment("smp_msg_2 from net while in state [expect2]"),
    {ok, {emit, [M1]}} = otr_smp_fsm:user_start(smp1,
						<<"s">>),
    {ok, need_user_secret} = otr_smp_fsm:smp_msg(smp2, M1),
    {ok, {emit, [M2]}} = otr_smp_fsm:user_secret(smp2,
						 <<"s">>),
    {ok, {emit, [_]}} = otr_smp_fsm:smp_msg(smp1, M2).

e2_smp_2_2(_Config) ->
    ct:comment("smp_msg_2 from net while in state [expect2] "
	       "when the knowledge proof fails the check"),
    {ok, {emit, [M1]}} = otr_smp_fsm:user_start(smp1,
						<<"s">>),
    {ok, need_user_secret} = otr_smp_fsm:smp_msg(smp2, M1),
    {ok,
     {emit,
      [{smp_msg_2, [A, B, C, D, E, F, G, H, I, J, K]}]}} =
	otr_smp_fsm:user_secret(smp2, <<"s">>),
    {error, proof_checking_failed} =
	otr_smp_fsm:smp_msg(smp1,
			    {smp_msg_2, [A, B, C, D, E, F, G, H, I, J, K - 1]}).




e3_user_secret(_Config) ->
    ct:comment("user supplied secret while in state "
	       "[expect3]"),
    {ok, {emit, [M1]}} = otr_smp_fsm:user_start(smp1,
						<<"s">>),
    {ok, need_user_secret} = otr_smp_fsm:smp_msg(smp2, M1),
    {ok, {emit, [M2]}} = otr_smp_fsm:user_secret(smp2,
						 <<"s">>),
    {ok, {emit, [_]}} = otr_smp_fsm:smp_msg(smp1, M2),
    {error, unexpected_user_secret} =
	otr_smp_fsm:user_secret(smp2, <<"some secret">>).

e3_smp_abort(_Config) ->
    ct:comment("smp_abort from net while in state [expect3]"),
    {ok, {emit, [M1]}} = otr_smp_fsm:user_start(smp1,
						<<"s">>),
    {ok, need_user_secret} = otr_smp_fsm:smp_msg(smp2, M1),
    {ok, {emit, [M2]}} = otr_smp_fsm:user_secret(smp2,
						 <<"s">>),
    {ok, {emit, [_]}} = otr_smp_fsm:smp_msg(smp1, M2),
    {error, net_aborted} = otr_smp_fsm:smp_msg(smp2,
					       smp_abort).

e3_smp_inv(_Config) ->
    ct:comment("smp msg that is not smp_msg_3 from net "
	       "while in state [expect3]"),
    {ok, {emit, [M1]}} = otr_smp_fsm:user_start(smp1,
						<<"s">>),
    {ok, need_user_secret} = otr_smp_fsm:smp_msg(smp2, M1),
    {ok, {emit, [M2]}} = otr_smp_fsm:user_secret(smp2,
						 <<"s">>),
    {ok, {emit, [_]}} = otr_smp_fsm:smp_msg(smp1, M2),
    {error, unexpected_smp_msg} = otr_smp_fsm:smp_msg(smp2,
						      {smp_msg_4, []}).

e3_smp_3_1(_Config) ->
    ct:comment("smp_msg_3 from net while in state [expect3], "
	       "verification succeeded"),
    {ok, {emit, [M1]}} = otr_smp_fsm:user_start(smp1,
						<<"s">>),
    {ok, need_user_secret} = otr_smp_fsm:smp_msg(smp2, M1),
    {ok, {emit, [M2]}} = otr_smp_fsm:user_secret(smp2,
						 <<"s">>),
    {ok, {emit, [M3]}} = otr_smp_fsm:smp_msg(smp1, M2),
    {verification_succeeded, {emit, [_]}} =
	otr_smp_fsm:smp_msg(smp2, M3).

e3_smp_3_2(_Config) ->
    ct:comment("smp_msg_3 from net while in state [expect3], "
	       "verification failed"),
    {ok, {emit, [M1]}} = otr_smp_fsm:user_start(smp1,
						<<"s1223">>),
    {ok, need_user_secret} = otr_smp_fsm:smp_msg(smp2, M1),
    {ok, {emit, [M2]}} = otr_smp_fsm:user_secret(smp2,
						 <<"t">>),
    {ok, {emit, [M3]}} = otr_smp_fsm:smp_msg(smp1, M2),
    {verification_failed, {emit, [_]}} =
	otr_smp_fsm:smp_msg(smp2, M3).

e3_smp_3_3(_Config) ->
    ct:comment("smp_msg_3 from net while in state [expect3], "
	       "knowledge proof failed"),
    {ok, {emit, [M1]}} = otr_smp_fsm:user_start(smp1,
						<<"s1223">>),
    {ok, need_user_secret} = otr_smp_fsm:smp_msg(smp2, M1),
    {ok, {emit, [M2]}} = otr_smp_fsm:user_secret(smp2,
						 <<"t">>),
    {ok, {emit, [M3]}} = otr_smp_fsm:smp_msg(smp1, M2),
    {smp_msg_3, [A, B, C, D, E, F, G, H]} = M3,
    N = {smp_msg_3, [A, B, C, D, E, F, G, H - 1]},
    {error, proof_checking_failed} =
	otr_smp_fsm:smp_msg(smp2, N).





e4_user_secret(_Config) ->
    ct:comment("user supplied secret while in state "
	       "[expect4]"),
    {ok, {emit, [M1]}} = otr_smp_fsm:user_start(smp1,
						<<"s">>),
    {ok, need_user_secret} = otr_smp_fsm:smp_msg(smp2, M1),
    {ok, {emit, [M2]}} = otr_smp_fsm:user_secret(smp2,
						 <<"s">>),
    {ok, {emit, [_]}} = otr_smp_fsm:smp_msg(smp1, M2),
    {error, unexpected_user_secret} =
	otr_smp_fsm:user_secret(smp1, <<"some secret">>).

e4_smp_inv(_Config) ->
    ct:comment("smp msg that is not smp_msg_4 from net "
	       "while in state [expect4]"),
    {ok, {emit, [M1]}} = otr_smp_fsm:user_start(smp1,
						<<"s">>),
    {ok, need_user_secret} = otr_smp_fsm:smp_msg(smp2, M1),
    {ok, {emit, [M2]}} = otr_smp_fsm:user_secret(smp2,
						 <<"s">>),
    {ok, {emit, [_]}} = otr_smp_fsm:smp_msg(smp1, M2),
    {error, unexpected_smp_msg} = otr_smp_fsm:smp_msg(smp1,
						      {smp_msg_1, []}).

e4_smp_abort(_Config) ->
    ct:comment("smp_abort from net while in state [expect4]"),
    {ok, {emit, [M1]}} = otr_smp_fsm:user_start(smp1,
						<<"s">>),
    {ok, need_user_secret} = otr_smp_fsm:smp_msg(smp2, M1),
    {ok, {emit, [M2]}} = otr_smp_fsm:user_secret(smp2,
						 <<"s">>),
    {ok, {emit, [_]}} = otr_smp_fsm:smp_msg(smp1, M2),
    {error, net_aborted} = otr_smp_fsm:smp_msg(smp1,
					       smp_abort).

e4_smp_4_1(_Config) ->
    ct:comment("smp_msg_4 from net while in state [expect4], "
	       "verification succeeded"),
    {ok, {emit, [M1]}} = otr_smp_fsm:user_start(smp1,
						<<"s">>),
    {ok, need_user_secret} = otr_smp_fsm:smp_msg(smp2, M1),
    {ok, {emit, [M2]}} = otr_smp_fsm:user_secret(smp2,
						 <<"s">>),
    {ok, {emit, [M3]}} = otr_smp_fsm:smp_msg(smp1, M2),
    {verification_succeeded, {emit, [M4]}} =
	otr_smp_fsm:smp_msg(smp2, M3),
    {verification_succeeded, {emit, []}} =
	otr_smp_fsm:smp_msg(smp1, M4).

e4_smp_4_2(_Config) ->
    ct:comment("smp_msg_4 from net while in state [expect4], "
	       "verification failed"),
    {ok, {emit, [M1]}} = otr_smp_fsm:user_start(smp1,
						<<"X">>),
    {ok, need_user_secret} = otr_smp_fsm:smp_msg(smp2, M1),
    {ok, {emit, [M2]}} = otr_smp_fsm:user_secret(smp2,
						 <<"U">>),
    {ok, {emit, [M3]}} = otr_smp_fsm:smp_msg(smp1, M2),
    {verification_failed, {emit, [M4]}} =
	otr_smp_fsm:smp_msg(smp2, M3),
    {verification_failed, {emit, []}} =
	otr_smp_fsm:smp_msg(smp1, M4).

e4_smp_4_3(_Config) ->
    ct:comment("smp_msg_4 from net while in state [expect4], "
	       "knowledge proof failed"),
    {ok, {emit, [M1]}} = otr_smp_fsm:user_start(smp1,
						<<"s">>),
    {ok, need_user_secret} = otr_smp_fsm:smp_msg(smp2, M1),
    {ok, {emit, [M2]}} = otr_smp_fsm:user_secret(smp2,
						 <<"s">>),
    {ok, {emit, [M3]}} = otr_smp_fsm:smp_msg(smp1, M2),
    {verification_succeeded, {emit, [M4]}} =
	otr_smp_fsm:smp_msg(smp2, M3),
    {smp_msg_4, [A, B, C]} = M4,
    N = {smp_msg_4, [A + 1, B, C]},
    {error, proof_checking_failed} =
	otr_smp_fsm:smp_msg(smp1, N).





cover(_Config) ->
    ct:comment("achive 100% coverage: call code_change/4, "
	       "terminate/3 and the handle_... functions "
	       "that are meant to fail"),
    ok = otr_smp_fsm:terminate(x, y, z),
    {ok, b, c} = otr_smp_fsm:code_change(a, b, c, d),
    {stop, {b, undefined_info, a}, c} =
	otr_smp_fsm:handle_info(a, b, c),
    {stop, {b, undefined_event, a}, c} =
	otr_smp_fsm:handle_event(a, b, c),
    ok.

user_abort(_Config) ->
    ct:comment("user requests to abort SMP"),
    {ok, {emit, [smp_abort]}} =
	otr_smp_fsm:user_abort(smp1).

user_start_1(_Config) ->
    ct:comment("user requests to begin SMP"),
    {ok, {emit, [{smp_msg_1, _}]}} =
	otr_smp_fsm:user_start(smp1, <<"the secret">>).

user_start_2(_Config) ->
    ct:comment("user requests to begin SMP when not "
	       "in state [expect1]"),
    {ok, {emit, [{smp_msg_1, _}]}} =
	otr_smp_fsm:user_start(smp1, <<"the secret">>),
    {error, smp_underway} = otr_smp_fsm:user_start(smp1,
						   <<"the secret">>).

user_start_3(_Config) ->
    ct:comment("user requests to begin SMP (Question/Answer "
	       "instead of Shared Secret"),
    {ok, {emit, [{smp_msg_1q, _, _}]}} =
	otr_smp_fsm:user_start(smp1, <<"the question">>,
			       <<"the answer">>).





start_smp_fsm(Config) ->
    {ok, Smp1} = otr_smp_fsm:start_link(<<2:160>>,
					<<1:160>>, <<3:64>>),
    {ok, Smp2} = otr_smp_fsm:start_link(<<1:160>>,
					<<2:160>>, <<3:64>>),
    register(smp1, Smp1),
    register(smp2, Smp2),
    Config.

stop_smp_fsm(Config) ->
    lists:foreach(fun (X) ->
			  catch unlink(whereis(X)),
			  catch exit(whereis(X), shutdown)
		  end,
		  [smp1, smp2]),
    Config.



