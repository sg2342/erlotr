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
    [user_abort, user_start_1, user_start_2, e1_user_secret,
     e1_smp_inv, e1_smp_abort, e1_smp_1_1, e1_smp_1_2,
     wus_smp_abort, wus_smp_inv, wus_user_secret, cover].

init_per_testcase(_TestCase, Config) ->
    start_smp_fsm(Config).

end_per_testcase(_TestCase, Config) ->
    stop_smp_fsm(Config).

%F{{{ e1_.../1
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
	otr_smp_fsm:smp_msg(smp2, N).%}}}F

%{{{F wus_.../1

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
	gen_fsm:sync_send_event(smp1, {user_secret, <<"s">>}, infinity).
%	otr_smp_fsm:user_secret(smp1, <<"s">>, 500000).

%}}}F

%F{{{
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

%}}}F

%F{{{ internal functions
start_smp_fsm(Config) ->
    {ok, Smp1} = otr_smp_fsm:start_link(<<1:160>>,
					<<2:160>>, <<3:64>>),
    {ok, Smp2} = otr_smp_fsm:start_link(<<2:160>>,
					<<1:160>>, <<3:64>>),
    register(smp1, Smp1),
    register(smp2, Smp2),
    Config.

stop_smp_fsm(Config) ->
    lists:foreach(fun (X) ->
			  catch unlink(whereis(X)),
			  catch exit(whereis(X), shutdown)
		  end,
		  [smp1, smp2]),
    Config.%}}}F

