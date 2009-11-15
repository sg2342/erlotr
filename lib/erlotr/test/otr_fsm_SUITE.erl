-module(otr_fsm_SUITE).

-author("Stefan Grundmann <sg2342@googlemail.com>").

-compile(export_all).

-include("ct.hrl").

-include("otr_internal.hrl").

-include("MessageTestVectors.hrl").

-include("DSATestVectors.hrl").

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
    [pt_usr_1, pt_usr_2, pt_usr_start, pt_usr_stop,
     pt_net_1, pt_net_error_1, pt_net_error_2, pt_net_data, ake_msg,
     cover].

%F{{{ init_per_testcase/2
init_per_testcase(pt_usr_2, Config) ->
    setup_fsm(Config, [send_whitespace_tag]);
init_per_testcase(pt_net_error_2, Config) ->
    setup_fsm(Config, [error_start_ake]);
init_per_testcase(ake_msg, Config) -> setup_pair(Config);
init_per_testcase(_TestCase, Config) ->
    setup_fsm(Config, []).

%}}}F

%F{{{ end_per_testcase/2
end_per_testcase(ake_msg, Config) ->
    catch unlink(whereis(fsm2)),
    catch exit(whereis(fsm2), shutdown),
    catch unlink(whereis(fsm1)),
    catch exit(whereis(fsm1), shutdown),
    catch unlink(whereis(net_pipe)),
    net_pipe ! stop,
    Config;
end_per_testcase(_TestCase, Config) ->
    case ?config(fsm, Config) of
      undefined -> ok;
      Fsm ->
	  unlink(Fsm),
	  catch exit(Fsm, shutdown),
	  false = is_process_alive(Fsm)
    end,
    case ?config(parser, Config) of
      undefined -> ok;
      Parser ->
	  unlink(Parser),
	  catch exit(Parser, shutdown),
	  false = is_process_alive(Parser)
    end,
    Config.%}}}F

ake_msg(_Config) ->
    otr_fsm:consume(fsm1, {user, start_otr}),
    {to_user1, {info, {encrypted_new_dsa_fp, _, _}}} =
	receive X -> erlang:display(X), X end,
    {to_user2, {info, {encrypted_new_dsa_fp, _, _}}} =
	receive Y -> erlang:display(Y), Y end,
    otr_fsm:consume(fsm2, {user, {message, "FOOO"}}),
    {to_user1, {message, "FOOO"}} = receive
				      Z -> erlang:display(Z), Z
				    end,
    ok.

pt_usr_1(Config) ->
    ct:comment("message from user while in state [plaintext]"),
    Fsm = (?config(fsm, Config)),
    otr_fsm:consume(Fsm, {user, {message, "foo bar baz"}}),
    R = {to_net, "foo bar baz"},
    R = receive R -> R after 500 -> timeout end.

pt_usr_2(Config) ->
    ct:comment("message from user while in state [plaintext] "
	       "with send_whitespace_tag=true"),
    Fsm = (?config(fsm, Config)),
    otr_fsm:consume(Fsm, {user, {message, "foo"}}),
    R = {to_net, "foo \t  \t\t\t\t \t \t \t    \t\t  \t "},
    R = receive R -> R after 500 -> timeout end.

pt_usr_start(Config) ->
    ct:comment("start_otr from user while in state [plaintext]"),
    Fsm = (?config(fsm, Config)),
    otr_fsm:consume(Fsm, {user, start_otr}),
    R = {to_net, "?OTRv2?"},
    R = receive R -> R after 500 -> timeout end.

pt_usr_stop(Config) ->
    ct:comment("stop_otr from user while in state [plaintext]"),
    Fsm = (?config(fsm, Config)),
    otr_fsm:consume(Fsm, {user, stop_otr}),
    timeout = receive R -> R after 1000 -> timeout end.

pt_net_1(Config) ->
    ct:comment("plaintext message from network while "
	       "in state [plaintext]"),
    Parser = (?config(parser, Config)),
    otr_parser_fsm:consume(Parser, "foo bar baz"),
    R = {to_user, {message, "foo bar baz", []}},
    R = receive R -> R after 500 -> timeout end.

pt_net_error_1(Config) ->
    ct:comment("error message from network while in "
	       "state [plaintext]"),
    Parser = (?config(parser, Config)),
    otr_parser_fsm:consume(Parser,
			   "?OTR Error:Some error."),
    R = {to_user, {error_net, "Some error."}},
    R = receive R -> R after 500 -> timeout end.

pt_net_error_2(Config) ->
    ct:comment("error message from network while in "
	       "state [plaintext] with error_start_ake=true"),
    Parser = (?config(parser, Config)),
    otr_parser_fsm:consume(Parser,
			   "?OTR Error:Some error."),
    R1 = {to_net, "?OTRv2?"},
    R1 = receive R1 -> R1 after 500 -> timeout end,
    R2 = {to_user, {error_net, "Some error."}},
    R2 = receive R2 -> R2 after 500 -> timeout end.

pt_net_data(Config) ->
    ct:comment("data message from network while in start "
	       "[plaintext]"),
    Parser = (?config(parser, Config)),
    {M, _} = (?MessageTestVector5),
    otr_parser_fsm:consume(Parser, M),
    R1 = {to_user, {error, unreadable_encrypted_received}},
    R1 = receive R1 -> R1 after 500 -> timeout end,
    R2 = {to_net,
	  "?OTR Error:You sent an encrypted message, "
	  "but we finished th private conversation"},
    R2 = receive R2 -> R2 after 500 -> timeout end.

cover(_Config) ->
    ct:comment("achive 100% coverage: call code_change/4, "
	       "terminate/3 and the handle_... functions "
	       "that are meant to fail"),
    ok = otr_fsm:terminate(x, y, z),
    {ok, b, c} = otr_fsm:code_change(a, b, c, d),
    {stop, {b, undefined_info, a}, c} =
	otr_fsm:handle_info(a, b, c),
    {stop, {b, undefined_event, a}, c} =
	otr_fsm:handle_event(a, b, c),
    {stop, {c, undefined_sync_event, a}, d} =
	otr_fsm:handle_sync_event(a, b, c, d),
    ok.

%F{{{ internal functions

setup_pair(Config) ->
    Self = self(),
    EmitUser1 = fun (X) -> Self ! {to_user1, X} end,
    EmitUser2 = fun (X) -> Self ! {to_user2, X} end,
    EmitNet = fun (X) -> net_pipe ! {self(), X} end,
    {ok, Parser1} = otr_parser_fsm:start_link(),
    {ok, Parser2} = otr_parser_fsm:start_link(),
    {ok, Fsm1} = otr_fsm:start_link([{emit_user, EmitUser1},
				     {emit_net, EmitNet}, {dsa, ?DSAKey1}]),
    {ok, Fsm2} = otr_fsm:start_link([{emit_user, EmitUser2},
				     {emit_net, EmitNet}, {dsa, ?DSAKey2}]),
    otr_parser_fsm:set_emit_fun(Parser1,
				fun (X) -> otr_fsm:consume(Fsm1, {net, X}) end),
    otr_parser_fsm:set_emit_fun(Parser2,
				fun (X) -> otr_fsm:consume(Fsm2, {net, X}) end),
    NetPipe = spawn_link(fun () ->
				 net_pipe(Fsm1, Parser1, Fsm2, Parser2)
			 end),
    register(net_pipe, NetPipe),
    register(fsm1, Fsm1),
    register(fsm2, Fsm2),
    Config.

net_pipe(Fsm1, Parser1, Fsm2, Parser2) ->
    receive
      {Fsm1, M} -> otr_parser_fsm:consume(Parser2, M);
      {Fsm2, M} -> otr_parser_fsm:consume(Parser1, M);
      _ -> exit(kill)
    end,
    net_pipe(Fsm1, Parser1, Fsm2, Parser2).

setup_fsm(Config, Opts) ->
    Self = self(),
    EmitUser = fun (X) -> Self ! {to_user, X} end,
    EmitNet = fun (X) -> Self ! {to_net, X} end,
    {ok, Parser} = otr_parser_fsm:start_link(),
    {ok, Fsm} = otr_fsm:start_link([{emit_user, EmitUser},
				    {emit_net, EmitNet}, {dsa, ?DSAKey1}
				    | Opts]),
    otr_parser_fsm:set_emit_fun(Parser,
				fun (X) -> otr_fsm:consume(Fsm, {net, X}) end),
    [{fsm, Fsm}, {parser, Parser} | Config]. %}}}F

