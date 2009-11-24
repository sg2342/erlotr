-module(otr_fsm_SUITE).

-author("Stefan Grundmann <sg2342@googlemail.com>").

-compile(export_all).

-include("ct.hrl").

-include("otr_internal.hrl").

-include("MessageTestVectors.hrl").

-include("DSATestVectors.hrl").

-define(TAG_V2, " \t  \t\t\t\t \t \t \t    \t\t  \t ").

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
    [pt_usr_1, pt_usr_2, pt_usr_3, pt_usr_start,
     pt_usr_stop, pt_net_1, pt_net_malfored, pt_net_error_1,
     pt_net_error_2, pt_net_data, pt_net_dh_key,
     pt_net_reveal_signature, pt_net_signature,
     pt_net_tagged_ws_1, pt_net_tagged_ws_2,
     pt_net_tagged_ws_3, pt_net_query_1, pt_net_query_2,
     pt_ake_msg_1, pt_ake_msg_2, enc_usr_start, enc_usr_stop,
     enc_net_plain, enc_net_tagged_ws_1, enc_net_tagged_ws_2,
     enc_net_error_1, enc_net_error_2, enc_net_malformed,
     enc_net_ignore_unreadable, enc_net_unreadable,
     fin_usr_start, fin_usr_stop, fin_usr_msg, fin_net_plain,
     fin_net_error_1, fin_net_error_2, fin_net_tagged_ws_1,
     fin_net_tagged_ws_2, fin_net_data, fin_net_ake,
     fragmented, padded, fin_net_malformed, heartbeat,
     cover].

%F{{{ init_per_testcase/2
init_per_testcase(pt_usr_2, Config) ->
    setup_fsm(Config, [send_whitespace_tag]);
init_per_testcase(pt_net_error_2, Config) ->
    setup_fsm(Config, [error_start_ake]);
init_per_testcase(pt_usr_3, Config) ->
    setup_fsm(Config, [require_encryption]);
init_per_testcase(pt_ake_msg_1, Config) ->
    setup_pair(Config, [], []);
init_per_testcase(pt_ake_msg_2, Config) ->
    setup_pair(Config, [require_encryption], []);
init_per_testcase(pt_net_tagged_ws_2, Config) ->
    setup_pair(Config,
	       [whitespace_start_ake, require_encryption], []);
init_per_testcase(pt_net_tagged_ws_1, Config) ->
    setup_pair(Config, [whitespace_start_ake], []);
init_per_testcase(pt_net_tagged_ws_3, Config) ->
    setup_pair(Config, [require_encryption], []);
init_per_testcase(enc_usr_start, Config) ->
    setup_pair(Config, [], []);
init_per_testcase(enc_usr_stop, Config) ->
    setup_pair(Config, [], []);
init_per_testcase(enc_net_plain, Config) ->
    setup_pair(Config, [], []);
init_per_testcase(enc_net_tagged_ws_1, Config) ->
    setup_pair(Config, [], []);
init_per_testcase(enc_net_tagged_ws_2, Config) ->
    setup_pair(Config, [whitespace_start_ake], []);
init_per_testcase(enc_net_error_1, Config) ->
    setup_pair(Config, [], []);
init_per_testcase(enc_net_error_2, Config) ->
    setup_pair(Config, [error_start_ake], []);
init_per_testcase(enc_net_malformed, Config) ->
    setup_pair(Config, [], []);
init_per_testcase(enc_net_malformed_encrypted,
		  Config) ->
    setup_pair(Config, [], []);
init_per_testcase(enc_net_ignore_unreadable, Config) ->
    setup_pair(Config, [], []);
init_per_testcase(enc_net_unreadable, Config) ->
    setup_pair(Config, [], []);
init_per_testcase(fin_usr_start, Config) ->
    setup_pair(Config, [], []);
init_per_testcase(fin_usr_stop, Config) ->
    setup_pair(Config, [], []);
init_per_testcase(fin_usr_msg, Config) ->
    setup_pair(Config, [], []);
init_per_testcase(fin_net_plain, Config) ->
    setup_pair(Config, [], []);
init_per_testcase(fin_net_error_1, Config) ->
    setup_pair(Config, [], []);
init_per_testcase(fin_net_error_2, Config) ->
    setup_pair(Config, [error_start_ake], []);
init_per_testcase(fin_net_tagged_ws_1, Config) ->
    setup_pair(Config, [], []);
init_per_testcase(fin_net_tagged_ws_2, Config) ->
    setup_pair(Config, [whitespace_start_ake], []);
init_per_testcase(fin_net_data, Config) ->
    setup_pair(Config, [], []);
init_per_testcase(fin_net_ake, Config) ->
    setup_pair(Config, [], []);
init_per_testcase(fin_net_malformed, Config) ->
    setup_pair(Config, [], []);
init_per_testcase(fragmented, Config) ->
    setup_pair(Config, [{max_fragment_size, 256}], []);
init_per_testcase(padded, Config) ->
    setup_pair(Config, [{min_enc_size, 23}], []);
init_per_testcase(heartbeat, Config) ->
    setup_pair(Config, [{heartbeat_timeout, 200}], []);
init_per_testcase(_TestCase, Config) ->
    setup_fsm(Config, []).

%}}}F

%F{{{ end_per_testcase/2
end_per_testcase(_TestCase, Config) ->
    lists:foreach(fun (X) ->
			  catch unlink(whereis(X)),
			  catch exit(whereis(X), shutdown)
		  end,
		  [fsm1, fsm2, parser1, parser2, net_pipe]),
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

%F{{{ pt_.../1
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

pt_usr_3(Config) ->
    ct:comment("message from user while in state [plaintext] "
	       "with require_encryption=true"),
    Fsm = (?config(fsm, Config)),
    otr_fsm:consume(Fsm, {user, {message, "foo"}}),
    R = {to_net, "?OTRv2?"},
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
    {to_user, {info, stopped}} = receive
				   R -> R after 500 -> timeout
				 end.

pt_net_1(Config) ->
    ct:comment("plaintext message from network while "
	       "in state [plaintext]"),
    Parser = (?config(parser, Config)),
    otr_parser_fsm:consume(Parser, "foo bar baz"),
    R = {to_user, {message, "foo bar baz", []}},
    R = receive R -> R after 500 -> timeout end.

pt_net_malfored(Config) ->
    ct:comment("malformed message from netrwork in state "
	       "[plaintext]"),
    Parser = (?config(parser, Config)),
    otr_parser_fsm:consume(Parser, "?OTR:Zm9vYmFy."),
    R = {to_user, {error, malformed_message_received}},
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
    ct:comment("data message from network while in state "
	       "[plaintext]"),
    Parser = (?config(parser, Config)),
    {M, _} = (?MessageTestVector5),
    otr_parser_fsm:consume(Parser, M),
    R1 = {to_user, {error, unreadable_encrypted_received}},
    R1 = receive R1 -> R1 after 500 -> timeout end,
    R2 = {to_net, "?OTR Error:" ++ (?ERR_MSG_UNEXPECTED)},
    R2 = receive R2 -> R2 after 500 -> timeout end.

pt_net_dh_key(Config) ->
    ct:comment("DH KEY message from network while in "
	       "state [plaintext] without AKE in progress"),
    Parser = (?config(parser, Config)),
    {M, _} = (?MessageTestVector2),
    otr_parser_fsm:consume(Parser, M),
    ok = receive _ -> not_ok after 500 -> ok end.

pt_net_reveal_signature(Config) ->
    ct:comment("REVEAL SIGNATURE message from network "
	       "while in state [plaintext] without AKE "
	       "in progress"),
    Parser = (?config(parser, Config)),
    {M, _} = (?MessageTestVector3),
    otr_parser_fsm:consume(Parser, M),
    ok = receive _ -> not_ok after 500 -> ok end.

pt_net_signature(Config) ->
    ct:comment("SIGNATURE message from network while "
	       "in state [plaintext] without AKE in "
	       "progress"),
    Parser = (?config(parser, Config)),
    {M, _} = (?MessageTestVector4),
    otr_parser_fsm:consume(Parser, M),
    ok = receive _ -> not_ok after 500 -> ok end.

pt_net_tagged_ws_1(_Config) ->
    ct:comment("Taged whitespace message from network "
	       "while in State [plaintext] when whitespace_st"
	       "art_ake=true"),
    otr_parser_fsm:consume(parser1, "FOOO" ++ (?TAG_V2)),
    {to_user1, {message, "FOOO"}} = receive
				      X -> X after 500 -> timeout
				    end,
    ok = key_exchange_completed().

pt_net_tagged_ws_2(_Config) ->
    ct:comment("Taged whitespace message from network "
	       "while in State [plaintext] when require_encry"
	       "ption=true and whitespace_start_ake=true"),
    otr_parser_fsm:consume(parser1, "FOOO" ++ (?TAG_V2)),
    {to_user1, {message, "FOOO", [warning_unencrypted]}} =
	receive X -> X after 500 -> timeout end,
    ok = key_exchange_completed().

pt_net_tagged_ws_3(_Config) ->
    ct:comment("Taged whitespace message from network "
	       "while in State [plaintext] when require_encry"
	       "ption=true"),
    otr_parser_fsm:consume(parser1, "FOOO" ++ (?TAG_V2)),
    {to_user1, {message, "FOOO", [warning_unencrypted]}} =
	receive X -> X after 500 -> timeout end,
    ok = receive _ -> not_ok after 500 -> ok end.

pt_net_query_1(Config) ->
    ct:comment("query message from network while in "
	       "state [plaintext]"),
    Parser = (?config(parser, Config)),
    otr_parser_fsm:consume(Parser, "?OTRv2?"),
    {to_net, _} = receive X -> X after 500 -> timeout end.

pt_net_query_2(Config) ->
    ct:comment("query message from network while in "
	       "state [plaintext], twice"),
    Parser = (?config(parser, Config)),
    otr_parser_fsm:consume(Parser, "?OTRv2?"),
    {to_net, _} = receive X -> X after 500 -> timeout end,
    otr_parser_fsm:consume(Parser, "?OTRv2?"),
    {to_net, _} = receive Y -> Y after 500 -> timeout end.

pt_ake_msg_1(_Config) ->
    ct:comment("complete AKE and message exchange"),
    otr_fsm:consume(fsm1, {user, start_otr}),
    ok = key_exchange_completed(),
    otr_fsm:consume(fsm2, {user, {message, "FOOO"}}),
    {to_user1, {message, "FOOO"}} = receive
				      R1 -> R1 after 500 -> timeout
				    end,
    otr_fsm:consume(fsm1, {user, {message, "XXXX"}}),
    {to_user2, {message, "XXXX"}} = receive
				      R2 -> R2 after 500 -> timeout
				    end,
    ok.

pt_ake_msg_2(_Config) ->
    ct:comment("complete AKE and message exchange, when "
	       "plain messages where received from user "
	       "before switching to mode [encrypted] "
	       "and require_encryption=true"),
    otr_fsm:consume(fsm1, {user, {message, "M1"}}),
    otr_fsm:consume(fsm1, {user, {message, "M2"}}),
    otr_fsm:consume(fsm1, {user, start_otr}),
    ok = key_exchange_completed(),
    {to_user2, {message, "M1"}} = receive
				    R1 -> R1 after 500 -> timeout
				  end,
    {to_user2, {message, "M2"}} = receive
				    R2 -> R2 after 500 -> timeout
				  end,
    ok.

%}}}F

%F{{{ enc_.../1
enc_usr_start(_Config) ->
    ct:comment("start otr command while in state [encrypted]"),
    otr_fsm:consume(fsm1, {user, start_otr}),
    {to_user1, {info, {encrypted_new_dsa_fp, _FP2, SIG1}}} =
	receive X1 -> X1 after 500 -> timeout end,
    {to_user2, {info, {encrypted_new_dsa_fp, _FP1, SIG1}}} =
	receive Y1 -> Y1 after 500 -> timeout end,
    otr_fsm:consume(fsm1, {user, start_otr}),
    {to_user1, {info, {encrypted, SIG2}}} = receive
					      X2 -> X2 after 500 -> timeout
					    end,
    {to_user2, {info, {encrypted, SIG2}}} = receive
					      Y2 -> Y2 after 500 -> timeout
					    end,
    ok.

enc_usr_stop(_Config) ->
    ct:comment("stop otr command while in state [encrypted]"),
    otr_fsm:consume(fsm1, {user, start_otr}),
    ok = key_exchange_completed(),
    otr_fsm:consume(fsm1, {user, stop_otr}),
    {to_user1, {info, stopped}} = receive
				    X4 -> X4 after 500 -> timeout
				  end,
    {to_user2, {info, finished}} = receive
				     X3 -> X3 after 500 -> timeout
				   end,
    timer:sleep(100),
    ok.

enc_net_plain(_Config) ->
    ct:comment("plain message from network while in "
	       "state  [encrypted]"),
    otr_fsm:consume(fsm1, {user, start_otr}),
    ok = key_exchange_completed(),
    otr_parser_fsm:consume(parser1, "some plain text"),
    R = {to_user1,
	 {message, "some plain text", [warning_unencrypted]}},
    R = receive X2 -> X2 after 500 -> timeout end.

enc_net_tagged_ws_1(_Config) ->
    ct:comment("tagged whitespace message from network "
	       "while in state [encrypted]"),
    otr_fsm:consume(fsm1, {user, start_otr}),
    ok = key_exchange_completed(),
    otr_parser_fsm:consume(parser1, "T WS" ++ (?TAG_V2)),
    R = {to_user1,
	 {message, "T WS", [warning_unencrypted]}},
    R = receive X3 -> X3 after 500 -> timeout end.

enc_net_tagged_ws_2(_Config) ->
    ct:comment("tagged whitespace message from network "
	       "while in state [encrypted] when whitespace_st"
	       "art_ake=true"),
    otr_fsm:consume(fsm1, {user, start_otr}),
    ok = key_exchange_completed(),
    otr_parser_fsm:consume(parser1, "T WS" ++ (?TAG_V2)),
    R = {to_user1,
	 {message, "T WS", [warning_unencrypted]}},
    R = receive X3 -> X3 after 500 -> timeout end,
    {to_user2, {info, {encrypted, SIG2}}} = receive
					      X2 -> X2 after 500 -> timeout
					    end,
    {to_user1, {info, {encrypted, SIG2}}} = receive
					      Y2 -> Y2 after 500 -> timeout
					    end,
    ok.

enc_net_error_1(_Config) ->
    ct:comment("error message from network while in "
	       "state [encrypted]"),
    otr_fsm:consume(fsm1, {user, start_otr}),
    ok = key_exchange_completed(),
    otr_parser_fsm:consume(parser1, "?OTR Error:The Error"),
    R = {to_user1, {error_net, "The Error"}},
    R = receive X3 -> X3 after 500 -> timeout end.

enc_net_error_2(_Config) ->
    ct:comment("error message from network while in "
	       "state [encrypted] when error_start_ake=true"),
    otr_fsm:consume(fsm1, {user, start_otr}),
    ok = key_exchange_completed(),
    otr_parser_fsm:consume(parser1, "?OTR Error:The Error"),
    R = {to_user1, {error_net, "The Error"}},
    R = receive X3 -> X3 after 500 -> timeout end,
    {to_user1, {info, {encrypted, SIG2}}} = receive
					      X2 -> X2 after 500 -> timeout
					    end,
    {to_user2, {info, {encrypted, SIG2}}} = receive
					      Y2 -> Y2 after 500 -> timeout
					    end,
    ok.

enc_net_malformed(_Config) ->
    ct:comment("malformed message from network in state "
	       "[encrypted]"),
    otr_fsm:consume(fsm1, {user, start_otr}),
    ok = key_exchange_completed(),
    otr_parser_fsm:consume(parser1, "?OTR:Zm9vYmFy."),
    R = {to_user1, {error, malformed_message_received}},
    R = receive R -> R after 500 -> timeout end.

enc_net_ignore_unreadable(_Config) ->
    ct:comment("unreadable message from network in state "
	       "[encrypted] when flag=ignore_unreadable"),
    otr_fsm:consume(fsm1, {user, start_otr}),
    ok = key_exchange_completed(),
    exchange_data(10),
    net_pipe ! {tap, self()},
    otr_fsm:consume(fsm1, {user, {message, "message foo"}}),
    Fsm1 = whereis(fsm1),
    {tap, {Fsm1, M}} = receive
			 X1 -> X1 after 500 -> timeout
		       end,
    {to_user2, {message, "message foo"}} = receive
					     X2 -> X2 after 500 -> timeout
					   end,
    exchange_data(3),
    {ok, M1} = otr_message:parse(M),
    otr_fsm:consume(fsm2,
		    {net, M1#otr_msg_data{flags = 1}}),
    exchange_data(3),
    ok.

enc_net_unreadable(_Config) ->
    ct:comment("unreadable message from network in state "
	       "[encrypted]"),
    otr_fsm:consume(fsm1, {user, start_otr}),
    ok = key_exchange_completed(),
    exchange_data(10),
    net_pipe ! {tap, self()},
    otr_fsm:consume(fsm1, {user, {message, "message foo"}}),
    Fsm1 = whereis(fsm1),
    {tap, {Fsm1, M}} = receive
			 X1 -> X1 after 500 -> timeout
		       end,
    {to_user2, {message, "message foo"}} = receive
					     X2 -> X2 after 500 -> timeout
					   end,
    exchange_data(3),
    {ok, M1} = otr_message:parse(M),
    otr_fsm:consume(fsm2, {net, M1}),
    {to_user2, {error, malformed_encrypted_received}} =
	receive X3 -> X3 after 500 -> timeout end,
    {to_user1, {error_net, ?ERR_MSG_MALFORMED}} = receive
						    X4 -> X4
						    after 500 -> timeout
						  end,
    exchange_data(3),
    ok.

%}}}F

%F{{{ fin_.../1
fin_usr_start(_Config) ->
    ct:comment("start otr command while in state [finished]"),
    otr_fsm:consume(fsm1, {user, start_otr}),
    ok = key_exchange_completed(),
    exchange_data(5),
    otr_fsm:consume(fsm2, {user, stop_otr}),
    {to_user2, {info, stopped}} = receive
				    X4 -> X4 after 500 -> timeout
				  end,
    {to_user1, {info, finished}} = receive
				     X3 -> X3 after 500 -> timeout
				   end,
    otr_fsm:consume(fsm1, {user, start_otr}),
    ok = key_exchange_2_completed(),
    exchange_data(5),
    ok.

fin_usr_stop(_Config) ->
    ct:comment("stop otr command while in state [finished]"),
    otr_fsm:consume(fsm1, {user, start_otr}),
    ok = key_exchange_completed(),
    exchange_data(5),
    otr_fsm:consume(fsm2, {user, stop_otr}),
    {to_user2, {info, stopped}} = receive
				    X4 -> X4 after 500 -> timeout
				  end,
    {to_user1, {info, finished}} = receive
				     X3 -> X3 after 500 -> timeout
				   end,
    otr_fsm:consume(fsm1, {user, stop_otr}),
    timer:sleep(100).

fin_usr_msg(_Config) ->
    ct:comment("message from user while in state [fin_usr_msg]"),
    otr_fsm:consume(fsm1, {user, start_otr}),
    ok = key_exchange_completed(),
    exchange_data(5),
    otr_fsm:consume(fsm2, {user, stop_otr}),
    {to_user2, {info, stopped}} = receive
				    X4 -> X4 after 500 -> timeout
				  end,
    {to_user1, {info, finished}} = receive
				     X3 -> X3 after 500 -> timeout
				   end,
    otr_fsm:consume(fsm1, {user, {message, "FOO"}}),
    {to_user1, {info, message_can_not_be_sent_this_time}} =
	receive X5 -> X5 after 500 -> timeout end.

fin_net_plain(_Config) ->
    ct:comment("plain message from user while in state "
	       "[fin_usr_msg]"),
    otr_fsm:consume(fsm1, {user, start_otr}),
    ok = key_exchange_completed(),
    exchange_data(5),
    otr_fsm:consume(fsm2, {user, stop_otr}),
    {to_user2, {info, stopped}} = receive
				    X4 -> X4 after 500 -> timeout
				  end,
    {to_user1, {info, finished}} = receive
				     X3 -> X3 after 500 -> timeout
				   end,
    otr_fsm:consume(fsm2, {user, {message, "FOO"}}),
    {to_user1, {message, "FOO", [warning_unencrypted]}} =
	receive X5 -> X5 after 500 -> timeout end.

fin_net_error_1(_Config) ->
    ct:comment("error message from network while in "
	       "state [finished]"),
    otr_fsm:consume(fsm1, {user, start_otr}),
    ok = key_exchange_completed(),
    exchange_data(5),
    otr_fsm:consume(fsm2, {user, stop_otr}),
    {to_user2, {info, stopped}} = receive
				    X4 -> X4 after 500 -> timeout
				  end,
    {to_user1, {info, finished}} = receive
				     X3 -> X3 after 500 -> timeout
				   end,
    otr_parser_fsm:consume(parser1, "?OTR Error:The Error"),
    R = {to_user1, {error_net, "The Error"}},
    R = receive X5 -> X5 after 500 -> timeout end.

fin_net_error_2(_Config) ->
    ct:comment("error message from network while in "
	       "state [finished] when error_start_ake=true"),
    otr_fsm:consume(fsm1, {user, start_otr}),
    ok = key_exchange_completed(),
    exchange_data(5),
    otr_fsm:consume(fsm2, {user, stop_otr}),
    {to_user2, {info, stopped}} = receive
				    X4 -> X4 after 500 -> timeout
				  end,
    {to_user1, {info, finished}} = receive
				     X3 -> X3 after 500 -> timeout
				   end,
    otr_parser_fsm:consume(parser1, "?OTR Error:The Error"),
    R = {to_user1, {error_net, "The Error"}},
    R = receive X5 -> X5 after 500 -> timeout end,
    ok = key_exchange_2_completed(),
    exchange_data(3).

fin_net_tagged_ws_1(_Config) ->
    ct:comment("tagged whitespace message from network "
	       "while in state [encrypted]"),
    otr_fsm:consume(fsm1, {user, start_otr}),
    ok = key_exchange_completed(),
    exchange_data(5),
    otr_fsm:consume(fsm2, {user, stop_otr}),
    {to_user2, {info, stopped}} = receive
				    X4 -> X4 after 500 -> timeout
				  end,
    {to_user1, {info, finished}} = receive
				     X3 -> X3 after 500 -> timeout
				   end,
    otr_parser_fsm:consume(parser1, "T WS" ++ (?TAG_V2)),
    R = {to_user1,
	 {message, "T WS", [warning_unencrypted]}},
    R = receive X5 -> X5 after 500 -> timeout end.

fin_net_tagged_ws_2(_Config) ->
    ct:comment("tagged whitespace message from network "
	       "while in state [encrypted] when whitespace_st"
	       "art_ake=true"),
    otr_fsm:consume(fsm1, {user, start_otr}),
    ok = key_exchange_completed(),
    exchange_data(5),
    otr_fsm:consume(fsm2, {user, stop_otr}),
    {to_user2, {info, stopped}} = receive
				    X4 -> X4 after 500 -> timeout
				  end,
    {to_user1, {info, finished}} = receive
				     X3 -> X3 after 500 -> timeout
				   end,
    otr_parser_fsm:consume(parser1, "T WS" ++ (?TAG_V2)),
    R = {to_user1,
	 {message, "T WS", [warning_unencrypted]}},
    R = receive X5 -> X5 after 500 -> timeout end,
    ok = key_exchange_2_completed().

fin_net_data(_Config) ->
    ct:comment("data message from network while in state "
	       "[encrypted]"),
    otr_fsm:consume(fsm1, {user, start_otr}),
    ok = key_exchange_completed(),
    exchange_data(5),
    otr_fsm:consume(fsm2, {user, stop_otr}),
    {to_user2, {info, stopped}} = receive
				    X4 -> X4 after 500 -> timeout
				  end,
    {to_user1, {info, finished}} = receive
				     X3 -> X3 after 500 -> timeout
				   end,
    {M, _} = (?MessageTestVector5),
    otr_parser_fsm:consume(parser1, M),
    {to_user1, {error, unreadable_encrypted_received}} =
	receive X5 -> X5 after 500 -> timeout end,
    {to_user2, {error_net, ?ERR_MSG_UNEXPECTED}} = receive
						     X6 -> X6
						     after 500 -> timeout
						   end.

fin_net_ake(_Config) ->
    ct:comment("ake from network while in state [encrypted]"),
    otr_fsm:consume(fsm1, {user, start_otr}),
    ok = key_exchange_completed(),
    exchange_data(5),
    otr_fsm:consume(fsm2, {user, stop_otr}),
    {to_user2, {info, stopped}} = receive
				    X4 -> X4 after 500 -> timeout
				  end,
    {to_user1, {info, finished}} = receive
				     X3 -> X3 after 500 -> timeout
				   end,
    otr_fsm:consume(fsm2, {user, start_otr}),
    key_exchange_2_completed().

fin_net_malformed(_Config) ->
    ct:comment("malformed message from network in state "
	       "[finished]"),
    otr_fsm:consume(fsm1, {user, start_otr}),
    ok = key_exchange_completed(),
    exchange_data(5),
    otr_fsm:consume(fsm2, {user, stop_otr}),
    {to_user2, {info, stopped}} = receive
				    X4 -> X4 after 500 -> timeout
				  end,
    {to_user1, {info, finished}} = receive
				     X3 -> X3 after 500 -> timeout
				   end,
    otr_parser_fsm:consume(parser1, "?OTR:Zm9vYmFy."),
    R = {to_user1, {error, malformed_message_received}},
    R = receive R -> R after 500 -> timeout end.

%}}}F

fragmented(_Config) ->
    ct:comment("ake, transmit/receive fragmented message"),
    otr_fsm:consume(fsm1, {user, start_otr}),
    ok = key_exchange_completed(),
    M = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
	"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
	"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
	"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
	"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
	"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
	"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
    otr_fsm:consume(fsm1, {user, {message, M}}),
    {to_user2, {message, M}} = receive
				 X1 -> X1 after 500 -> timeout
			       end.

padded(_Config) ->
    ct:comment("ake, transmit/receive padded message"),
    otr_fsm:consume(fsm1, {user, start_otr}),
    ok = key_exchange_completed(),
    M = "XXX",
    otr_fsm:consume(fsm1, {user, {message, M}}),
    {to_user2, {message, M}} = receive
				 X1 -> X1 after 500 -> timeout
			       end.

heartbeat(_Config) ->
    ct:comment("ake, transmit/receive heartbeat message"),
    otr_fsm:consume(fsm1, {user, start_otr}),
    ok = key_exchange_completed(),
    M = "XXX",
    otr_fsm:consume(fsm2, {user, {message, M}}),
    {to_user1, {message, M}} = receive
				 X1 -> X1 after 500 -> timeout
			       end,
    timer:sleep(100),
    otr_fsm:consume(fsm2, {user, {message, M}}),
    {to_user1, {message, M}} = receive
				 X2 -> X2 after 500 -> timeout
			       end,
    timer:sleep(150),
    otr_fsm:consume(fsm2, {user, {message, M}}),
    {to_user1, {message, M}} = receive
				 X3 -> X3 after 500 -> timeout
			       end,
    timer:sleep(100).

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

exchange_data(0) -> ok;
exchange_data(N) ->
    do_exchange_data(N), exchange_data(N - 1).

do_exchange_data(N) when N div 2 == 0 ->
    M = "MSG" ++ integer_to_list(N),
    otr_fsm:consume(fsm2, {user, {message, M}}),
    {to_user1, {message, M}} = receive
				 X -> X after 500 -> timeout
			       end;
do_exchange_data(N) ->
    M = "MSG" ++ integer_to_list(N),
    otr_fsm:consume(fsm1, {user, {message, M}}),
    {to_user2, {message, M}} = receive
				 X -> X after 500 -> timeout
			       end.

key_exchange_completed() ->
    receive
      {to_user1,
       {info, {encrypted_new_dsa_fp, _FP2, SIG1}}} ->
	  receive
	    {to_user2,
	     {info, {encrypted_new_dsa_fp, _FP1, SIG1}}} ->
		ok
	    after 500 -> timeout
	  end;
      {to_user2,
       {info, {encrypted_new_dsa_fp, _FP1, SIG1}}} ->
	  receive
	    {to_user1,
	     {info, {encrypted_new_dsa_fp, _FP2, SIG1}}} ->
		ok
	    after 500 -> timeout
	  end
      after 500 -> timeout
    end.

key_exchange_2_completed() ->
    receive
      {to_user1, {info, {encrypted, SIG}}} ->
	  receive
	    {to_user2, {info, {encrypted, SIG}}} -> ok
	    after 500 -> timeout
	  end;
      {to_user2, {info, {encrypted, SIG}}} ->
	  receive
	    {to_user1, {info, {encrypted, SIG}}} -> ok
	    after 500 -> timeout
	  end
      after 500 -> timeout
    end.

setup_pair(Config, Opts1, Opts2) ->
    Self = self(),
    EmitUser1 = fun (X) -> Self ! {to_user1, X} end,
    EmitUser2 = fun (X) -> Self ! {to_user2, X} end,
    EmitNet = fun (X) -> net_pipe ! {self(), X} end,
    {ok, Parser1} = otr_parser_fsm:start_link(),
    {ok, Parser2} = otr_parser_fsm:start_link(),
    {ok, Fsm1} = otr_fsm:start_link([{emit_user, EmitUser1},
				     {emit_net, EmitNet}, {dsa, ?DSAKey1}
				     | Opts1]),
    {ok, Fsm2} = otr_fsm:start_link([{emit_user, EmitUser2},
				     {emit_net, EmitNet}, {dsa, ?DSAKey2}
				     | Opts2]),
    otr_parser_fsm:set_emit_fun(Parser1,
				fun (X) -> otr_fsm:consume(Fsm1, {net, X}) end),
    otr_parser_fsm:set_emit_fun(Parser2,
				fun (X) -> otr_fsm:consume(Fsm2, {net, X}) end),
    register(fsm1, Fsm1),
    register(fsm2, Fsm2),
    register(parser1, Parser1),
    register(parser2, Parser2),
    NetPipe = spawn_link(fun () ->
				 net_pipe(Fsm1, Parser1, Fsm2, Parser2)
			 end),
    register(net_pipe, NetPipe),
    Config.

net_pipe(F1, P1, F2, P2, Tap) ->
    receive
      {F1, M} ->
	  Tap ! {tap, {F1, M}}, otr_parser_fsm:consume(P2, M);
      {F2, M} ->
	  Tap ! {tap, {F2, M}}, otr_parser_fsm:consume(P1, M);
      _ -> exit(kill)
    end,
    net_pipe(F1, P1, F2, P2).

net_pipe(F1, P1, F2, P2) ->
    receive
      {tap, Tap} -> net_pipe(F1, P1, F2, P2, Tap);
      {F1, M} ->
	  otr_parser_fsm:consume(P2, M), net_pipe(F1, P1, F2, P2);
      {F2, M} ->
	  otr_parser_fsm:consume(P1, M), net_pipe(F1, P1, F2, P2);
      _ -> exit(kill)
    end.

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

