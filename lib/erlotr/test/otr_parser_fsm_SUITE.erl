-module(otr_parser_fsm_SUITE).

-author("Stefan Grundmann <sg2342@googlemail.com>").

-compile(export_all).

-include("ct.hrl").

-include("otr_internal.hrl").

-include("MessageTestVectors.hrl").

init_per_suite(Config) -> Config.

end_per_suite(Config) -> Config.

init_per_testcase(_, Config) ->
    {ok, P} = otr_parser_fsm:start_link(),
    Self = self(),
    otr_parser_fsm:set_emit_fun(P, fun (M) -> Self ! M end),
    [{parser, P} | Config].

end_per_testcase(_, Config) ->
    P = (?config(parser, Config)),
    unlink(P),
    catch exit(?config(parser, Config), shutdown),
    false = is_process_alive(P),
    Config.

all() ->
    [plain, otr_dh_commit, otr_dh_key, error_1,
     fragmented_1, fragmented_2, fragmented_fail_1,
     fragmented_fail_2, fragmented_fail_3,
     fragmented_fail_4, cover].

plain(Config) ->
    P = (?config(parser, Config)),
    ct:comment("parse plain message"),
    otr_parser_fsm:consume(P, "some plain text"),
    {plain, "some plain text"} = receive
				   M -> M after 100 -> timeout
				 end.

otr_dh_commit(Config) ->
    P = (?config(parser, Config)),
    ct:comment("parse OTR DH COMMIT message (from testvector "
	       "#1)"),
    {S, M} = (?MessageTestVector1),
    otr_parser_fsm:consume(P, S),
    M = receive X -> X after 100 -> timeout end.

otr_dh_key(Config) ->
    P = (?config(parser, Config)),
    ct:comment("parse OTR DH KEY message (from testvector "
	       "#2)"),
    {S, M} = (?MessageTestVector2),
    otr_parser_fsm:consume(P, S),
    M = receive X -> X after 100 -> timeout end.

error_1(Config) ->
    P = (?config(parser, Config)),
    ct:comment("parse invalid OTR DATA message"),
    otr_parser_fsm:consume(P, "?OTR:AAIAAQID."),
    {error, {encoded_m, invalid_data_message}} = receive
						   X -> X after 100 -> timeout
						 end.

fragmented_1(Config) ->
    P = (?config(parser, Config)),
    ct:comment("parse fragmented OTR DATA message (from "
	       "testvector #7)"),
    {_, L, M} = (?MessageTestVector7),
    lists:foreach(fun (S) -> otr_parser_fsm:consume(P, S)
		  end,
		  L),
    M = receive X -> X after 200 -> timeout end.

fragmented_2(Config) ->
    P = (?config(parser, Config)),
    ct:comment("parse fragmented OTR DATA message; parse "
	       "the first fragment twice (from testvector "
	       "#7)"),
    {_, L, M} = (?MessageTestVector7),
    otr_parser_fsm:consume(P, lists:nth(1, L)),
    lists:foreach(fun (S) -> otr_parser_fsm:consume(P, S)
		  end,
		  L),
    M = receive X -> X after 200 -> timeout end.

fragmented_fail_1(Config) ->
    P = (?config(parser, Config)),
    ct:comment("discard 3 fragments from testvector "
	       "#7 after parsing of a non fragment message"),
    {_, L, _} = (?MessageTestVector7),
    lists:foreach(fun (S) -> otr_parser_fsm:consume(P, S)
		  end,
		  lists:sublist(L, 3)),
    otr_parser_fsm:consume(P, "plain text"),
    {plain, "plain text"} = receive
			      X -> X after 200 -> timeout
			    end.

fragmented_fail_2(Config) ->
    P = (?config(parser, Config)),
    ct:comment("fragmented fragment"),
    L = ["?OTR,1,2,?OTR,1,9,foo,", "?OTR,2,2,oo,,"],
    lists:foreach(fun (S) -> otr_parser_fsm:consume(P, S)
		  end,
		  L),
    {error, fragmented_fragment} = receive
				     X -> X after 200 -> timeout
				   end.

fragmented_fail_3(Config) ->
    P = (?config(parser, Config)),
    ct:comment("fragmented plain text"),
    L = ["?OTR,1,2,foo,", "?OTR,2,2,bar,,"],
    lists:foreach(fun (S) -> otr_parser_fsm:consume(P, S)
		  end,
		  L),
    {error, fragmented_plain} = receive
				  X -> X after 200 -> timeout
				end.

fragmented_fail_4(Config) ->
    P = (?config(parser, Config)),
    ct:comment("fragmented invalid OTR encoded mesage "
	       "(wrong version)"),
    L = ["?OTR,1,2,?OTR:EAABAgMEBQ,", "?OTR,2,2,Y=.,"],
    lists:foreach(fun (S) -> otr_parser_fsm:consume(P, S)
		  end,
		  L),
    {error, {encoded_m, unsupported_version}} = receive
						  X -> X after 200 -> timeout
						end.

cover(_Config) ->
    ct:comment("achive 100% coverage: call code_change/4, "
	       "terminate/3 and the handle_... functions "
	       "that are meant to fail"),
    ok = otr_parser_fsm:terminate(x, y, z),
    {ok, b, c} = otr_parser_fsm:code_change(a, b, c, d),
    {stop, {b, undefined_info, a}, c} =
	otr_parser_fsm:handle_info(a, b, c),
    {stop, {b, undefined_event, a}, c} =
	otr_parser_fsm:handle_event(a, b, c),
    {stop, {c, undefined_sync_event, a}, d} =
	otr_parser_fsm:handle_sync_event(a, b, c, d),
    ok.
