-module(otr_tlv_SUITE).

-author("Stefan Grundmann <sg2342@googlemail.com>").

-compile(export_all).

init_per_suite(Config) -> Config.

end_per_suite(Config) -> Config.

init_per_testcase(_TestCase, Config) -> Config.

end_per_testcase(_TestCase, Config) -> Config.

all() ->
    [e_empty, d_empty, e_padding, d_padding, e_disconnected,
     d_disconnected, e_smp_abort, d_smp_abort, e_smp_msg_s,
     d_smp_msg_s, d_error, d_error_smp].

e_empty(_C) ->
    ct:comment("encode empty messages"),
    <<>> = otr_tlv:encode(""),
    <<0>> = otr_tlv:encode({"", []}).

d_empty(_C) ->
    ct:comment("decode empty messages"),
    {[], []} = otr_tlv:decode(<<>>),
    {[], []} = otr_tlv:decode(<<0>>).

e_padding(_C) ->
    ct:comment("encode messages with padding"),
    <<"some text", 0, 0:16, 8:16, _ThePadding:8/binary>> =
	otr_tlv:encode({"some text", [{padding, 8}]}),
    <<0, 0:16, 0:16>> = otr_tlv:encode({"",
					[{padding, 0}]}).

d_padding(_C) ->
    ct:comment("decode messages with padding"),
    {"some text", [{padding, 0}]} =
	otr_tlv:decode(<<"some text", 0, 0:16, 0:16>>).

e_disconnected(_C) ->
    ct:comment("encode message with disconnected record"),
    <<"some text", 0, 1:16, 0:16>> =
	otr_tlv:encode({"some text", [disconnected]}).

d_disconnected(_C) ->
    ct:comment("decode messages with disconnected record"),
    {"some text", [disconnected]} =
	otr_tlv:decode(<<"some text", 0, 1:16, 4:16, 1, 2, 3,
			 4>>),
    {"", [disconnected]} = otr_tlv:decode(<<0, 1:16,
					    0:16>>).

e_smp_abort(_C) ->
    ct:comment("encode message with smp_abort record"),
    <<"some text", 0, 6:16, 0:16>> =
	otr_tlv:encode({"some text", [smp_abort]}).

d_smp_abort(_C) ->
    ct:comment("decode messages with smp_abort record"),
    {"some text", [smp_abort]} =
	otr_tlv:decode(<<"some text", 0, 6:16, 0:16>>),
    {"", [smp_abort]} = otr_tlv:decode(<<0, 6:16, 2:16,
					 "ab">>).

e_smp_msg_s(_C) ->
    ct:comment("encode messages with SMP Message records"),
    <<"some text", 0, 2:16, 4:16, 0:32>> =
	otr_tlv:encode({"some text", [{smp_msg_1, []}]}),
    <<"some text", 0, 3:16, 4:16, 0:32>> =
	otr_tlv:encode({"some text", [{smp_msg_2, []}]}),
    <<"some text", 0, 4:16, 4:16, 0:32>> =
	otr_tlv:encode({"some text", [{smp_msg_3, []}]}),
    <<"some text", 0, 5:16, 4:16, 0:32>> =
	otr_tlv:encode({"some text", [{smp_msg_4, []}]}),
    <<0, 2:16, 14:16, 2:32, 0, 0, 0, 1, 23, 0, 0, 0, 1,
      42>> =
	otr_tlv:encode({[], [{smp_msg_1, [23, 42]}]}).

d_smp_msg_s(_C) ->
    ct:comment("decode messages with SMP Message records"),
    {"", [{smp_msg_1, [256]}]} = otr_tlv:decode(<<0, 2:16,
						  10:16, 1:32, 0, 0, 0, 2, 1,
						  0>>),
    {"some text", [{smp_msg_2, []}]} =
	otr_tlv:decode(<<"some text", 0, 3:16, 4:16, 0:32>>),
    {"some text", [{smp_msg_3, []}]} =
	otr_tlv:decode(<<"some text", 0, 4:16, 4:16, 0:32>>),
    {"some text", [{smp_msg_4, []}]} =
	otr_tlv:decode(<<"some text", 0, 5:16, 4:16, 0:32>>).

d_error(_C) ->
    ct:comment("fail to decode messages with invalid "
	       "tlv records"),
    {"some text", [{smp_msg_1q, [], error}]} = otr_tlv:decode(<<"some text", 0,
					    7:16, 0:16>>),
    {"some text", error} = otr_tlv:decode(<<"some text", 0,
					    0:16, 0:16, 0:16>>).

d_error_smp(_C) ->
    ct:comment("fail to decode the MPI list of messages "
	       "that contain smp_msg records with invalid "
	       "MPI lists"),
    {"", [{smp_msg_1, error}]} = otr_tlv:decode(<<0, 2:16,
						  4:16, 1:32>>),
    {"", [{smp_msg_2, error}]} = otr_tlv:decode(<<0, 3:16,
						  5:16, 1:32, 9>>).
