-module(otr_message_SUITE).

-author("Stefan Grundmann <sg2342@googlemail.com>").

-compile(export_all).

-include_lib("erlotr/include/otr.hrl").

-include("MessageTestVectors.hrl").

init_per_suite(Config) -> Config.

end_per_suite(Config) -> Config.

init_per_testcase(_TestCase, Config) -> Config.

end_per_testcase(_TestCase, Config) -> Config.

all() ->
    [parse_dh_commit, encode_dh_commit, parse_dh_key,
     encode_dh_key, parse_reveal_signature,
     encode_reveal_signature, parse_signature,
     encode_signature, parse_data_1, encode_data_1,
     parse_data_2, encode_data_2, parse_query, encode_query,
     parse_error, encode_error, parse_tagged_ws_1,
     parse_tagged_ws_2, encode_tagged_ws, parse_fragment,
     encode_fragmented_1, encode_fragmented_2, parse_plain_1,
     parse_plain_2, parse_plain_3, parse_plain_4,
     parse_plain_5, parse_fail_1, parse_fail_2, parse_fail_3,
     parse_fail_4, parse_fail_5].

parse_dh_commit(_Config) ->
    ct:comment("parse OTR DH COMMIT message (using testvector "
	       "#1)"),
    {Data, Message} = (?MessageTestVector1),
    {ok, Message} = otr_message:parse(Data).

encode_dh_commit(_Config) ->
    ct:comment("encode OTR DH COMMIT message (using "
	       "testvector #1)"),
    {Data, Message} = (?MessageTestVector1),
    {ok, Data} = otr_message:encode(Message).

parse_dh_key(_Config) ->
    ct:comment("parse OTR DH KEY message (using testvector "
	       "#2)"),
    {Data, Message} = (?MessageTestVector2),
    {ok, Message} = otr_message:parse(Data).

encode_dh_key(_Config) ->
    ct:comment("encode OTR DH KEY message (using testvector "
	       "#2)"),
    {Data, Message} = (?MessageTestVector2),
    {ok, Data} = otr_message:encode(Message).

parse_reveal_signature(_Config) ->
    ct:comment("parse OTR REVEAL SIGNATURE message (using "
	       "testvector #3)"),
    {Data, Message} = (?MessageTestVector3),
    {ok, Message} = otr_message:parse(Data).

encode_reveal_signature(_Config) ->
    ct:comment("encode OTR REVEAL SIGNATURE message "
	       "(using testvector #3)"),
    {Data, Message} = (?MessageTestVector3),
    {ok, Data} = otr_message:encode(Message).

parse_signature(_Config) ->
    ct:comment("parse OTR SIGNATURE message (using testvector "
	       "#4)"),
    {Data, Message} = (?MessageTestVector4),
    {ok, Message} = otr_message:parse(Data).

encode_signature(_Config) ->
    ct:comment("encode OTR SIGNATURE message (using "
	       "testvector #4)"),
    {Data, Message} = (?MessageTestVector4),
    {ok, Data} = otr_message:encode(Message).

parse_data_1(_Config) ->
    ct:comment("parse OTR DATA message (using testvector "
	       "#5)"),
    {Data, Message} = (?MessageTestVector5),
    {ok, Message} = otr_message:parse(Data).

encode_data_1(_Config) ->
    ct:comment("encode OTR DATA message (using testvector "
	       "#5)"),
    {Data, Message} = (?MessageTestVector5),
    {ok, Data} = otr_message:encode(Message).

parse_data_2(_Config) ->
    ct:comment("parse OTR DATA message (using testvector "
	       "#6)"),
    {Data, Message} = (?MessageTestVector6),
    {ok, Message} = otr_message:parse(Data).

encode_data_2(_Config) ->
    ct:comment("encode OTR DATA message (using testvector "
	       "#6)"),
    {Data, Message} = (?MessageTestVector6),
    {ok, Data} = otr_message:encode(Message).

parse_query(_Config) ->
    ct:comment("parse OTR QUERY messages"),
    L = ["?OTR?v2?", "?OTRv2?", "?OTRv134562?",
	 "?OTR?v9082?"],
    R = {ok, otr_msg_query},
    lists:foreach(fun (X) -> R = otr_message:parse(X) end,
		  L).

encode_query(_Config) ->
    ct:comment("encode OTR QUERY message"),
    {ok, "?OTRv2?"} = otr_message:encode(otr_msg_query).

parse_error(_Config) ->
    ct:comment("parse OTR Error message"),
    {ok, #otr_msg_error{s = "error message"}} =
	otr_message:parse("?OTR Error:error message").

encode_error(_Config) ->
    ct:comment("encode OTR Error message"),
    {ok, "?OTR Error:error message"} =
	otr_message:encode(#otr_msg_error{s = "error message"}).

parse_tagged_ws_1(_Config) ->
    ct:comment("parse OTR TAGGED WHITESPACE (V2) message"),
    M = "some irrelvant text in front of the "
	"v2 tag \t  \t\t\t\t \t \t \t    \t\t "
	" \t and after it",
    {ok,
     #otr_msg_tagged_ws{s =
			    "some irrelvant text in front of the "
			    "v2 tagand after it"}} =
	otr_message:parse(M).

parse_tagged_ws_2(_Config) ->
    ct:comment("parse OTR TAGGED WHITESPACE (V1 or V2) "
	       "message"),
    M = "some irrelvant text in front of the "
	"v1 and v2 tag \t  \t\t\t\t \t \t \t "
	"  \t \t  \t   \t\t  \t and after it",
    {ok,
     #otr_msg_tagged_ws{s =
			    "some irrelvant text in front of the "
			    "v1 and v2 tagand after it"}} =
	otr_message:parse(M).

encode_tagged_ws(_Config) ->
    ct:comment("encode OTR TAGGED WHITESPACE message"),
    {ok,
     "the leading plaintext \t  \t\t\t\t \t "
     "\t \t    \t\t  \t "} =
	otr_message:encode(#otr_msg_tagged_ws{s =
						  "the leading plaintext"}).

parse_fragment(_Config) ->
    ct:comment("parse OTR FRAGMENT message"),
    {ok, #otr_msg_fragment{k = 1, n = 2, f = "foobarnaz"}} =
	otr_message:parse("?OTR,1,2,foobarnaz,").


encode_fragmented_1(_Config) ->
    ct:comment("encode fragmented OTR DATA message (using "
	       "testvector #7)"),
    {MaxFragSize, FragmentList, Message} =
	(?MessageTestVector7),
    {fragmented, FragmentList} = otr_message:encode(Message,
						    MaxFragSize).

encode_fragmented_2(_Config) ->
    ct:comment("do not fragement messgages that are "
	       "smaller than the maximum fragment size "
	       "(using testvector #3)"),
    {Data, Message} = (?MessageTestVector3),
    {ok, Data} = otr_message:encode(Message, 1024).

parse_plain_1(_Config) ->
    ct:comment("Fail to decode OTR QUERY (no V2) messages"),
    plain = otr_message:parse("?OTR? v1 message"),
    plain =
	otr_message:parse("?OTR?v3456? v1,v3,v4,v5,v6 but no v2 "
			  "message"),
    plain =
	otr_message:parse("?OTR?v malformed qyery message").

parse_plain_2(_Config) ->
    ct:comment("Fail to decode OTR DATA messages that "
	       "does not termintate with a ."),
    plain =
	otr_message:parse("just because there is a ?OTR: in the "
			  "stream  don't assume a data message").

parse_plain_3(_Config) ->
    ct:comment("Fail to decode OTR DATA messages that "
	       "is not base64 encoded"),
    plain =
	otr_message:parse("just because there is a ?OTR: in the "
			  "stream  don't assume a data message, "
			  "not even if there is a dot.").

parse_plain_4(_Config) ->
    ct:comment("Fail to decode malformend OTR FRAGMENT "
	       "message"),
    plain =
	otr_message:parse(" ?OTR, this message does not contain "
			  "enough ,").

parse_plain_5(_Config) ->
    ct:comment("Fail to decode malformend OTR FRAGMENT "
	       "message"),
    plain =
	otr_message:parse(" ?OTR, this message does has enough "
			  ", ,, but no integers").

parse_fail_1(_Config) ->
    ct:comment("indicate wrong protocol version in OTR "
	       "DATA message"),
    {error, {encoded_m, unsupported_version}} =
	otr_message:parse("?OTR:AAFzb21lIGlycmVsZXZhbnQgc3R1ZmYgYWZ0ZXIg"
			  "dmVyc2lvbg==.").

parse_fail_2(_Config) ->
    ct:comment("indicate invalid OTR DATA message (garbage "
	       "after protocoll version)"),
    {error, {encoded_m, invalid_data_message}} =
	otr_message:parse("?OTR:AAJwcm90b2NvbHZlcnNpb24gaXMgb2sgYnV0IG5v"
			  "dGhpbmcgZWxzZQ==.").

parse_fail_3(_Config) ->
    ct:comment("indicate invalid OTR FRAGMENT message "
	       "(K > N)"),
    {error, {fragment_m, invalid_fragment_m}} =
	otr_message:parse("?OTR,2,1,foo,").

parse_fail_4(_Config) ->
    ct:comment("indicate invalid OTR FRAGMENT message "
	       "(K = 0)"),
    {error, {fragment_m, invalid_fragment_m}} =
	otr_message:parse("?OTR,0,1,foo,").

parse_fail_5(_Config) ->
    ct:comment("indicate invalid OTR FRAGMENT message "
	       "(N = 0)"),
    {error, {fragment_m, invalid_fragment_m}} =
	otr_message:parse("?OTR,2,0,foo,").
