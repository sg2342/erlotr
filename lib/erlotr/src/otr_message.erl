-module(otr_message).

-author("Stefan Grundmann <sg2342@googlemail.com>").

-include("otr_internal.hrl").

%F{{{ constants
-define(TAG_V1_or_V2,
	" \t  \t\t\t\t \t \t \t   \t \t  \t  "
	" \t\t  \t ").

-define(TAG_V2, " \t  \t\t\t\t \t \t \t    \t\t  \t ").

%}}}F

-export([encode/1, encode/2, parse/1]).

encode(M) -> do_encode(M).

encode(M, MaxFragmentSize) ->
    {ok, S} = do_encode(M), do_fragment(S, MaxFragmentSize).

parse(M) when is_list(M) ->
    {ParseFun, Ss, Sl} = get_parsefun_and_params(M),
    case ParseFun(M, Ss, Sl) of
      plain -> plain;
      Else -> Else
    end.

%F{{{ encode code
do_encode({plain, M}) -> {ok, M};
do_encode(otr_msg_query) -> {ok, "?OTRv2?"};
do_encode(#otr_msg_tagged_ws{s = S}) ->
    {ok, S ++ (?TAG_V2)};
do_encode(#otr_msg_error{s = S}) ->
    {ok, "?OTR Error:" ++ S};
do_encode(#otr_msg_dh_commit{enc_gx = EncGx,
			     hash_gx = HashGx}) ->
    do_encode_bin(<<2:16, (?TYPE_DH_COMMIT),
		    (size(EncGx)):32, EncGx/binary, (size(HashGx)):32,
		    HashGx/binary>>);
do_encode(#otr_msg_dh_key{gy = Gy}) ->
    MpiGy = otr_util:mpint(Gy),
    do_encode_bin(<<2:16, (?TYPE_DH_KEY), MpiGy/binary>>);
do_encode(#otr_msg_reveal_signature{r = R,
				    enc_sig = EncSig, mac = Mac}) ->
    do_encode_bin(<<2:16, (?TYPE_REVEAL_SIGNATURE),
		    (size(R)):32, R/binary, (size(EncSig)):32,
		    EncSig/binary, Mac/binary>>);
do_encode(#otr_msg_signature{enc_sig = EncSig,
			     mac = Mac}) ->
    do_encode_bin(<<2:16, (?TYPE_SIGNATURE),
		    (size(EncSig)):32, EncSig/binary, Mac/binary>>);
do_encode(#otr_msg_data{flags = Flags,
			sender_keyid = SenderKeyId,
			recipient_keyid = RecipientKeyId, dhy = Dhy,
			ctr_init = Ctr, enc_data = Data, mac = Mac,
			old_mac_keys = OldMacKeys}) ->
    MpiDhy = otr_util:mpint(Dhy),
    do_encode_bin(<<2:16, (?TYPE_DATA), Flags:8,
		    SenderKeyId:32, RecipientKeyId:32, MpiDhy/binary,
		    Ctr:8/binary, (size(Data)):32, Data/binary,
		    Mac:20/binary, (size(OldMacKeys)):32,
		    OldMacKeys/binary>>).

do_encode_bin(Bin) ->
    {ok, "?OTR:" ++ base64:encode_to_string(Bin) ++ "."}.

%}}}F

%F{{{ fragment encode code

do_fragment(S, MaxFragmentSize)
    when length(S) =< MaxFragmentSize ->
    {ok, S};
do_fragment(S, MaxFragmentSize) ->
    do_fragment_1(S, 1,
		  (length(S) + MaxFragmentSize - 1) div MaxFragmentSize,
		  MaxFragmentSize, []).

do_fragment_1(LastFragment, K, K, _, L) ->
    Header = fragment_header(K, K),
    {fragmented,
     lists:reverse([Header ++ LastFragment ++ "," | L])};
do_fragment_1(S, K, N, Fs, L) ->
    Header = fragment_header(K, N),
    {Piece, Rest} = lists:split(Fs, S),
    do_fragment_1(Rest, K + 1, N, Fs,
		  [Header ++ Piece ++ "," | L]).

fragment_header(K, N) ->
    "?OTR," ++
      integer_to_list(K) ++ "," ++ integer_to_list(N) ++ ",".

%}}}F

%F{{{ parse code
get_parsefun_and_params(M) ->
    L = [{"?OTR,", fun parse_fragment_m/3},
	 {"?OTR:", fun parse_encoded_m/3},
	 {"?OTR Error:", fun parse_error_m/3},
	 {"?OTRv", fun parse_query_m/3},
	 {"?OTR?v", fun parse_query_m/3},
	 {?TAG_V2, fun parse_tagged_ws_m/3},
	 {?TAG_V1_or_V2, fun parse_tagged_ws_m/3}],
    get_parsefun_and_params_1(M, L).

get_parsefun_and_params_1(_, []) ->
    {fun (_, _, _) -> plain end, ignored, ignored};
get_parsefun_and_params_1(M, [{SubString, F} | T]) ->
    case string:str(M, SubString) of
      0 -> get_parsefun_and_params_1(M, T);
      X -> {F, X, length(SubString)}
    end.

parse_error_m(M, Ss, Sl) ->
    {ok, #otr_msg_error{s = string:sub_string(M, Ss + Sl)}}.

parse_tagged_ws_m(M, Ss, Sl) ->
    {ok,
     #otr_msg_tagged_ws{s =
			    string:concat(string:sub_string(M, 1, Ss - 1),
					  string:sub_string(M, Ss + Sl))}}.

parse_query_m(M, Ss, Sl) ->
    case string:chr(string:sub_string(M, Ss + Sl), $2) of
      0 -> plain;
      X ->
	  case string:chr(string:sub_string(M, Ss + Sl), $?) of
	    Y when Y > X -> {ok, otr_msg_query};
	    _ -> plain
	  end
    end.

parse_fragment_m(M, Ss, Sl) ->
    X = string:chr(string:sub_string(M, Ss + Sl), $,),
    Y = string:chr(string:sub_string(M, Ss + Sl + X), $,),
    Z = string:rchr(string:sub_string(M, Ss + Sl + X + Y),
		   $,),
    if X > 0, Y > 0, Z > 0 ->
	   try K = list_to_integer(string:sub_string(M, Ss + Sl,
						     Ss + Sl + X - 2)),
	       N = list_to_integer(string:sub_string(M, Ss + Sl + X,
						     Ss + Sl + X + Y - 2)),
	       F = string:substr(M, Ss + Sl + X + Y, Z - 1),
	       if K > 0, N > 0, K =< N, length(F) > 0 ->
		      {ok, #otr_msg_fragment{k = K, n = N, f = F}};
		  true -> {error, {fragment_m, invalid_fragment_m}}
	       end
	   catch
	     error:badarg -> plain
	   end;
       true -> plain
    end.

parse_encoded_m(M, Ss, Sl) ->
    case string:chr(string:sub_string(M, Ss + Sl), $.) of
      0 -> plain;
      X ->
	  try Bin = base64:decode(string:substr(M, Ss + Sl,
						X - 1)),
	      try parse_encoded_bin(Bin) catch
		_:_ -> {error, {encoded_m, invalid_data_message}}
	      end
	  catch
	    _:_ -> plain %base64:decode failed
	  end
    end.

parse_encoded_bin(<<_X:16, _/binary>>) when _X /= 2 ->
    {error, {encoded_m, unsupported_version}};
parse_encoded_bin(<<2:16, (?TYPE_DH_COMMIT), _ZEncGx:32,
		    EncGx:_ZEncGx/binary, _ZHashGx:32,
		    HashGx:_ZHashGx/binary>>) ->
    {ok,
     #otr_msg_dh_commit{enc_gx = EncGx, hash_gx = HashGx}};
parse_encoded_bin(<<2:16, (?TYPE_DH_KEY),
		    MpiGy/binary>>) ->
    {ok, #otr_msg_dh_key{gy = otr_util:erlint(MpiGy)}};
parse_encoded_bin(<<2:16, (?TYPE_REVEAL_SIGNATURE),
		    _ZR:32, R:_ZR/binary, _ZEncSig:32,
		    EncSig:_ZEncSig/binary, Mac:20/binary>>) ->
    {ok,
     #otr_msg_reveal_signature{r = R, enc_sig = EncSig,
			       mac = Mac}};
parse_encoded_bin(<<2:16, (?TYPE_SIGNATURE),
		    _ZEncSig:32, EncSig:_ZEncSig/binary, Mac:20/binary>>) ->
    {ok, #otr_msg_signature{enc_sig = EncSig, mac = Mac}};
parse_encoded_bin(<<2:16, (?TYPE_DATA), Flags:8,
		    SenderKeyId:32, RecipientKeyId:32, ZMpiDhy:32,
		    MpiDhy:ZMpiDhy/binary, Ctr:8/binary, _ZData:32,
		    Data:_ZData/binary, Mac:20/binary, _ZOldMacKeys:32,
		    OldMacKeys:_ZOldMacKeys/binary>>) ->
    Dhy = otr_util:erlint(<<ZMpiDhy:32, MpiDhy/binary>>),
    {ok,
     #otr_msg_data{flags = Flags, sender_keyid = SenderKeyId,
		   recipient_keyid = RecipientKeyId, dhy = Dhy,
		   ctr_init = Ctr, enc_data = Data, mac = Mac,
		   old_mac_keys = OldMacKeys}}.%}}}F

