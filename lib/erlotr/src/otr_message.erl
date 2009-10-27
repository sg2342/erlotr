-module(otr_message).

-author("Stefan Grundmann <sg2342@googlemail.com>").

-include("otr_message.hrl").

%F{{{ constants
-define(TYPE_DH_COMMIT,        16#02:8).
-define(TYPE_DH_KEY,           16#0a:8).
-define(TYPE_REVEAL_SIGNATURE, 16#11:8).
-define(TYPE_SIGNATURE,        16#12:8).
-define(TYPE_DATA, 	       16#03:8).

-define(TAG_START, " \t  \t\t\t\t \t \t \t  ").

-define(TAG_V1, " \t \t  \t ").

-define(TAG_V2, "  \t\t  \t ").

%}}}F



-export([decode/1, decode/2, encode/1, encode/2, parse_fragment/1]).

-export([mpint/1]).

decode(M) -> decode(M, #otr_fragment{}).

decode(M, #otr_fragment{k = K, n = N, f = F}) -> 
    try case parse(M) of
	#otr_fragment{k = N, n = N, f = Nf} when N > 0 ->
	    OtrMsg = parse(concat_binary([F, Nf])), 
	    {ok, OtrMsg};
	#otr_fragment{k = Nk, n = N, f = Nf } when Nk == (K + 1) ->
	    {fragment, #otr_fragment{k = Nk, n = N, f=concat_binary([F, Nf])}};
	#otr_fragment{k = 1, n = Nn} = Nf when Nn > 0 -> {fragment, Nf};
	#otr_fragment{} -> {error, invalid_fragment};
	OtrMsg = #otr_msg{type = _, value = _} -> {ok, OtrMsg}
       end
    catch
	_:_ -> {error, parse_exception}
    end.

encode(M, FragSize) ->
    case encode(M) of
      {ok, Me} when size(Me) > FragSize ->
	  fragment(Me, FragSize);
      {ok, Me} -> {ok, Me}
    end.

%F{{{ encode/1
encode(#otr_msg{type = query_v2}) ->
    {ok, <<"?OTRv2?">>};
encode(#otr_msg{type = error, value = ErrorMsg}) ->
    {ok, list_to_binary("?OTR Error:" ++ ErrorMsg)};
encode(#otr_msg{type = dh_commit,
		value =
		    #otr_msg_dh_commit{enc_gx = EncGx, mac_gx = MacGx}}) ->
    Enc = base64:encode(<<2:16, ?TYPE_DH_COMMIT,
			  (size(EncGx)):32, EncGx/binary, (size(MacGx)):32,
			  MacGx/binary>>),
    {ok, <<"?OTR:", Enc/binary, ".">>};
encode(#otr_msg{type = dh_key,
		value = #otr_msg_dh_key{gy = Gy}}) ->
    MpiGy = mpint(Gy),
    Enc = base64:encode(<<2:16, ?TYPE_DH_KEY, MpiGy/binary>>),
    {ok, <<"?OTR:", Enc/binary, ".">>};
encode(#otr_msg{type = reveal_signature,
		value =
		    #otr_msg_reveal_signature{revealed_key = RevKey,
					      enc_sig = EncSig,
					      mac_enc_sig = MacEncSig}})
    when size(MacEncSig) == 20 ->
    Enc = base64:encode(<<2:16, ?TYPE_REVEAL_SIGNATURE,
			  (size(RevKey)):32, RevKey/binary, (size(EncSig)):32,
			  EncSig/binary, MacEncSig/binary>>),
    {ok, <<"?OTR:", Enc/binary, ".">>};
encode(#otr_msg{type = signature,
		value =
		    #otr_msg_signature{enc_sig = EncSig,
				       mac_enc_sig = MacEncSig}})
    when size(MacEncSig) == 20 ->
    Enc = base64:encode(<<2:16, ?TYPE_SIGNATURE,
			  (size(EncSig)):32, EncSig/binary, MacEncSig/binary>>),
    {ok, <<"?OTR:", Enc/binary, ".">>};
encode(#otr_msg{type = data,
		value =
		    #otr_msg_data{flags = Flags, sender_keyid = SenderKeyId,
				  recipient_keyid = RecipientKeyId,
				  dhy = Dhy, ctr_init = Ctr,
				  enc_data = EncData, mac = Mac,
				  old_mac_keys = OldMacKeys}})
    when size(Mac) == 20, SenderKeyId > 0,
	 RecipientKeyId > 0, size(Ctr) == 8 ->
    MpiDhy = mpint(Dhy),
    Enc = base64:encode(<<2:16, ?TYPE_DATA, Flags:8,
			  SenderKeyId:32, RecipientKeyId:32, MpiDhy/binary, 
			  Ctr/binary, (size(EncData)):32, EncData/binary, 
			  Mac/binary, (size(OldMacKeys)):32,
			  OldMacKeys/binary>>),
    {ok, <<"?OTR:", Enc/binary, ".">>}.%}}}F

parse_fragment(Fr) ->
    [K, N, F] =  string:tokens(binary_to_list(Fr), ","),
    #otr_fragment{k = list_to_integer(K), 
                  n = list_to_integer(N), 
		  f = list_to_binary(F)}.

%F{{{ parse/1
parse(<<"?OTR:", Bin/binary>>) ->
    Sz = size(Bin) - 1,
    <<Encoded:Sz/binary, ".">> = Bin,
    parse_encoded(base64:decode(Encoded));
parse(<<"?OTR,", Bin/binary>>) ->
    Sz = size(Bin) - 1,
    <<F:Sz/binary, ",">> = Bin,
    parse_fragment(F);
parse(<<"?OTR Error:", ErrorMsg/binary>>) ->
    #otr_msg{type = error,
	     value = binary_to_list(ErrorMsg)};
parse(<<"?OTR?v", R/binary>>) ->
    S = binary_to_list(R),
    T = case string:chr(S, $?) of
	  0 -> query_v1;
	  X ->
	      case string:chr(string:left(S, X - 1), $2) of
		0 -> query_v1;
		_ -> query_v1_or_v2
	      end
	end,
    #otr_msg{type = T};
parse(<<"?OTRv", R/binary>>) ->
    S = binary_to_list(R),
    T = case string:chr(S, $?) of
	  0 -> plain;
	  X ->
	      case string:chr(string:left(S, X - 1), $2) of
		0 -> query_unsupported;
		_ -> query_v2
	      end
	end,
    #otr_msg{type = T};
parse(<<"?OTR?", _R/binary>>) ->
    #otr_msg{type = query_v1};
parse(Msg) when is_binary(Msg) ->
    S = binary_to_list(Msg),
    T = case string:str(S,
			(?TAG_START) ++ (?TAG_V1) ++ (?TAG_V2))
	    of
	  0 ->
	      case string:str(S, (?TAG_START) ++ (?TAG_V1)) of
		0 ->
		    case string:str(S, (?TAG_START) ++ (?TAG_V2)) of
		      0 -> plain;
		      _ -> tagged_whitespace_v2
		    end;
		_ -> tagged_whitespace_v1
	      end;
	  _ -> tagged_whitespace_v1_or_v2
	end,
    #otr_msg{type = T}.%}}}F

%F{{{ parse_encoded/1
parse_encoded(<<2:16, ?TYPE_DH_COMMIT, _ZEncGx:32,
		EncGx:_ZEncGx/binary, _ZMacGx:32,
		MacGx:_ZMacGx/binary>>) ->
    #otr_msg{type = dh_commit,
	     value =
		 #otr_msg_dh_commit{enc_gx = EncGx, mac_gx = MacGx}};
parse_encoded(<<2:16, ?TYPE_DH_KEY, MpiGy/binary>>) ->
    #otr_msg{type = dh_key,
	     value = #otr_msg_dh_key{gy = crypto:erlint(MpiGy)}};
parse_encoded(<<2:16, ?TYPE_REVEAL_SIGNATURE,
		_ZRevKey:32, RevKey:_ZRevKey/binary, _ZEncSig:32,
		EncSig:_ZEncSig/binary, MacEncSig:20/binary>>) ->
    #otr_msg{type = reveal_signature,
	     value =
		 #otr_msg_reveal_signature{revealed_key = RevKey,
					   enc_sig = EncSig,
					   mac_enc_sig = MacEncSig}};
parse_encoded(<<2:16, ?TYPE_SIGNATURE, _ZEncSig:32,
		EncSig:_ZEncSig/binary, MacEncSig:20/binary>>) ->
    #otr_msg{type = signature,
	     value =
		 #otr_msg_signature{enc_sig = EncSig,
				    mac_enc_sig = MacEncSig}};
parse_encoded(<<2:16, ?TYPE_DATA, Flags:8,
		SenderKeyId:32, RecipientKeyId:32, ZMpiDhy:32,
		MpiDhy:ZMpiDhy/binary, Ctr:8/binary, _ZData:32,
		Data:_ZData/binary, Mac:20/binary, _ZOldMacKeys:32,
		OldMacKeys:_ZOldMacKeys/binary>>) ->
    Dhy = crypto:erlint(<<ZMpiDhy:32, MpiDhy/binary>>),
    #otr_msg{type = data,
	     value =
		 #otr_msg_data{flags = Flags, sender_keyid = SenderKeyId,
			       recipient_keyid = RecipientKeyId,
			       dhy = Dhy, ctr_init = Ctr,
			       enc_data = Data, mac = Mac,
			       old_mac_keys = OldMacKeys}};
parse_encoded(_) ->
    erlang:error(badarg).%}}}F

%F{{{ fragment/2 
fragment(M, Fs) ->
    fragment(M, 1, (size(M) + Fs - 1) div Fs, Fs, []).

fragment(LastPiece, K, K, _, L) ->
    Header = fragment_header(K, K),
    {fragmented,
     lists:reverse([concat_binary([Header, LastPiece, <<",">>]) | L])};
fragment(M, K, N, Fs, L) ->
    <<Piece:Fs/binary, Tail/binary>> = M,
    Header = fragment_header(K, N),
    fragment(Tail, K + 1, N, Fs,
	     [concat_binary([Header, Piece, <<",">>]) | L]).

fragment_header(K, N) ->
    list_to_binary("?OTR," ++ integer_to_list(K) ++
		   "," ++ integer_to_list(N) ++ ",").
%}}}F

mpint(X) ->
    <<_Size:32, Bin/binary>> = crypto:mpint(X),
    Stripped = strip_leading_zeros(Bin),
    <<(size(Stripped)):32, Stripped/binary>>.

strip_leading_zeros(<<0:8, Tail/binary>>) ->
    strip_leading_zeros(Tail);
strip_leading_zeros(Stripped) -> Stripped.
