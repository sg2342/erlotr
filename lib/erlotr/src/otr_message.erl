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

-define(QUESTION_MARK, 63).

-define(DIGIT_TWO, 50).
%}}}F

-export([decode/1, encode/1]).


decode(M) -> {ok, parse(M)}.

%F{{{ encode/1
encode(#otr_msg{type = query_v2}) -> {ok, <<"?OTRv2?">>};
encode(#otr_msg{type = error, value = ErrorMsg}) ->
    {ok, <<"?OTR Error:", ErrorMsg>>};
encode(#otr_msg{type = dh_commit, 
                value = #otr_msg_dh_commit{enc_gx = EncGx, 
		                           mac_gx = MacGx}}) 
    when size(MacGx) == 20 ->
    Enc = base64:encode(<<2:16, ?TYPE_DH_COMMIT, (size(EncGx)):32, 
                          EncGx/binary, MacGx/binary>>),
    {ok, <<"?OTR:", Enc/binary, ".">>}; 
encode(#otr_msg{type = dh_key, 
                value = #otr_msg_dh_key{mpi_gy = MpiGy}}) ->
    Enc = base64:encode(<<2:16, ?TYPE_DH_KEY, (size(MpiGy)):32, 
                          MpiGy/binary>>),
    {ok, <<"?OTR:", Enc/binary, ".">>};
encode(#otr_msg{type = reveal_signature,
                value = #otr_msg_reveal_signature{revealed_key = RevKey,
		                                  enc_sig = EncSig,
						  mac_enc_sig = MacEncSig}})
    when size(MacEncSig) == 20 ->
    Enc = base64:encode(<<2:16, ?TYPE_REVEAL_SIGNATURE, 
                          (size(RevKey)):32, RevKey/binary, 
			  (size(EncSig)):32, EncSig/binary,
			  MacEncSig/binary>>),
    {ok, <<"?OTR:", Enc/binary, ".">>};
encode(#otr_msg{type = signature, 
                value = #otr_msg_signature{enc_sig = EncSig,
		                           mac_enc_sig = MacEncSig}})
    when size(MacEncSig) == 20 ->
    Enc = base64:encode(<<2:16, ?TYPE_SIGNATURE, (size(EncSig)):32,
	 		  EncSig/binary, MacEncSig/binary>>),
    {ok, <<"?OTR:", Enc/binary, ".">>};
encode(#otr_msg{type = data,
                value = #otr_msg_data{flags = Flags, 
		                      sender_keyid = SenderKeyId,
				      recipient_keyid = RecipientKeyId,
				      mpi_dhy = MpiDhy,
				      ctr_init = Ctr,
				      enc_data = EncData,
				      mac = Mac,
				      old_mac_keys = OldMacKeys}})
    when size(Mac) == 20, SenderKeyId > 0, RecipientKeyId > 0, size(Ctr) == 8 ->
    Enc = base64:encode(<<2:16, ?TYPE_DATA, Flags:8, SenderKeyId:32, 
			  RecipientKeyId:32, (size(MpiDhy)):32, 
			  MpiDhy/binary, Ctr/binary, 
			  (size(EncData)):32, EncData/binary, Mac/binary,
			  (size(OldMacKeys)):32, OldMacKeys/binary>>),
    {ok, <<"?OTR:", Enc/binary, ".">>}.
%}}}F

%F{{{ parse/1
parse(<<"?OTR:", Bin/binary>>) ->
    Sz = size(Bin) - 1,
    <<Encoded:Sz/binary, ".">> = Bin,
    parse_encoded(base64:decode(Encoded));
parse(<<"?OTR,", Value/binary>>) ->
    #otr_msg{type = fragment, value = Value}; % XXX Later
parse(<<"?OTR Error:", ErrorMsg/binary>>) ->
    #otr_msg{type = error,
	     value = binary_to_list(ErrorMsg)};
parse(<<"?OTR?v", R/binary>>) ->
    S = binary_to_list(R),
    T = case string:chr(S, ?QUESTION_MARK) of
	  0 -> query_v1;
	  X ->
	      case string:chr(string:left(S, X - 1), ?DIGIT_TWO) of
		0 -> query_v1;
		_ -> query_v1_or_v2
	      end
	end,
    #otr_msg{type = T};
parse(<<"?OTRv", R/binary>>) ->
    S = binary_to_list(R),
    T = case string:chr(S, ?QUESTION_MARK) of
	  0 -> plain;
	  X ->
	      case string:chr(string:left(S, X - 1), ?DIGIT_TWO) of
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
		      _ -> tagged_whitespace_v2_only
		    end;
		_ -> tagged_whitespace_v1_only
	      end;
	  _ -> tagged_whitespace_v1_and_v2
	end,
    #otr_msg{type = T}.
%}}}F

%F{{{ parse_encoded/1 
parse_encoded(<<2:16, ?TYPE_DH_COMMIT, _ZEncGx:32,
		EncGx:_ZEncGx/binary, _ZMacGx:32,
		MacGx:_ZMacGx/binary>>) ->
    #otr_msg{type = dh_commit,
	     value =
		 #otr_msg_dh_commit{enc_gx = EncGx,
				    mac_gx = MacGx}};
parse_encoded(<<2:16, ?TYPE_DH_KEY, _ZMpiGy:32, MpiGy:_ZMpiGy/binary>>) ->
   #otr_msg{type = dh_key, 
            value = #otr_msg_dh_key{mpi_gy = MpiGy}};
parse_encoded(<<2:16, ?TYPE_REVEAL_SIGNATURE, _ZRevKey:32, 
                RevKey:_ZRevKey/binary, _ZEncSig:32, 
		EncSig:_ZEncSig/binary, MacEncSig:20/binary>>) ->
    #otr_msg{type = reveal_signature, 
             value = #otr_msg_reveal_signature{revealed_key = RevKey,
					       enc_sig = EncSig,
					       mac_enc_sig = MacEncSig}};
parse_encoded(<<2:16, ?TYPE_SIGNATURE, _ZEncSig:32,
               EncSig:_ZEncSig/binary, MacEncSig:20/binary>>) ->
    #otr_msg{type = signature,
	     value = #otr_msg_signature{enc_sig = EncSig,
					mac_enc_sig = MacEncSig}};
parse_encoded(<<2:16, ?TYPE_DATA, Flags:8, SenderKeyId:32, 
                RecipientKeyId:32, _ZMpiDhy:32, MpiDhy:_ZMpiDhy/binary,
		Ctr:8/binary, _ZData:32, Data:_ZData/binary,
		Mac:20/binary, _ZOldMacKeys:32, 
		OldMacKeys:_ZOldMacKeys/binary>>) ->
    #otr_msg{type = data,
             value = #otr_msg_data{flags = Flags,
				   sender_keyid = SenderKeyId,
				   recipient_keyid = RecipientKeyId,
				   mpi_dhy = MpiDhy,
				   ctr_init = Ctr,
				   enc_data = Data,
				   mac = Mac,
				   old_mac_keys = OldMacKeys}};
parse_encoded(_) ->
    erlang:error(badarg).
%}}}F
