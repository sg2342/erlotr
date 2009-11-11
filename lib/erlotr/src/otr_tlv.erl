%%
%% Purpose: Off-the-Record Messaging
%%          (http://www.cypherpunks.ca/otr/Protocol-v2-3.1.0.html)
%%          OTR data message TLV encoding decoding
%%

-module(otr_tlv).

-author("Stefan Grundmann <sg2342@googlemail.com>").

-copyright("Copyright 2009 Stefan Grundmann").

-export([decode/1, encode/1]).

encode(Message) when is_list(Message) ->
    list_to_binary(Message);
encode({Message, TLVLst})
    when is_list(Message), is_list(TLVLst) ->
    <<(list_to_binary(Message))/binary,
      (encode_tlvs(TLVLst, <<0>>))/binary>>.

decode(Bin) ->
    {MessagePart, TLVPart} = split_parts(Bin),
    {MessagePart, dec_tlv(TLVPart, [])}.

%F{{{ internal functions
encode_tlvs([], Acc) -> Acc;
encode_tlvs([{padding, I} | Rest], Acc) when is_integer(I) ->
    encode_tlvs(Rest,
		<<Acc/binary, 0:16, I:16, 0:(I bsl 3)>>);
encode_tlvs([disconnected | Rest], Acc) ->
    encode_tlvs(Rest,
		<<Acc/binary, 1:16, 0:16>>);
encode_tlvs([{smp_msg_1, V} | Rest], Acc) ->
    L = encode_smp_mpi_lst(V),
    encode_tlvs(Rest,
		<<Acc/binary, 2:16, (size(L)):16, L/binary>>);
encode_tlvs([{smp_msg_2, V} | Rest], Acc) ->
    L = encode_smp_mpi_lst(V),
    encode_tlvs(Rest,
		<<Acc/binary, 3:16, (size(L)):16, L/binary>>);
encode_tlvs([{smp_msg_3, V} | Rest], Acc) ->
    L = encode_smp_mpi_lst(V),
    encode_tlvs(Rest,
		<<Acc/binary, 4:16, (size(L)):16, L/binary>>);
encode_tlvs([{smp_msg_4, V} | Rest], Acc) ->
    L = encode_smp_mpi_lst(V),
    encode_tlvs(Rest,
		<<Acc/binary, 5:16, (size(L)):16, L/binary>>);
encode_tlvs([smp_abort | Rest], Acc) ->
    encode_tlvs(Rest,
		<<Acc/binary, 6:16, 0:16>>).

encode_smp_mpi_lst([]) -> <<0:32>>;
encode_smp_mpi_lst(L) when is_list(L) ->
    do_encode_smp_mpi_lst(L, <<(length(L)):32>>).

do_encode_smp_mpi_lst([], Acc) -> Acc;
do_encode_smp_mpi_lst([Int | Rest], Acc) ->
    do_encode_smp_mpi_lst(Rest,
			  <<Acc/binary, (otr_util:mpint(Int))/binary>>).

dec_tlv(<<>>, Acc) -> lists:reverse(Acc);
dec_tlv(<<0:16, L:16, _V:L/binary, Rest/binary>>, Acc) ->
    dec_tlv(Rest, [{padding, L} | Acc]);
dec_tlv(<<1:16, L:16, _V:L/binary, Rest/binary>>, Acc) ->
    dec_tlv(Rest, [disconnected | Acc]);
dec_tlv(<<2:16, L:16, V:L/binary, Rest/binary>>, Acc) ->
    dec_tlv(Rest, [{smp_msg_1, dec_smp_mpi_lst(V)} | Acc]);
dec_tlv(<<3:16, L:16, V:L/binary, Rest/binary>>, Acc) ->
    dec_tlv(Rest, [{smp_msg_2, dec_smp_mpi_lst(V)} | Acc]);
dec_tlv(<<4:16, L:16, V:L/binary, Rest/binary>>, Acc) ->
    dec_tlv(Rest, [{smp_msg_3, dec_smp_mpi_lst(V)} | Acc]);
dec_tlv(<<5:16, L:16, V:L/binary, Rest/binary>>, Acc) ->
    dec_tlv(Rest, [{smp_msg_4, dec_smp_mpi_lst(V)} | Acc]);
dec_tlv(<<6:16, L:16, _V:L/binary, Rest/binary>>, Acc) ->
    dec_tlv(Rest, [smp_abort | Acc]);
dec_tlv(_, _) -> error.

dec_smp_mpi_lst(<<Count:32, V/binary>>) ->
    do_decode_smp_mpi_lst(Count, V, []).

do_decode_smp_mpi_lst(0, <<>>, Acc) ->
    lists:reverse(Acc);
do_decode_smp_mpi_lst(C,
		      <<L:32, V:L/binary, Rest/binary>>, Acc) ->
    do_decode_smp_mpi_lst(C - 1, Rest,
			  [otr_util:erlint(<<L:32, V/binary>>) | Acc]);
do_decode_smp_mpi_lst(_, _, _) -> error.

split_parts(Bin) ->
    Message = binary_to_list(Bin),
    case string:chr(Message, 0) of
      0 -> {Message, <<>>};
      X ->
	  {string:substr(Message, 1, X - 1),
	   list_to_binary(string:substr(Message, X + 1))}
    end.

%}}}F
