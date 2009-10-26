-module(otr_crypto).

-author("Stefan Grundmann <sg2342@googlemail.com>").

-export([aes_ctr_128_encrypt/3, aes_ctr_128_decrypt/3]).


aes_ctr_128_decrypt(Key, Nonce, Data) ->
    aes_ctr_128_encrypt(Key, Nonce, Data).

aes_ctr_128_encrypt(Key, Nonce, Data)
    when size(Key) == 16, size(Nonce) == 8,
	 is_binary(Data) ->
    do_aes_ctr_128(Key, {Nonce, 0}, Data, <<>>).


%
% abuse crypto:aes_cfb_128_encrypt/3 
% by feeding it 16 byte blocks
%
do_aes_ctr_128(_, _, <<>>, Ciphertext) -> Ciphertext;
do_aes_ctr_128(Key, {Nonce, Counter}, Plaintext,
	       Ciphertext)
    when size(Plaintext) < 16 ->
    PadSize = 16 - size(Plaintext),
    PtBlock = <<Plaintext/binary, 0:(PadSize bsl 3)>>,
    Control = <<Nonce/binary, Counter:64>>,
    CtBlock = crypto:aes_cfb_128_encrypt(Key, Control,
					 PtBlock),
    <<Ciphertext/binary, CtBlock:(size(Plaintext))/binary>>;
do_aes_ctr_128(Key, {Nonce, Counter}, Plaintext,
	       Ciphertext) ->
    <<PtBlock:16/binary, Tail/binary>> = Plaintext,
    Control = <<Nonce/binary, Counter:64>>,
    CtBlock = crypto:aes_cfb_128_encrypt(Key, Control,
					 PtBlock),
    do_aes_ctr_128(Key, {Nonce, Counter + 1}, Tail,
		   <<Ciphertext/binary, CtBlock/binary>>).
