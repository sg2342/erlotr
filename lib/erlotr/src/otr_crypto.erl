%
% this module is mostly just a wrapper around crypto primitives provided by
% the crypto application.
%
% some crypto primitives needed by the OTR application are not part
% of the crypto application. these are implemented here.
%

-module(otr_crypto).

-author("Stefan Grundmann <sg2342@googlemail.com>").

-include("otr_internal.hrl").

-export([aes_ctr_128_decrypt/3, aes_ctr_128_encrypt/3,
	 aes_ecb_128_decrypt/2, aes_ecb_128_encrypt/2,
	 dh_agree/2, dh_gen_key/0, dsa_sign/2, dsa_verify/3,
	 irandom/1, sha1/1, sha1/3, sha1HMAC/2, sha256/1,
	 sha256/3, sha256HMAC/2]).

%F{{{ ...HMAC...
sha1HMAC(Key, Data) -> crypto:sha_mac(Key, Data).

sha256HMAC(Key, Data) when size(Key) > 64 ->
    HK = sha256(Key),
    sha256HMAC(<<HK/binary, 0:(32 bsl 3)>>, Data);
sha256HMAC(Key, Data) when size(Key) < 64 ->
    sha256HMAC(<<Key/binary, 0:(64 - size(Key) bsl 3)>>,
	       Data);
sha256HMAC(Key, Data) ->
    KxorIpad = list_to_binary([V bxor 54
			       || V <- binary_to_list(Key)]),
    KxorOpad = list_to_binary([V bxor 92
			       || V <- binary_to_list(Key)]),
    H1 = sha256(<<KxorIpad/binary, Data/binary>>),
    sha256(<<KxorOpad/binary, H1/binary>>).%}}}F

%F{{{ sha1...
sha1(Data) -> crypto:sha(Data).

sha1(Data, Offset, Length)
    when is_binary(Data), Offset > 0, Length > 0,
	 size(Data) - (Offset + Length) > 0 ->
    <<_:Offset/binary, Part:Length/binary, _/binary>> =
	Data,
    crypto:sha(Part).%}}}F

%F{{{ sha1...
sha256(Data) -> crypto:sha256(Data).

sha256(Data, Offset, Length)
    when is_binary(Data), Offset > 0, Length > 0,
	 size(Data) - (Offset + Length) > 0 ->
    <<_:Offset/binary, Part:Length/binary, _/binary>> =
	Data,
    crypto:sha256(Part).%}}}F

%F{{{ aes_ecb_ ...
%
% abuse CBC mode with an IV of 0 to have ECB mode functionality
%
aes_ecb_128_encrypt(Key, Block) ->
    crypto:aes_cbc_128_encrypt(Key, <<0:128>>, Block).

aes_ecb_128_decrypt(Key, Block) ->
    crypto:aes_cbc_128_decrypt(Key, <<0:128>>, Block).%}}}F

%F{{{ aes_ctr_128 ...
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

%}}}F

%F{{{ dsa_sign, dsa_verify
%
% stolen from ssh-1.1.6/src/ssh_dsa.erl

dsa_sign(_DsaKey = [P, Q, G, X, _], Data) ->
    dsa_sign([P, Q, G, X], Data);
dsa_sign(_PrivateKey = [P, Q, G, X], Data) ->
    K = irandom(160) rem Q,
    R = ipow(G, K, P) rem Q,
    Ki = invert(K, Q),
    BS = size(Data) bsl 3,
    <<M:BS/big-unsigned-integer>> = Data,
    S = Ki * (M + X * R) rem Q,
    {R, S}.

dsa_verify(_PublicKey = [P, Q, G, Y], Data, {R0, S0}) ->
    W = invert(S0, Q),
    BS = size(Data) bsl 3,
    <<M0:BS/big-unsigned-integer>> = Data,
    U1 = M0 * W rem Q,
    U2 = R0 * W rem Q,
    T1 = ipow(G, U1, P),
    T2 = ipow(Y, U2, P),
    V = T1 * T2 rem P rem Q,
    V == R0.

%}}}F

%F{{{ dh_gen_key/0, dh_agree/2

dh_gen_key() ->
    P = (?DH_MODULUS),
    Private = irandom(isize(P) - 1, 1, 1),
    Public = ipow(2, Private, P),
    if (Public >= 2) and (Public =< (?DH_MODULUS) - 2) ->
	   {Private, Public};
       true -> dh_gen_key()
    end.

dh_agree(Private, PeerPub) ->
    ipow(PeerPub, Private, ?DH_MODULUS).

%}}}F

%F{{{ irandom, ipow, invert, issize
%
% stolen from Lsh-1.1.6/src/ssh_math.erl, ssh-1.1.6/src/ssh_math.erl

irandom(Bits) -> %F{{{
    irandom(Bits, 1, 0).

irandom(0, _Top, _Bottom) -> 0;
irandom(Bits, Top, Bottom) ->
    Bytes = (Bits + 7) div 8,
    Skip = (8 - Bits rem 8) rem 8,
    TMask = case Top of
	      0 -> 0;
	      1 -> 128;
	      2 -> 192
	    end,
    BMask = case Bottom of
	      0 -> 0;
	      1 -> 1 bsl Skip
	    end,
    <<X:Bits/big-unsigned-integer, _:Skip>> = random(Bytes,
						     TMask, BMask),
    X.

random(N, TMask, BMask) ->
    list_to_binary(rnd(N, TMask, BMask)).

rnd(0, _TMask, _BMask) -> [];
rnd(1, TMask, BMask) -> [rand8() bor TMask bor BMask];
rnd(N, TMask, BMask) ->
    [rand8() bor TMask | rnd_n(N - 1, BMask)].

rnd_n(1, BMask) -> [rand8() bor BMask];
rnd_n(I, BMask) -> [rand8() | rnd_n(I - 1, BMask)].

rand8() -> (rand32() bsr 8) band 255.

rand32() -> random:uniform(4294967296) - 1.

%}}}F

%F{{{ isisze/1
%% HACK WARNING :-)
-define(VERSION_MAGIC, 131).

-define(SMALL_INTEGER_EXT, $a).

-define(INTEGER_EXT, $b).

-define(SMALL_BIG_EXT, $n).

-define(LARGE_BIG_EXT, $o).

isize(N) when N > 0 ->
    case term_to_binary(N) of
      <<(?VERSION_MAGIC), (?SMALL_INTEGER_EXT), X>> ->
	  isize_byte(X);
      <<(?VERSION_MAGIC), (?INTEGER_EXT), X3, X2, X1, X0>> ->
	  isize_bytes([X3, X2, X1, X0]);
      <<(?VERSION_MAGIC), (?SMALL_BIG_EXT),
	S:8/big-unsigned-integer, 0, Ds:S/binary>> ->
	  K = S - 1,
	  <<_:K/binary, Top>> = Ds,
	  isize_byte(Top) + K * 8;
      <<(?VERSION_MAGIC), (?LARGE_BIG_EXT),
	S:32/big-unsigned-integer, 0, Ds:S/binary>> ->
	  K = S - 1,
	  <<_:K/binary, Top>> = Ds,
	  isize_byte(Top) + K * 8
    end;
isize(0) -> 0.

%% big endian byte list
isize_bytes([0 | L]) -> isize_bytes(L);
isize_bytes([Top | L]) ->
    isize_byte(Top) + length(L) * 8.

%% Well could be improved
isize_byte(X) ->
    if X >= 128 -> 8;
       X >= 64 -> 7;
       X >= 32 -> 6;
       X >= 16 -> 5;
       X >= 8 -> 4;
       X >= 4 -> 3;
       X >= 2 -> 2;
       X >= 1 -> 1;
       true -> 0
    end.

%}}}F

ipow(A, B, M) when M > 0, B >= 0 ->
    crypto:mod_exp(A, B, M).

invert(X, P)
    when X > 0, P > 0, X < P -> %F{{{
    I = inv(X, P, 1, 0),
    if I < 0 -> P + I;
       true -> I
    end.

inv(0, _, _, Q) -> Q;
inv(X, P, R1, Q1) ->
    D = P div X,
    inv(P rem X, X, Q1 - D * R1, R1).%}}}F
				     %}}}F

