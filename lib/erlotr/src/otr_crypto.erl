%
% this module is mostly just a wrapper around crypto primitives provided by
% the crypto application. 
%
% some crypto primitives needed by the OTR application are not part
% of the crypto application. these are implemented here.
%

-module(otr_crypto).

-author("Stefan Grundmann <sg2342@googlemail.com>").

-export([aes_ctr_128_decrypt/3, aes_ctr_128_encrypt/3,
	 dsa_sign/2, dsa_verify/3,
	 sha1/1, sha1/3, sha1HMAC/2, sha256/1, sha256/3,
	 sha256HMAC/2]).

%F{{{ ...HMAC...
sha1HMAC(Key, Data) -> crypto:sha_mac(Key, Data).

sha256HMAC(Key, Data) when size(Key) > 64 ->
    HK = sha256(Key),
    sha256HMAC(<<HK/binary, 0:(32 bsl 3)>>, Data);
sha256HMAC(Key, Data) when size(Key) < 64 ->
    sha256HMAC(<<Key/binary, 0:(64 - size(Key) bsl 3)>>,
	       Data);
sha256HMAC(Key, Data) ->
    KxorIpad = list_to_binary([V bxor 16#36
			       || V <- binary_to_list(Key)]),
    KxorOpad = list_to_binary([V bxor 16#5c
			       || V <- binary_to_list(Key)]),
    H1 = sha256(<<KxorIpad/binary, Data/binary>>),
    sha256(<<KxorOpad/binary, H1/binary>>).
%}}}F

%F{{{ sha1...
sha1(Data) -> crypto:sha(Data).

sha1(Data, Offset, Length)
    when is_binary(Data), Offset > 0, Length > 0,
	 size(Data) - (Offset + Length) > 0 ->
    <<_:Offset/binary, Part:Length/binary, _/binary>> =
	Data,
    crypto:sha(Part).
%}}}F

%F{{{ sha1...
sha256(Data) -> crypto:sha256(Data).

sha256(Data, Offset, Length)
    when is_binary(Data), Offset > 0, Length > 0,
	 size(Data) - (Offset + Length) > 0 ->
    <<_:Offset/binary, Part:Length/binary, _/binary>> =
	Data,
    crypto:sha256(Part).
%}}}F

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
% stolen from ssh-1.1.6/src/ssh_dsa.erl, ssh-1.1.6/src/ssh_math.erl
%
dsa_sign(_PrivateKey = [P, Q, G, X], Data) ->
    K = irandom(160) rem Q,
    R = ipow(G, K, P) rem Q,
    Ki = invert(K, Q),
    <<M:160/big-unsigned-integer>> = sha1(Data),
    S = (Ki * (M + X*R)) rem Q,
    {R, S}.

dsa_verify(_PublicKye = [P, Q, G, Y], Data, {R0, S0}) ->
    W = invert(S0, Q),
    <<M0:160/big-unsigned-integer>> = sha1(Data),
    U1 = (M0*W) rem Q,
    U2 = (R0*W) rem Q,
    T1 = ipow(G, U1, P),
    T2 = ipow(Y, U2, P),
    V = ((T1*T2) rem P) rem Q,
    (V == R0).   

irandom(Bits) -> %F{{{
    irandom(Bits, 1, 0).

irandom(0, _Top, _Bottom) -> 
    0;
irandom(Bits, Top, Bottom) ->
    Bytes = (Bits+7) div 8,
    Skip  = (8-(Bits rem 8)) rem 8,
    TMask = case Top of
		  0 -> 0;
		  1 -> 16#80;
		  2 -> 16#c0
	      end,
    BMask = case Bottom of
		0 -> 0;
		1 -> (1 bsl Skip)
	    end,
    <<X:Bits/big-unsigned-integer, _:Skip>> = random(Bytes, TMask, BMask),
    X.

random(N) ->
    random(N, 0, 0).

random(N, TMask, BMask) ->
    list_to_binary(rnd(N, TMask, BMask)).

rnd(0, _TMask, _BMask) ->
    [];
rnd(1, TMask, BMask) ->
    [(rand8() bor TMask) bor BMask];
rnd(N, TMask, BMask) ->
    [(rand8() bor TMask) | rnd_n(N-1, BMask)].

rnd_n(1, BMask) ->
    [rand8() bor BMask];
rnd_n(I, BMask) ->
    [rand8() | rnd_n(I-1, BMask)].

rand8() ->
    (rand32() bsr 8) band 16#ff.

rand32() ->
    random:uniform(16#100000000) -1.

%}}}F

ipow(A, B, M) when M > 0, B >= 0 ->
    crypto:mod_exp(A, B, M).

invert(X,P) when X > 0, P > 0, X < P -> %F{{{
    I = inv(X,P,1,0),
    if 
        I < 0 -> P + I;
        true -> I
    end.

inv(0,_,_,Q) -> Q;
inv(X,P,R1,Q1) ->
    D = P div X,
    inv(P rem X, X, Q1 - D*R1, R1).
%}}}F

%}}}F
