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

-export([aes_ctr_128_decrypt/3, aes_ctr_128_encrypt/3]).

-export([dh_agree/2, dh_gen_key/0]).

-export([dsa_sign/2, dsa_verify/3]).

-export([sha1/1, sha1/3, sha1HMAC/2, sha256/1, sha256/3,
	 sha256HMAC/2]).

-export([mod/2, mod_exp/3, mod_inv/2]).

-export([rand_bytes/1, rand_int/1]).

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
    K = mod(rand_int(20), Q),
    R = mod(mod_exp(G, K, P), Q),
    Ki = mod_inv(K, Q),
    BS = size(Data) bsl 3,
    <<M:BS/big-unsigned-integer>> = Data,
    S = mod(Ki * (M + X * R), Q),
    {R, S}.

dsa_verify(_PublicKey = [P, Q, G, Y], Data, {R0, S0}) ->
    W = mod_inv(S0, Q),
    BS = size(Data) bsl 3,
    <<M0:BS/big-unsigned-integer>> = Data,
    U1 = M0 * W rem Q,
    U2 = R0 * W rem Q,
    T1 = mod_exp(G, U1, P),
    T2 = mod_exp(Y, U2, P),
    V = T1 * T2 rem P rem Q,
    V == R0.

%}}}F

%F{{{ dh_gen_key/0, dh_agree/2

dh_gen_key() ->
    P = (?DH_MODULUS),
    Private = crypto:erlint(<<320:32,
			      (crypto:rand_bytes(320))/binary>>),
    Public = mod_exp(2, Private, P),
    if (Public >= 2) and (Public =< (?DH_MODULUS) - 2) ->
	   {Private, Public};
       true -> dh_gen_key()
    end.

dh_agree(Private, PeerPub) ->
    mod_exp(PeerPub, Private, ?DH_MODULUS).

%}}}F

mod(X, P) when X >= 0 -> X rem P;
mod(X, P) when X < 0 -> P + X rem P.

rand_int(Nb) ->
    otr_util:erlint(<<Nb:32, (rand_bytes(Nb))/binary>>).

rand_bytes(Nb) -> crypto:rand_bytes(Nb).

% stolen from ssh-1.1.6/src/ssh_math.erl
mod_exp(A, B, M) when M > 0, B >= 0 ->
    crypto:mod_exp(A, B, M).

mod_inv(X, P) when X > 0, P > 0, X < P ->
    I = inv(X, P, 1, 0),
    if I < 0 -> P + I;
       true -> I
    end.

inv(0, _, _, Q) -> Q;
inv(X, P, R1, Q1) ->
    D = P div X, inv(P rem X, X, Q1 - D * R1, R1).
