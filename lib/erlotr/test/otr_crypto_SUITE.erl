-module(otr_crypto_SUITE).

-author("Stefan Grundmann <sg2342@googlemail.com>").

-include("AesTestVectors.hrl").

-include("Sha1TestVectors.hrl").

-include("Sha256TestVectors.hrl").

-include("HMACTestVectors.hrl").

-include("DSATestVectors.hrl").

-compile(export_all).

init_per_suite(Config) ->
    case application:start(crypto) of
      ok ->
	  ct:comment("crypto application started"),
	  [{stop_crypto, true} | Config];
      {error, {already_started, crypto}} -> Config
    end.

end_per_suite(Config) ->
    case proplists:lookup(stop_crypto, Config) of
      {stop_crypto, true} ->
	  application:stop(crypto),
	  ct:comment("crypto application stopped");
      _ -> ok
    end,
    Config.

init_per_testcase(_TestCase, Config) -> Config.

end_per_testcase(_TestCase, Config) -> Config.

all() ->
    [aes_ctr_128_1, aes_ctr_128_2, aes_ctr_128_3,
     aes_ctr_128_4, aes_ctr_128_5, aes_ctr_128_6, sha1_1,
     sha1_2, sha1_3, sha256_1, sha256_2, sha256_3,
     sha1HMAC_1, sha1HMAC_2, sha1HMAC_3, sha256HMAC_1,
     sha256HMAC_2, sha256HMAC_3, dsa_verify_1, dsa_verify_2,
     dsa_sign_1, dsa_sign_2, dh_key_exchange].

%F{{{ aes_ctr_128_...

aes_ctr_128_1(_Config) ->
    ct:comment("AES testvector #1 (16 bytes plaintext)"),
    {Key, Nonce, Plaintext, Ciphertext} = (?AESTestVector1),
    Ciphertext = otr_crypto:aes_ctr_128_encrypt(Key, Nonce,
						Plaintext),
    Plaintext = otr_crypto:aes_ctr_128_decrypt(Key, Nonce,
					       Ciphertext),
    ok.

aes_ctr_128_2(_Config) ->
    ct:comment("AES testvector #2 (32 bytes plaintext)"),
    {Key, Nonce, Plaintext, Ciphertext} = (?AESTestVector2),
    Ciphertext = otr_crypto:aes_ctr_128_encrypt(Key, Nonce,
						Plaintext),
    Plaintext = otr_crypto:aes_ctr_128_decrypt(Key, Nonce,
					       Ciphertext),
    ok.

aes_ctr_128_3(_Config) ->
    ct:comment("AES testvector #3 (32 bytes plaintext)"),
    {Key, Nonce, Plaintext, Ciphertext} = (?AESTestVector3),
    Ciphertext = otr_crypto:aes_ctr_128_encrypt(Key, Nonce,
						Plaintext),
    Plaintext = otr_crypto:aes_ctr_128_decrypt(Key, Nonce,
					       Ciphertext),
    ok.

aes_ctr_128_4(_Config) ->
    ct:comment("AES testvector #4 (45 bytes plaintext)"),
    {Key, Nonce, Plaintext, Ciphertext} = (?AESTestVector4),
    Ciphertext = otr_crypto:aes_ctr_128_encrypt(Key, Nonce,
						Plaintext),
    Plaintext = otr_crypto:aes_ctr_128_decrypt(Key, Nonce,
					       Ciphertext),
    ok.

aes_ctr_128_5(_Config) ->
    ct:comment("AES testvector #5 (256 bytes plaintext)"),
    {Key, Nonce, Plaintext, Ciphertext} = (?AESTestVector5),
    Ciphertext = otr_crypto:aes_ctr_128_encrypt(Key, Nonce,
						Plaintext),
    Plaintext = otr_crypto:aes_ctr_128_decrypt(Key, Nonce,
					       Ciphertext),
    ok.

aes_ctr_128_6(_Config) ->
    ct:comment("AES testvector #6 (1024 bytes plaintext)"),
    {Key, Nonce, Plaintext, Ciphertext} = (?AESTestVector6),
    Ciphertext = otr_crypto:aes_ctr_128_encrypt(Key, Nonce,
						Plaintext),
    Plaintext = otr_crypto:aes_ctr_128_decrypt(Key, Nonce,
					       Ciphertext),
    ok.

%}}}F

%F{{{ sha1...

sha1_1(_Config) ->
    ct:comment("SHA1 testvector #1 (61 bytes message)"),
    {Msg, MD} = (?SHA1TestVector1),
    MD = otr_crypto:sha1(Msg),
    ok.

sha1_2(_Config) ->
    ct:comment("SHA1 testvector #2 (559 bytes message)"),
    {Msg, MD} = (?SHA1TestVector2),
    MD = otr_crypto:sha1(Msg),
    ok.

sha1_3(_Config) ->
    ct:comment("SHA1 testvector #3 (95 bytes message, "
	       "offset 22, lenght 52)"),
    {Offset, Length, Msg, MD} = (?SHA1TestVector3),
    MD = otr_crypto:sha1(Msg, Offset, Length),
    ok.

%}}}F

%F{{{ sha256...

sha256_1(_Config) ->
    ct:comment("SHA256 testvector #1 ( 35 bytes message)"),
    {Msg, MD} = (?SHA256TestVector1),
    MD = otr_crypto:sha256(Msg),
    ok.

sha256_2(_Config) ->
    ct:comment("SHA256 testvector #2 ( 460 bytes message)"),
    {Msg, MD} = (?SHA256TestVector2),
    MD = otr_crypto:sha256(Msg),
    ok.

sha256_3(_Config) ->
    ct:comment("SHA256 testvector #3 (  146 bytes message, "
	       "offset 26, lenght 64)"),
    {Offset, Length, Msg, MD} = (?SHA256TestVector3),
    MD = otr_crypto:sha256(Msg, Offset, Length),
    ok.

%}}}F

%F{{{ ...HMAC...
sha1HMAC_1(_Config) ->
    ct:comment("Sha1HMAC testvector #1 (Klen = 8, Tlen "
	       "= 10)"),
    {Key, Data, Mac} = (?HMACTestVector1),
    SzMac = size(Mac),
    <<Mac:SzMac/binary, _/binary>> =
	otr_crypto:sha1HMAC(Key, Data),
    ok.

sha1HMAC_2(_Config) ->
    ct:comment("Sha1HMAC testvector #2 (Klen = 128, "
	       "Tlen = 12)"),
    {Key, Data, Mac} = (?HMACTestVector2),
    SzMac = size(Mac),
    <<Mac:SzMac/binary, _/binary>> =
	otr_crypto:sha1HMAC(Key, Data),
    ok.

sha1HMAC_3(_Config) ->
    ct:comment("Sha1HMAC testvector #3 (Klen = 25  ,Tlen "
	       "= 12)"),
    {Key, Data, Mac} = (?HMACTestVector3),
    SzMac = size(Mac),
    <<Mac:SzMac/binary, _/binary>> =
	otr_crypto:sha1HMAC(Key, Data),
    ok.

sha256HMAC_1(_Config) ->
    ct:comment("Sha256HMAC testvector #1 (Klen = 8, "
	       "Tlen = 16)"),
    {Key, Data, Mac} = (?HMACTestVector4),
    SzMac = size(Mac),
    <<Mac:SzMac/binary, _/binary>> =
	otr_crypto:sha256HMAC(Key, Data),
    ok.

sha256HMAC_2(_Config) ->
    ct:comment("Sha256HMAC testvector #2 (Klen = 400, "
	       "Tlen = 24)"),
    {Key, Data, Mac} = (?HMACTestVector5),
    SzMac = size(Mac),
    <<Mac:SzMac/binary, _/binary>> =
	otr_crypto:sha256HMAC(Key, Data),
    ok.

sha256HMAC_3(_Config) ->
    ct:comment("Sha256HMAC testvector #3 (Klen = 64, "
	       "Tlen = 16)"),
    {Key, Data, Mac} = (?HMACTestVector6),
    SzMac = size(Mac),
    <<Mac:SzMac/binary, _/binary>> =
	otr_crypto:sha256HMAC(Key, Data),
    ok.

%}}}F

%F{{{  dsa...
dsa_verify_1(_Config) ->
    ct:comment("DSA Verify testvector #1"),
    {[P, Q, G, _, Y], Data, Signature, Result} =
	(?DSATestVector1),
    Result = otr_crypto:dsa_verify([P, Q, G, Y],
				   otr_crypto:sha1(Data), Signature),
    ok.

dsa_verify_2(_Config) ->
    ct:comment("DSA Verify testvector #2"),
    {[P, Q, G, _, Y], Data, Signature, Result} =
	(?DSATestVector1),
    Result = otr_crypto:dsa_verify([P, Q, G, Y],
				   otr_crypto:sha1(Data), Signature),
    ok.

dsa_sign_1(_Config) ->
    ct:comment("DSA Sign random data, keys from testvector #1"),
    {[P, Q, G, X, Y], _, _, _} = (?DSATestVector1),
    Data = crypto:rand_bytes(1024),
    {R, S} = otr_crypto:dsa_sign([P, Q, G, X, Y], Data),
    true = otr_crypto:dsa_verify([P, Q, G, Y], Data,
				 {R, S}).

dsa_sign_2(_Config) ->
    ct:comment("DSA Sign random data, keys from testvector #2"),
    {[P, Q, G, X, Y], _, _, _} = (?DSATestVector2),
    Data = crypto:rand_bytes(512),
    {R, S} = otr_crypto:dsa_sign([P, Q, G, X], Data),
    true = otr_crypto:dsa_verify([P, Q, G, Y], Data,
				 {R, S}).

%}}}F

%F{{{ dh_key_exchange
dh_key_exchange(_Config) ->
    ct:comment("Diffie Hellman key exchange"),
    {PrivAlice, PubAlice} = otr_crypto:dh_gen_key(),
    {PrivBob, PubBob} = otr_crypto:dh_gen_key(),
    SharedSecret = otr_crypto:dh_agree(PrivAlice, PubBob),
    SharedSecret = otr_crypto:dh_agree(PrivBob, PubAlice),
    ok.%}}}F

