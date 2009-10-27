-module(otr_crypto_SUITE).

-author("Stefan Grundmann <sg2342@googlemail.com>").

-include("AesTestVectors.hrl").

-include("Sha1TestVectors.hrl").

-include("Sha256TestVectors.hrl").

-compile(export_all).


init_per_suite(Config) -> 
    case application:start(crypto) of
	ok ->
	    ct:comment("crypto application started"),
	    [{stop_crypto, true} |Config];
	{error, {already_started, crypto}} -> Config
    end.

end_per_suite(Config) -> 
    case proplists:lookup(stop_crypto, Config) of
	{stop_crypto, true} -> application:stop(crypto),
	    ct:comment("crypto application stopped");
	_ -> ok
    end, Config.

init_per_testcase(_TestCase, Config) -> Config.

end_per_testcase(_TestCase, Config) -> Config.


all() -> [aes_ctr_128_1, aes_ctr_128_2, aes_ctr_128_3, 
	  aes_ctr_128_4, aes_ctr_128_5, aes_ctr_128_6, 
	  sha1_1, sha1_2, sha1_3, sha256_1, sha256_2, 
	  sha256_3].

%F{{{ aes_ctr_128_...

aes_ctr_128_1(_Config) -> 
    ct:comment("AES testvector #1 (16 bytes plaintext)"),
    {Key, Nonce, Plaintext, Ciphertext} = ?AESTestVector1,
    Ciphertext = otr_crypto:aes_ctr_128_encrypt(Key, Nonce, Plaintext),
    Plaintext = otr_crypto:aes_ctr_128_decrypt(Key, Nonce, Ciphertext), ok.

aes_ctr_128_2(_Config) -> 
    ct:comment("AES testvector #2 (32 bytes plaintext)"),
    {Key, Nonce, Plaintext, Ciphertext} = ?AESTestVector2,
    Ciphertext = otr_crypto:aes_ctr_128_encrypt(Key, Nonce, Plaintext),
    Plaintext = otr_crypto:aes_ctr_128_decrypt(Key, Nonce, Ciphertext), ok.

aes_ctr_128_3(_Config) -> 
    ct:comment("AES testvector #3 (32 bytes plaintext)"),
    {Key, Nonce, Plaintext, Ciphertext} = ?AESTestVector3,
    Ciphertext = otr_crypto:aes_ctr_128_encrypt(Key, Nonce, Plaintext),
    Plaintext = otr_crypto:aes_ctr_128_decrypt(Key, Nonce, Ciphertext), ok.

aes_ctr_128_4(_Config) -> 
    ct:comment("AES testvector #4 (45 bytes plaintext)"),
    {Key, Nonce, Plaintext, Ciphertext} = ?AESTestVector4,
    Ciphertext = otr_crypto:aes_ctr_128_encrypt(Key, Nonce, Plaintext),
    Plaintext = otr_crypto:aes_ctr_128_decrypt(Key, Nonce, Ciphertext), ok.

aes_ctr_128_5(_Config) -> 
    ct:comment("AES testvector #5 (256 bytes plaintext)"),
    {Key, Nonce, Plaintext, Ciphertext} = ?AESTestVector5,
    Ciphertext = otr_crypto:aes_ctr_128_encrypt(Key, Nonce, Plaintext),
    Plaintext = otr_crypto:aes_ctr_128_decrypt(Key, Nonce, Ciphertext), ok.

aes_ctr_128_6(_Config) -> 
    ct:comment("AES testvector #6 (1024 bytes plaintext)"),
    {Key, Nonce, Plaintext, Ciphertext} = ?AESTestVector6,
    Ciphertext = otr_crypto:aes_ctr_128_encrypt(Key, Nonce, Plaintext),
    Plaintext = otr_crypto:aes_ctr_128_decrypt(Key, Nonce, Ciphertext), ok.

%}}}F

%F{{{ sha1...

sha1_1(_Config) ->
    ct:comment("SHA1 testvector #1 (61 bytes message)"),
    {Msg, MD} = ?SHA1TestVector1,
    MD = otr_crypto:sha1(Msg), ok.

sha1_2(_Config) ->
    ct:comment("SHA1 testvector #2 (559 bytes message)"),
    {Msg, MD} = ?SHA1TestVector2,
    MD = otr_crypto:sha1(Msg), ok.

sha1_3(_Config) ->
    ct:comment("SHA1 testvector #3 (95 bytes message, offset 22, lenght 52)"),
    {Offset, Length, Msg, MD} = ?SHA1TestVector3,
    MD = otr_crypto:sha1(Msg, Offset, Length), ok.

%}}}F

%F{{{ sha256...

sha256_1(_Config) ->
    ct:comment("SHA256 testvector #1 ( 35 bytes message)"),
    {Msg, MD} = ?SHA256TestVector1,
    MD = otr_crypto:sha256(Msg), ok.

sha256_2(_Config) ->
    ct:comment("SHA256 testvector #2 ( 460 bytes message)"),
    {Msg, MD} = ?SHA256TestVector2,
    MD = otr_crypto:sha256(Msg), ok.

sha256_3(_Config) ->
    ct:comment("SHA256 testvector #3 (  146 bytes message, offset 26, lenght 64)"),
    {Offset, Length, Msg, MD} = ?SHA256TestVector3,
    MD = otr_crypto:sha256(Msg, Offset, Length), ok.

%}}}F
