--- lib/crypto/src/crypto.erl.orig	2009-09-22 14:59:04.071307396 +0200
+++ lib/crypto/src/crypto.erl	2009-09-22 15:00:43.607850728 +0200
@@ -25,8 +25,8 @@
 -export([md4/1, md4_init/0, md4_update/2, md4_final/1]).
 -export([md5/1, md5_init/0, md5_update/2, md5_final/1]).
 -export([sha/1, sha_init/0, sha_update/2, sha_final/1]).
-%-export([sha256/1, sha256_init/0, sha256_update/2, sha256_final/1]).
-%-export([sha512/1, sha512_init/0, sha512_update/2, sha512_final/1]).
+-export([sha256/1, sha256_init/0, sha256_update/2, sha256_final/1]).
+-export([sha512/1, sha512_init/0, sha512_update/2, sha512_final/1]).
 -export([md5_mac/2, md5_mac_96/2, sha_mac/2, sha_mac_96/2]).
 -export([des_cbc_encrypt/3, des_cbc_decrypt/3, des_cbc_ivec/1]).
 -export([des3_cbc_encrypt/5, des3_cbc_decrypt/5]).
@@ -102,14 +102,14 @@
 -define(MD4_UPDATE,	 49).
 -define(MD4_FINAL,	 50).
 
-%% -define(SHA256,		 51).
-%% -define(SHA256_INIT,	 52).
-%% -define(SHA256_UPDATE,	 53).
-%% -define(SHA256_FINAL,	 54).
-%% -define(SHA512,		 55).
-%% -define(SHA512_INIT,	 56).
-%% -define(SHA512_UPDATE,	 57).
-%% -define(SHA512_FINAL,	 58).
+-define(SHA256,		 51).
+-define(SHA256_INIT,	 52).
+-define(SHA256_UPDATE,	 53).
+-define(SHA256_FINAL,	 54).
+-define(SHA512,		 55).
+-define(SHA512_INIT,	 56).
+-define(SHA512_UPDATE,	 57).
+-define(SHA512_FINAL,	 58).
 
 
 %% -define(IDEA_CBC_ENCRYPT, 34).
@@ -118,8 +118,8 @@
 -define(FUNC_LIST, [md4, md4_init, md4_update, md4_final,
 		    md5, md5_init, md5_update, md5_final,
 		    sha, sha_init, sha_update, sha_final,
-%% 		    sha256, sha256_init, sha256_update, sha256_final,
-%% 		    sha512, sha512_init, sha512_update, sha512_final,
+ 		    sha256, sha256_init, sha256_update, sha256_final,
+ 		    sha512, sha512_init, sha512_update, sha512_final,
 		    md5_mac,  md5_mac_96,
 		    sha_mac,  sha_mac_96,
 		    des_cbc_encrypt, des_cbc_decrypt,
@@ -211,29 +211,29 @@
 
 %% sha256 and sha512 requires openssl-0.9.8 removed for now
 
-%% sha256(Data) ->
-%%     control(?SHA256, Data).
+sha256(Data) ->
+    control(?SHA256, Data).
 
-%% sha256_init() ->
-%%     control(?SHA256_INIT, []).
+sha256_init() ->
+    control(?SHA256_INIT, []).
 
-%% sha256_update(Context, Data) ->
-%%     control(?SHA256_UPDATE, [Context, Data]).
+sha256_update(Context, Data) ->
+    control(?SHA256_UPDATE, [Context, Data]).
 
-%% sha256_final(Context) ->
-%%         control(?SHA256_FINAL, Context).
+sha256_final(Context) ->
+        control(?SHA256_FINAL, Context).
 
-%% sha512(Data) ->
-%%     control(?SHA512, Data).
+sha512(Data) ->
+    control(?SHA512, Data).
 
-%% sha512_init() ->
-%%     control(?SHA512_INIT, []).
+sha512_init() ->
+    control(?SHA512_INIT, []).
 
-%% sha512_update(Context, Data) ->
-%%     control(?SHA512_UPDATE, [Context, Data]).
+sha512_update(Context, Data) ->
+    control(?SHA512_UPDATE, [Context, Data]).
 
-%% sha512_final(Context) ->
-%%     control(?SHA512_FINAL, Context).
+sha512_final(Context) ->
+    control(?SHA512_FINAL, Context).
 
 %%
 %%  MESSAGE AUTHENTICATION CODES
