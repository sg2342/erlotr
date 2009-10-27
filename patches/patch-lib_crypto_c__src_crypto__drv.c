--- lib/crypto/c_src/crypto_drv.c.orig	2009-03-12 13:28:59.000000000 +0100
+++ lib/crypto/c_src/crypto_drv.c	2009-09-22 15:41:41.461798087 +0200
@@ -197,7 +197,7 @@
 #define DRV_MD4_UPDATE          49
 #define DRV_MD4_FINAL           50
 
-#define SSL_VERSION_0_9_8 0
+#define SSL_VERSION_0_9_8 1
 #if SSL_VERSION_0_9_8
 #define DRV_SHA256              51
 #define DRV_SHA256_INIT         52
@@ -1457,7 +1457,7 @@
        if (len != SHA512_CTX_LEN)
 	  return -1;
        memcpy(&sha512_ctx, buf, SHA512_CTX_LEN); /* XXX Use buf only? */
-       bin = return_binary(rbuf,rlen,SHA512_LEN));
+       bin = return_binary(rbuf,rlen,SHA512_LEN);
        SHA512_Final(bin, &sha512_ctx);
        return SHA512_LEN;		
 #endif
