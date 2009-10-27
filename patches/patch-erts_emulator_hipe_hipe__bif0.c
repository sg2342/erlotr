--- erts/emulator/hipe/hipe_bif0.c.orig	2009-09-22 14:55:46.147702301 +0200
+++ erts/emulator/hipe/hipe_bif0.c	2009-09-22 14:56:11.657728017 +0200
@@ -441,7 +441,7 @@
 	BIF_ERROR(BIF_P, BADARG);
     nrbytes = unsigned_val(BIF_ARG_2);
     block = erts_alloc(ERTS_ALC_T_HIPE, nrbytes);
-    if ((unsigned long)block & (align-1))
+    if (nrbytes && ((unsigned long)block & (align-1)))
 	fprintf(stderr, "Yikes! erts_alloc() returned misaligned address %p\r\n", block);
     BIF_RET(address_to_term(block, BIF_P));
 }
