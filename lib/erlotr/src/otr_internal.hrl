-define (TYPE_DH_COMMIT, 16#02).
-define (TYPE_DH_KEY, 16#0A).
-define (TYPE_REVEAL_SIGNATURE, 16#11).
-define (TYPE_SIGNATURE, 16#12).
-define (TYPE_DATA, 16#03).

-record(otr_msg_fragment, {k = 0, n = 0, f = []}).
-record(otr_msg_error, {s}).
-record(otr_msg_tagged_ws, {s}).

-record(otr_msg_dh_commit, {enc_gx, hash_gx}).
-record(otr_msg_dh_key, {gy}).
-record(otr_msg_reveal_signature, {r, enc_sig, mac}).
-record(otr_msg_signature, {enc_sig, mac}).
-record(otr_msg_data, {flags, sender_keyid, recipient_keyid, 
		       dhy, ctr_init, enc_data, mac, old_mac_keys}).

-define(ERR_MSG_UNEXPECTED, " You sent unexpected encrypted data to us").
-define(ERR_MSG_NOT_IN_PRIVATE, " You sent an encrypted message, "
        "but we finished the private conversation").
-define(ERR_MSG_MALFORMED, " You transmitted a malformed data message").
-define(ERR_MSG_UNREADABLE, " You transmitted an unreadable "
        "encrypted message.").

-define(DEFAULT_MAX_FRAG_SIZE, 1024).

-define(DH_MODULUS, 
16#FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF).
