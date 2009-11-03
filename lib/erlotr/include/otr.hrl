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


-define(OTRL_ERRCODE_MSG_NOT_IN_PRIVATE, "You sent sn encrypted message, "
        "but we finished th private conversation").
