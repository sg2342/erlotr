-record(otr_msg, {type, value}).

-record(otr_msg_dh_commit, {enc_gx, mac_gx}).

-record(otr_msg_dh_key, {mpi_gy}).

-record(otr_msg_reveal_signature, {revealed_key, 
				   enc_sig, 
				   mac_enc_sig}).

-record(otr_msg_signature, {enc_sig, mac_enc_sig}).

-record(otr_msg_data, {flags,
		       sender_keyid,
		       recipient_keyid,
		       mpi_dhy,
		       ctr_init,
		       enc_data,
		       mac,
		       old_mac_keys}).

-record(otr_fragment, {k = 0, n = 0, f = <<>>}).
