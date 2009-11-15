%{import, ["log/cover.db"]}.
%{export, ["log/cover.db"]}.
{incl_mods, [otr_message, 
             otr_crypto, 
             otr_util, 
             otr_parser_fsm, 
             otr_fsm, 
             otr_ake_fsm,
             otr_app,
             otr,
             otr_sup,
             otr_ctx_sup,
			 otr_tlv,
			 otr_mcgs]}.
