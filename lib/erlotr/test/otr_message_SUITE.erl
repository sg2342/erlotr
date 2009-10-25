-module(otr_message_SUITE).

-compile(export_all).

-include_lib("erlotr/include/otr_message.hrl").

init_per_suite(Config) -> Config.

end_per_suite(Config) -> Config.

init_per_testcase(_TestCase, Config) -> Config.

end_per_testcase(_TestCase, Config) -> Config.

all() ->
    [decode_plain, decode_query_v1, decode_query_v2,
     decode_query_v1_or_v2, decode_error, decode_dh_commit,
     decode_dh_key, decode_reveal_signature,
     decode_signature, decode_data_1, decode_data_2,
     encode_query, encode_error, encode_dh_commit,
     encode_dh_key, encode_reveal_signature,
     encode_signature, encode_data_1, encode_data_2].

%F{{{ decode_...

decode_plain(_Config) -> %F{{{
    {ok, #otr_msg{type = plain}} =
	otr_message:decode(<<"foo">>). %}}}F

decode_query_v1(_Config) -> %F{{{
    R = {ok, #otr_msg{type = query_v1}},
    R = otr_message:decode(<<"?OTR?">>),
    R = otr_message:decode(<<"?OTR?v">>),
    R = otr_message:decode(<<"?OTR?v34567?">>). %}}}F

decode_query_v2(_Config) -> %F{{{
    R = {ok, #otr_msg{type = query_v2}},
    R = otr_message:decode(<<"?OTRv2?">>),
    R = otr_message:decode(<<"?OTRv45672?">>). %}}}F

decode_query_v1_or_v2(_Config) -> %F{{{
    R = {ok, #otr_msg{type = query_v1_or_v2}},
    R = otr_message:decode(<<"?OTR?v2?">>),
    R = otr_message:decode(<<"?OTR?v34586792?">>),
    R = otr_message:decode(<<"?OTR?v34525534?">>). %}}}F

decode_error(_Config) -> %F{{{
    ErrorMsg = "some error message",
    M = erlang:concat_binary([<<"?OTR Error:">>,
			      erlang:list_to_binary(ErrorMsg)]),
    R = {ok, #otr_msg{type = error, value = ErrorMsg}},
    R = otr_message:decode(M). %}}}F

decode_dh_commit(_Config) -> %F{{{
    M = <<"?OTR:AAICAAAAxCwNbeDb5N6sHCjimu6LwWDUcNalKWnf"
	  "1QR0B2iCT/WchV4lywHavNWmmT1KAvyogIeYZPv+pFg4S"
	  "FBazbrGgpMoC7YFr8kJskrHSdy4d9UnttYV3+1UGenXgl"
	  "2ECfyOwj7V/G2QwiPunLtLuFz94rk7jhMbNuZf4WY0r12"
	  "Nw/QeYbTRt2rRk+XTKv/wiWyq9zxfofhqsrP3UW+koMYb"
	  "iDQmawgB/qzKn6BAWrar2heFYPdFUDnvRlIGwdDgI2EG9"
	  "nfbRqwAAAAgf5bMB4oYtPAqDPD+eyTujEw7fXKmQz3Gcl"
	  "wYFdlrVmk=.">>,
    EncGx = <<44, 13, 109, 224, 219, 228, 222, 172, 28, 40,
	      226, 154, 238, 139, 193, 96, 212, 112, 214, 165, 41,
	      105, 223, 213, 4, 116, 7, 104, 130, 79, 245, 156, 133,
	      94, 37, 203, 1, 218, 188, 213, 166, 153, 61, 74, 2, 252,
	      168, 128, 135, 152, 100, 251, 254, 164, 88, 56, 72, 80,
	      90, 205, 186, 198, 130, 147, 40, 11, 182, 5, 175, 201,
	      9, 178, 74, 199, 73, 220, 184, 119, 213, 39, 182, 214,
	      21, 223, 237, 84, 25, 233, 215, 130, 93, 132, 9, 252,
	      142, 194, 62, 213, 252, 109, 144, 194, 35, 238, 156,
	      187, 75, 184, 92, 253, 226, 185, 59, 142, 19, 27, 54,
	      230, 95, 225, 102, 52, 175, 93, 141, 195, 244, 30, 97,
	      180, 209, 183, 106, 209, 147, 229, 211, 42, 255, 240,
	      137, 108, 170, 247, 60, 95, 161, 248, 106, 178, 179,
	      247, 81, 111, 164, 160, 198, 27, 136, 52, 38, 107, 8, 1,
	      254, 172, 202, 159, 160, 64, 90, 182, 171, 218, 23, 133,
	      96, 247, 69, 80, 57, 239, 70, 82, 6, 193, 208, 224, 35,
	      97, 6, 246, 119, 219, 70, 172>>,
    MacGx = <<127, 150, 204, 7, 138, 24, 180, 240, 42, 12,
	      240, 254, 123, 36, 238, 140, 76, 59, 125, 114, 166, 67,
	      61, 198, 114, 92, 24, 21, 217, 107, 86, 105>>,
    R = {ok,
	 #otr_msg{type = dh_commit,
		  value =
		      #otr_msg_dh_commit{enc_gx = EncGx, mac_gx = MacGx}}},
    R = otr_message:decode(M). %}}}F

decode_dh_key(_Config) -> %F{{{
    M = <<"?OTR:AAIKAAAAwBlpxOqNOmK6dPYVxiO7IWs+V7YKHJ+B"
	  "kzThBOKapZKJU4YhfGZbq/+BbWB+vW1wDBLt19LAv2E1s"
	  "kifRU8CLSlCzESbTlrnF/rk4cKj6NmAiaB7EDXV/L5bjX"
	  "4hDvshAY3hQaj/2QJ85Sq7u9MIObCfhCS3vMbA4DrrV99"
	  "hzGy6ogPhspoKiuvMrTPaKbfGVFlKeAQTniTQT5EvxNTY"
	  "z5XX2qa64WjlfK1UUSzNqNQdl+QO20NSyNKWm6cCp5epM"
	  "Q==.">>,
    MpiGy = <<25, 105, 196, 234, 141, 58, 98, 186, 116, 246,
	      21, 198, 35, 187, 33, 107, 62, 87, 182, 10, 28, 159,
	      129, 147, 52, 225, 4, 226, 154, 165, 146, 137, 83, 134,
	      33, 124, 102, 91, 171, 255, 129, 109, 96, 126, 189, 109,
	      112, 12, 18, 237, 215, 210, 192, 191, 97, 53, 178, 72,
	      159, 69, 79, 2, 45, 41, 66, 204, 68, 155, 78, 90, 231,
	      23, 250, 228, 225, 194, 163, 232, 217, 128, 137, 160,
	      123, 16, 53, 213, 252, 190, 91, 141, 126, 33, 14, 251,
	      33, 1, 141, 225, 65, 168, 255, 217, 2, 124, 229, 42,
	      187, 187, 211, 8, 57, 176, 159, 132, 36, 183, 188, 198,
	      192, 224, 58, 235, 87, 223, 97, 204, 108, 186, 162, 3,
	      225, 178, 154, 10, 138, 235, 204, 173, 51, 218, 41, 183,
	      198, 84, 89, 74, 120, 4, 19, 158, 36, 208, 79, 145, 47,
	      196, 212, 216, 207, 149, 215, 218, 166, 186, 225, 104,
	      229, 124, 173, 84, 81, 44, 205, 168, 212, 29, 151, 228,
	      14, 219, 67, 82, 200, 210, 150, 155, 167, 2, 167, 151,
	      169, 49>>,
    R = {ok,
	 #otr_msg{type = dh_key,
		  value = #otr_msg_dh_key{mpi_gy = MpiGy}}},
    R = otr_message:decode(M). %}}}F

decode_reveal_signature(_Config) -> %F{{{
    M = <<"?OTR:AAIRAAAAEOgmDPnVX65cXR6XKmnqf18AAAHSrBnG"
	  "I8WgWW0WfP2+O3kdWPRN3VbTzFiipWGyfqK7EBULIzj5c"
	  "g39gixRTEu0YHfr4haGhA4ngc0vyRsxiViCXy/o1lRd7X"
	  "e2zSRhwTTd46r9vXV/KJQHLPVQNyxJZMWLzuacExfCkDn"
	  "CZUflwtY0dPqs5aO450aZkpp65o4QpvXlOk7xxbJIac4i"
	  "AUfd1UEn96Lt024i6gbPpYm1+cuE0v/R1j/6vvhaJ73tW"
	  "AkRF1KixXNZlA2xg59FC/6JdAuCNPp/EHCwicTPyw3BDh"
	  "VVvOqIwFfJxrHEz5ixcLtwI2sd3X/eiy5mSUu75j2XjXf"
	  "8wEEMorYmOFEth948r65ruRdmn0BjFOxBvETgn7LULdJh"
	  "QQDfjriRt+vg2Grbn+Z5HiJFU2vLd2yib8FGKvg1bnOnV"
	  "oO2L2eB/4t5y7WIJUjJVHOawAsnw6pVNHq14b9E4Nbn/5"
	  "h9kYv3svrJWE0WXDdlJDLUGMwRYqsoK/8tKfdH2Ic6wMk"
	  "DWFbC/LFumCIHt+Tx3gHyseu4d4LnHzJg4+h0Kl0j0fCM"
	  "zb9DNRuUVwIxXmDkY7yRsUhKyHkuUhr/h5j/YAsJlflpG"
	  "m8A7FoNCpywk788r8RIj/n9PoSlDX7NFH+X+/QafaOONi"
	  "6t2sMWqRhZ+hLS.">>,
    RevKey = <<232, 38, 12, 249, 213, 95, 174, 92, 93, 30,
	       151, 42, 105, 234, 127, 95>>,
    EncSig = <<172, 25, 198, 35, 197, 160, 89, 109, 22, 124,
	       253, 190, 59, 121, 29, 88, 244, 77, 221, 86, 211, 204,
	       88, 162, 165, 97, 178, 126, 162, 187, 16, 21, 11, 35,
	       56, 249, 114, 13, 253, 130, 44, 81, 76, 75, 180, 96,
	       119, 235, 226, 22, 134, 132, 14, 39, 129, 205, 47, 201,
	       27, 49, 137, 88, 130, 95, 47, 232, 214, 84, 93, 237,
	       119, 182, 205, 36, 97, 193, 52, 221, 227, 170, 253, 189,
	       117, 127, 40, 148, 7, 44, 245, 80, 55, 44, 73, 100, 197,
	       139, 206, 230, 156, 19, 23, 194, 144, 57, 194, 101, 71,
	       229, 194, 214, 52, 116, 250, 172, 229, 163, 184, 231,
	       70, 153, 146, 154, 122, 230, 142, 16, 166, 245, 229, 58,
	       78, 241, 197, 178, 72, 105, 206, 34, 1, 71, 221, 213,
	       65, 39, 247, 162, 237, 211, 110, 34, 234, 6, 207, 165,
	       137, 181, 249, 203, 132, 210, 255, 209, 214, 63, 250,
	       190, 248, 90, 39, 189, 237, 88, 9, 17, 23, 82, 162, 197,
	       115, 89, 148, 13, 177, 131, 159, 69, 11, 254, 137, 116,
	       11, 130, 52, 250, 127, 16, 112, 176, 137, 196, 207, 203,
	       13, 193, 14, 21, 85, 188, 234, 136, 192, 87, 201, 198,
	       177, 196, 207, 152, 177, 112, 187, 112, 35, 107, 29,
	       221, 127, 222, 139, 46, 102, 73, 75, 187, 230, 61, 151,
	       141, 119, 252, 192, 65, 12, 162, 182, 38, 56, 81, 45,
	       135, 222, 60, 175, 174, 107, 185, 23, 102, 159, 64, 99,
	       20, 236, 65, 188, 68, 224, 159, 178, 212, 45, 210, 97,
	       65, 0, 223, 142, 184, 145, 183, 235, 224, 216, 106, 219,
	       159, 230, 121, 30, 34, 69, 83, 107, 203, 119, 108, 162,
	       111, 193, 70, 42, 248, 53, 110, 115, 167, 86, 131, 182,
	       47, 103, 129, 255, 139, 121, 203, 181, 136, 37, 72, 201,
	       84, 115, 154, 192, 11, 39, 195, 170, 85, 52, 122, 181,
	       225, 191, 68, 224, 214, 231, 255, 152, 125, 145, 139,
	       247, 178, 250, 201, 88, 77, 22, 92, 55, 101, 36, 50,
	       212, 24, 204, 17, 98, 171, 40, 43, 255, 45, 41, 247, 71,
	       216, 135, 58, 192, 201, 3, 88, 86, 194, 252, 177, 110,
	       152, 34, 7, 183, 228, 241, 222, 1, 242, 177, 235, 184,
	       119, 130, 231, 31, 50, 96, 227, 232, 116, 42, 93, 35,
	       209, 240, 140, 205, 191, 67, 53, 27, 148, 87, 2, 49, 94,
	       96, 228, 99, 188, 145, 177, 72, 74, 200, 121, 46, 82,
	       26, 255, 135, 152, 255, 96, 11, 9, 149, 249, 105, 26,
	       111, 0, 236, 90, 13, 10, 156, 176, 147, 191, 60, 175,
	       196, 72, 143, 249, 253, 62, 132, 165, 13, 126, 205,
	       20>>,
    MacEncSig = <<127, 151, 251, 244, 26, 125, 163, 142, 54,
		  46, 173, 218, 195, 22, 169, 24, 89, 250, 18, 210>>,
    R = {ok,
	 #otr_msg{type = reveal_signature,
		  value =
		      #otr_msg_reveal_signature{revealed_key = RevKey,
						enc_sig = EncSig,
						mac_enc_sig = MacEncSig}}},
    R = otr_message:decode(M).  %}}}F

decode_signature(_Config) -> %F{{{
    M = <<"?OTR:AAISAAAB0n3kDM4JfUWOnSwxHjqmli+gpHt+ePIO"
	  "e3JFys7tuJ5ydfoQbIpAB12ItXx5WaN8WtJnGT9tEXm2S"
	  "ERhu1ymXcL4mCiO2fPPapSMUDOJvqu2oCANMWJCF7dvAC"
	  "Yuh1RyAoHd19SCjxk8jQDzXD2HNXXgitxTvLyi/F8ci0H"
	  "zM5rQADBlE4kpU6Wajdmqp9drAG9nlr6drLXa4OMDf1Tt"
	  "hiFqekdtgCc3X9u3/S0MdQ4n/2WtdHdICKlUP2HmDOKQ8"
	  "F2/RdhlVn/0db6wng78rupICL8KSII6lyQ4ke5AD0tlEF"
	  "Mfe2/K0T2IEv0Ct24UzEXN+j6caHNgT0vPz2IfM31wRay"
	  "ci0XBVjCeCPXtBOkr49i7jduqcTzf4wp8iOslf8JuKJH5"
	  "Y4N45eZugyDE8LBvh1LghtBSssn9oi+2JokDD89w3Lcup"
	  "79ZZrEm3qeEsmIQxtjc9SvYKYt18u/xj64JiObvhFIBPr"
	  "WKPLkEy/rJZisTGc3E17aixmHP1nj9sWLa7QWuupWmERS"
	  "dH9N4Obk+fTTtEqAYogmAPIqdDaunDqOGfx2qTvoLzsWD"
	  "0vfanX0iBYKhTAxo2qibb+O2z1AUioqJvQYElExkvYNOH"
	  "QPPxNo+QT0LTTQREOvgXGCnLzHLN71piA==.">>,
    EncSig = <<125, 228, 12, 206, 9, 125, 69, 142, 157, 44,
	       49, 30, 58, 166, 150, 47, 160, 164, 123, 126, 120, 242,
	       14, 123, 114, 69, 202, 206, 237, 184, 158, 114, 117,
	       250, 16, 108, 138, 64, 7, 93, 136, 181, 124, 121, 89,
	       163, 124, 90, 210, 103, 25, 63, 109, 17, 121, 182, 72,
	       68, 97, 187, 92, 166, 93, 194, 248, 152, 40, 142, 217,
	       243, 207, 106, 148, 140, 80, 51, 137, 190, 171, 182,
	       160, 32, 13, 49, 98, 66, 23, 183, 111, 0, 38, 46, 135,
	       84, 114, 2, 129, 221, 215, 212, 130, 143, 25, 60, 141,
	       0, 243, 92, 61, 135, 53, 117, 224, 138, 220, 83, 188,
	       188, 162, 252, 95, 28, 139, 65, 243, 51, 154, 208, 0,
	       48, 101, 19, 137, 41, 83, 165, 154, 141, 217, 170, 167,
	       215, 107, 0, 111, 103, 150, 190, 157, 172, 181, 218,
	       224, 227, 3, 127, 84, 237, 134, 33, 106, 122, 71, 109,
	       128, 39, 55, 95, 219, 183, 253, 45, 12, 117, 14, 39,
	       255, 101, 173, 116, 119, 72, 8, 169, 84, 63, 97, 230,
	       12, 226, 144, 240, 93, 191, 69, 216, 101, 86, 127, 244,
	       117, 190, 176, 158, 14, 252, 174, 234, 72, 8, 191, 10,
	       72, 130, 58, 151, 36, 56, 145, 238, 64, 15, 75, 101, 16,
	       83, 31, 123, 111, 202, 209, 61, 136, 18, 253, 2, 183,
	       110, 20, 204, 69, 205, 250, 62, 156, 104, 115, 96, 79,
	       75, 207, 207, 98, 31, 51, 125, 112, 69, 172, 156, 139,
	       69, 193, 86, 48, 158, 8, 245, 237, 4, 233, 43, 227, 216,
	       187, 141, 219, 170, 113, 60, 223, 227, 10, 124, 136,
	       235, 37, 127, 194, 110, 40, 145, 249, 99, 131, 120, 229,
	       230, 110, 131, 32, 196, 240, 176, 111, 135, 82, 224,
	       134, 208, 82, 178, 201, 253, 162, 47, 182, 38, 137, 3,
	       15, 207, 112, 220, 183, 46, 167, 191, 89, 102, 177, 38,
	       222, 167, 132, 178, 98, 16, 198, 216, 220, 245, 43, 216,
	       41, 139, 117, 242, 239, 241, 143, 174, 9, 136, 230, 239,
	       132, 82, 1, 62, 181, 138, 60, 185, 4, 203, 250, 201,
	       102, 43, 19, 25, 205, 196, 215, 182, 162, 198, 97, 207,
	       214, 120, 253, 177, 98, 218, 237, 5, 174, 186, 149, 166,
	       17, 20, 157, 31, 211, 120, 57, 185, 62, 125, 52, 237,
	       18, 160, 24, 162, 9, 128, 60, 138, 157, 13, 171, 167,
	       14, 163, 134, 127, 29, 170, 78, 250, 11, 206, 197, 131,
	       210, 247, 218, 157, 125, 34, 5, 130, 161, 76, 12, 104,
	       218, 168, 155, 111, 227, 182, 207, 80, 20, 138, 138,
	       137, 189, 6, 4, 148, 76, 100, 189, 131, 78, 29, 3, 207,
	       196, 218>>,
    MacEncSig = <<62, 65, 61, 11, 77, 52, 17, 16, 235, 224,
		  92, 96, 167, 47, 49, 203, 55, 189, 105, 136>>,
    R = {ok,
	 #otr_msg{type = signature,
		  value =
		      #otr_msg_signature{enc_sig = EncSig,
					 mac_enc_sig = MacEncSig}}},
    R = otr_message:decode(M). %}}}F

decode_data_1(_Config) -> %F{{{
    M = <<"?OTR:AAIDAAAAAAEAAAABAAAAwNrWiTNVRLbfXoektbMU"
	  "n9WfuJfT/OKEeThJum1VUgJOe40dlBDuTYOW+qhAEK7m9"
	  "9m7+fdbAeHdPKR14BQ5cOG7w2e0a37essAQPp4r105vne"
	  "I5XbHWBQspfIHfObz1iChK75GBvSb/LiLA0moBim+Vjfg"
	  "mrcC25bpYgBExuoalXJ+0/WAm3nQqtgR2USvONUphg/YY"
	  "wKfDwQaf/9vMbFjd2Fa47lE1lFFLZSRw3w5KVy9cs8e6A"
	  "S0GAuHG5He+GAAAAAAAAAABAAAAE5jPPXpVrMzhw59c04"
	  "KqmPcNOEJLhOeX3O/VWuO2B5fU5vdzN6NraQAAAAA=.">>,
    MpiDhy = <<218, 214, 137, 51, 85, 68, 182, 223, 94, 135,
	       164, 181, 179, 20, 159, 213, 159, 184, 151, 211, 252,
	       226, 132, 121, 56, 73, 186, 109, 85, 82, 2, 78, 123,
	       141, 29, 148, 16, 238, 77, 131, 150, 250, 168, 64, 16,
	       174, 230, 247, 217, 187, 249, 247, 91, 1, 225, 221, 60,
	       164, 117, 224, 20, 57, 112, 225, 187, 195, 103, 180,
	       107, 126, 222, 178, 192, 16, 62, 158, 43, 215, 78, 111,
	       157, 226, 57, 93, 177, 214, 5, 11, 41, 124, 129, 223,
	       57, 188, 245, 136, 40, 74, 239, 145, 129, 189, 38, 255,
	       46, 34, 192, 210, 106, 1, 138, 111, 149, 141, 248, 38,
	       173, 192, 182, 229, 186, 88, 128, 17, 49, 186, 134, 165,
	       92, 159, 180, 253, 96, 38, 222, 116, 42, 182, 4, 118,
	       81, 43, 206, 53, 74, 97, 131, 246, 24, 192, 167, 195,
	       193, 6, 159, 255, 219, 204, 108, 88, 221, 216, 86, 184,
	       238, 81, 53, 148, 81, 75, 101, 36, 112, 223, 14, 74, 87,
	       47, 92, 179, 199, 186, 1, 45, 6, 2, 225, 198, 228, 119,
	       190, 24>>,
    EncData = <<152, 207, 61, 122, 85, 172, 204, 225, 195,
		159, 92, 211, 130, 170, 152, 247, 13, 56, 66>>,
    Mac = <<75, 132, 231, 151, 220, 239, 213, 90, 227, 182,
	    7, 151, 212, 230, 247, 115, 55, 163, 107, 105>>,
    R = {ok,
	 #otr_msg{type = data,
		  value =
		      #otr_msg_data{flags = 0, sender_keyid = 1,
				    recipient_keyid = 1, mpi_dhy = MpiDhy,
				    ctr_init = <<0, 0, 0, 0, 0, 0, 0, 1>>,
				    enc_data = EncData, mac = Mac,
				    old_mac_keys = <<>>}}},
    R = otr_message:decode(M).  %}}}F

decode_data_2(_Config) -> %F{{{
    M = <<"?OTR:AAIDAAAAAAIAAAADAAAAwJamDA7Dg2QNRCc+4gJR"
	  "3H2tXB/EHKOBGb7kDVFTJItn+Djs6zh4hy7PPCrYAVr81"
	  "d9qaccXkaAER1TAvKmL/1VwYHeedRU97wEc4yc5ruiUcJ"
	  "izRifWdeoYV3V8MWsyehuLsi7Wc6/n2yp25UpOLeiczcl"
	  "/SPR+BMz+hdOBTylxXMLhjdeV99HzwepWeU0Dg97rd+BG"
	  "xq1jLEwo+tJ3DZM+NLaFagM8GTrlZ8vRioVOqAPLPAC0p"
	  "u3Ss4skRV251AAAAAAAAAABAAAADW3+eaa9o1udN2vmml"
	  "D2fLbbFLhiGMX1nOOdToTLMpL0LAAAABR24QC8o2e4uet"
	  "+3uZoqppch8VAPw==.">>,
    MpiDhy = <<150, 166, 12, 14, 195, 131, 100, 13, 68, 39,
	       62, 226, 2, 81, 220, 125, 173, 92, 31, 196, 28, 163,
	       129, 25, 190, 228, 13, 81, 83, 36, 139, 103, 248, 56,
	       236, 235, 56, 120, 135, 46, 207, 60, 42, 216, 1, 90,
	       252, 213, 223, 106, 105, 199, 23, 145, 160, 4, 71, 84,
	       192, 188, 169, 139, 255, 85, 112, 96, 119, 158, 117, 21,
	       61, 239, 1, 28, 227, 39, 57, 174, 232, 148, 112, 152,
	       179, 70, 39, 214, 117, 234, 24, 87, 117, 124, 49, 107,
	       50, 122, 27, 139, 178, 46, 214, 115, 175, 231, 219, 42,
	       118, 229, 74, 78, 45, 232, 156, 205, 201, 127, 72, 244,
	       126, 4, 204, 254, 133, 211, 129, 79, 41, 113, 92, 194,
	       225, 141, 215, 149, 247, 209, 243, 193, 234, 86, 121,
	       77, 3, 131, 222, 235, 119, 224, 70, 198, 173, 99, 44,
	       76, 40, 250, 210, 119, 13, 147, 62, 52, 182, 133, 106,
	       3, 60, 25, 58, 229, 103, 203, 209, 138, 133, 78, 168, 3,
	       203, 60, 0, 180, 166, 237, 210, 179, 139, 36, 69, 93,
	       185, 212>>,
    EncData = <<109, 254, 121, 166, 189, 163, 91, 157, 55,
		107, 230, 154, 80>>,
    Mac = <<246, 124, 182, 219, 20, 184, 98, 24, 197, 245,
	    156, 227, 157, 78, 132, 203, 50, 146, 244, 44>>,
    OMC = <<118, 225, 0, 188, 163, 103, 184, 185, 235, 126,
	    222, 230, 104, 170, 154, 92, 135, 197, 64, 63>>,
    R = {ok,
	 #otr_msg{type = data,
		  value =
		      #otr_msg_data{flags = 0, sender_keyid = 2,
				    recipient_keyid = 3, mpi_dhy = MpiDhy,
				    ctr_init = <<0, 0, 0, 0, 0, 0, 0, 1>>,
				    enc_data = EncData, mac = Mac,
				    old_mac_keys = OMC}}},
    R = otr_message:decode(M).  %}}}F

%}}}F

%F{{{ encode_...

encode_query(_Config) -> %F{{{
    {ok, <<"?OTRv2?">>} = otr_message:encode(#otr_msg{type =
							  query_v2}).%}}}F

encode_error(_Config) -> %F{{{
    {ok, <<"?OTR Error:blablub">>} =
	otr_message:encode(#otr_msg{type = error,
				    value = "blablub"}). %}}}F

encode_dh_commit(_Config) -> %F{{{
    R = <<"?OTR:AAICAAAAxCwNbeDb5N6sHCjimu6LwWDUcNalKWnf"
	  "1QR0B2iCT/WchV4lywHavNWmmT1KAvyogIeYZPv+pFg4S"
	  "FBazbrGgpMoC7YFr8kJskrHSdy4d9UnttYV3+1UGenXgl"
	  "2ECfyOwj7V/G2QwiPunLtLuFz94rk7jhMbNuZf4WY0r12"
	  "Nw/QeYbTRt2rRk+XTKv/wiWyq9zxfofhqsrP3UW+koMYb"
	  "iDQmawgB/qzKn6BAWrar2heFYPdFUDnvRlIGwdDgI2EG9"
	  "nfbRqwAAAAgf5bMB4oYtPAqDPD+eyTujEw7fXKmQz3Gcl"
	  "wYFdlrVmk=.">>,
    EncGx = <<44, 13, 109, 224, 219, 228, 222, 172, 28, 40,
	      226, 154, 238, 139, 193, 96, 212, 112, 214, 165, 41,
	      105, 223, 213, 4, 116, 7, 104, 130, 79, 245, 156, 133,
	      94, 37, 203, 1, 218, 188, 213, 166, 153, 61, 74, 2, 252,
	      168, 128, 135, 152, 100, 251, 254, 164, 88, 56, 72, 80,
	      90, 205, 186, 198, 130, 147, 40, 11, 182, 5, 175, 201,
	      9, 178, 74, 199, 73, 220, 184, 119, 213, 39, 182, 214,
	      21, 223, 237, 84, 25, 233, 215, 130, 93, 132, 9, 252,
	      142, 194, 62, 213, 252, 109, 144, 194, 35, 238, 156,
	      187, 75, 184, 92, 253, 226, 185, 59, 142, 19, 27, 54,
	      230, 95, 225, 102, 52, 175, 93, 141, 195, 244, 30, 97,
	      180, 209, 183, 106, 209, 147, 229, 211, 42, 255, 240,
	      137, 108, 170, 247, 60, 95, 161, 248, 106, 178, 179,
	      247, 81, 111, 164, 160, 198, 27, 136, 52, 38, 107, 8, 1,
	      254, 172, 202, 159, 160, 64, 90, 182, 171, 218, 23, 133,
	      96, 247, 69, 80, 57, 239, 70, 82, 6, 193, 208, 224, 35,
	      97, 6, 246, 119, 219, 70, 172>>,
    MacGx = <<127, 150, 204, 7, 138, 24, 180, 240, 42, 12,
	      240, 254, 123, 36, 238, 140, 76, 59, 125, 114, 166, 67,
	      61, 198, 114, 92, 24, 21, 217, 107, 86, 105>>,
    Q = #otr_msg{type = dh_commit,
		 value =
		     #otr_msg_dh_commit{enc_gx = EncGx, mac_gx = MacGx}},
    {ok, R} = otr_message:encode(Q). %}}}F

encode_dh_key(_Config) -> %F{{{
    R = <<"?OTR:AAIKAAAAwBlpxOqNOmK6dPYVxiO7IWs+V7YKHJ+B"
	  "kzThBOKapZKJU4YhfGZbq/+BbWB+vW1wDBLt19LAv2E1s"
	  "kifRU8CLSlCzESbTlrnF/rk4cKj6NmAiaB7EDXV/L5bjX"
	  "4hDvshAY3hQaj/2QJ85Sq7u9MIObCfhCS3vMbA4DrrV99"
	  "hzGy6ogPhspoKiuvMrTPaKbfGVFlKeAQTniTQT5EvxNTY"
	  "z5XX2qa64WjlfK1UUSzNqNQdl+QO20NSyNKWm6cCp5epM"
	  "Q==.">>,
    MpiGy = <<25, 105, 196, 234, 141, 58, 98, 186, 116, 246,
	      21, 198, 35, 187, 33, 107, 62, 87, 182, 10, 28, 159,
	      129, 147, 52, 225, 4, 226, 154, 165, 146, 137, 83, 134,
	      33, 124, 102, 91, 171, 255, 129, 109, 96, 126, 189, 109,
	      112, 12, 18, 237, 215, 210, 192, 191, 97, 53, 178, 72,
	      159, 69, 79, 2, 45, 41, 66, 204, 68, 155, 78, 90, 231,
	      23, 250, 228, 225, 194, 163, 232, 217, 128, 137, 160,
	      123, 16, 53, 213, 252, 190, 91, 141, 126, 33, 14, 251,
	      33, 1, 141, 225, 65, 168, 255, 217, 2, 124, 229, 42,
	      187, 187, 211, 8, 57, 176, 159, 132, 36, 183, 188, 198,
	      192, 224, 58, 235, 87, 223, 97, 204, 108, 186, 162, 3,
	      225, 178, 154, 10, 138, 235, 204, 173, 51, 218, 41, 183,
	      198, 84, 89, 74, 120, 4, 19, 158, 36, 208, 79, 145, 47,
	      196, 212, 216, 207, 149, 215, 218, 166, 186, 225, 104,
	      229, 124, 173, 84, 81, 44, 205, 168, 212, 29, 151, 228,
	      14, 219, 67, 82, 200, 210, 150, 155, 167, 2, 167, 151,
	      169, 49>>,
    Q = #otr_msg{type = dh_key,
		 value = #otr_msg_dh_key{mpi_gy = MpiGy}},
    {ok, R} = otr_message:encode(Q). %}}}F

encode_reveal_signature(_Config) -> %F{{{
    R = <<"?OTR:AAIRAAAAEOgmDPnVX65cXR6XKmnqf18AAAHSrBnG"
	  "I8WgWW0WfP2+O3kdWPRN3VbTzFiipWGyfqK7EBULIzj5c"
	  "g39gixRTEu0YHfr4haGhA4ngc0vyRsxiViCXy/o1lRd7X"
	  "e2zSRhwTTd46r9vXV/KJQHLPVQNyxJZMWLzuacExfCkDn"
	  "CZUflwtY0dPqs5aO450aZkpp65o4QpvXlOk7xxbJIac4i"
	  "AUfd1UEn96Lt024i6gbPpYm1+cuE0v/R1j/6vvhaJ73tW"
	  "AkRF1KixXNZlA2xg59FC/6JdAuCNPp/EHCwicTPyw3BDh"
	  "VVvOqIwFfJxrHEz5ixcLtwI2sd3X/eiy5mSUu75j2XjXf"
	  "8wEEMorYmOFEth948r65ruRdmn0BjFOxBvETgn7LULdJh"
	  "QQDfjriRt+vg2Grbn+Z5HiJFU2vLd2yib8FGKvg1bnOnV"
	  "oO2L2eB/4t5y7WIJUjJVHOawAsnw6pVNHq14b9E4Nbn/5"
	  "h9kYv3svrJWE0WXDdlJDLUGMwRYqsoK/8tKfdH2Ic6wMk"
	  "DWFbC/LFumCIHt+Tx3gHyseu4d4LnHzJg4+h0Kl0j0fCM"
	  "zb9DNRuUVwIxXmDkY7yRsUhKyHkuUhr/h5j/YAsJlflpG"
	  "m8A7FoNCpywk788r8RIj/n9PoSlDX7NFH+X+/QafaOONi"
	  "6t2sMWqRhZ+hLS.">>,
    RevKey = <<232, 38, 12, 249, 213, 95, 174, 92, 93, 30,
	       151, 42, 105, 234, 127, 95>>,
    EncSig = <<172, 25, 198, 35, 197, 160, 89, 109, 22, 124,
	       253, 190, 59, 121, 29, 88, 244, 77, 221, 86, 211, 204,
	       88, 162, 165, 97, 178, 126, 162, 187, 16, 21, 11, 35,
	       56, 249, 114, 13, 253, 130, 44, 81, 76, 75, 180, 96,
	       119, 235, 226, 22, 134, 132, 14, 39, 129, 205, 47, 201,
	       27, 49, 137, 88, 130, 95, 47, 232, 214, 84, 93, 237,
	       119, 182, 205, 36, 97, 193, 52, 221, 227, 170, 253, 189,
	       117, 127, 40, 148, 7, 44, 245, 80, 55, 44, 73, 100, 197,
	       139, 206, 230, 156, 19, 23, 194, 144, 57, 194, 101, 71,
	       229, 194, 214, 52, 116, 250, 172, 229, 163, 184, 231,
	       70, 153, 146, 154, 122, 230, 142, 16, 166, 245, 229, 58,
	       78, 241, 197, 178, 72, 105, 206, 34, 1, 71, 221, 213,
	       65, 39, 247, 162, 237, 211, 110, 34, 234, 6, 207, 165,
	       137, 181, 249, 203, 132, 210, 255, 209, 214, 63, 250,
	       190, 248, 90, 39, 189, 237, 88, 9, 17, 23, 82, 162, 197,
	       115, 89, 148, 13, 177, 131, 159, 69, 11, 254, 137, 116,
	       11, 130, 52, 250, 127, 16, 112, 176, 137, 196, 207, 203,
	       13, 193, 14, 21, 85, 188, 234, 136, 192, 87, 201, 198,
	       177, 196, 207, 152, 177, 112, 187, 112, 35, 107, 29,
	       221, 127, 222, 139, 46, 102, 73, 75, 187, 230, 61, 151,
	       141, 119, 252, 192, 65, 12, 162, 182, 38, 56, 81, 45,
	       135, 222, 60, 175, 174, 107, 185, 23, 102, 159, 64, 99,
	       20, 236, 65, 188, 68, 224, 159, 178, 212, 45, 210, 97,
	       65, 0, 223, 142, 184, 145, 183, 235, 224, 216, 106, 219,
	       159, 230, 121, 30, 34, 69, 83, 107, 203, 119, 108, 162,
	       111, 193, 70, 42, 248, 53, 110, 115, 167, 86, 131, 182,
	       47, 103, 129, 255, 139, 121, 203, 181, 136, 37, 72, 201,
	       84, 115, 154, 192, 11, 39, 195, 170, 85, 52, 122, 181,
	       225, 191, 68, 224, 214, 231, 255, 152, 125, 145, 139,
	       247, 178, 250, 201, 88, 77, 22, 92, 55, 101, 36, 50,
	       212, 24, 204, 17, 98, 171, 40, 43, 255, 45, 41, 247, 71,
	       216, 135, 58, 192, 201, 3, 88, 86, 194, 252, 177, 110,
	       152, 34, 7, 183, 228, 241, 222, 1, 242, 177, 235, 184,
	       119, 130, 231, 31, 50, 96, 227, 232, 116, 42, 93, 35,
	       209, 240, 140, 205, 191, 67, 53, 27, 148, 87, 2, 49, 94,
	       96, 228, 99, 188, 145, 177, 72, 74, 200, 121, 46, 82,
	       26, 255, 135, 152, 255, 96, 11, 9, 149, 249, 105, 26,
	       111, 0, 236, 90, 13, 10, 156, 176, 147, 191, 60, 175,
	       196, 72, 143, 249, 253, 62, 132, 165, 13, 126, 205,
	       20>>,
    MacEncSig = <<127, 151, 251, 244, 26, 125, 163, 142, 54,
		  46, 173, 218, 195, 22, 169, 24, 89, 250, 18, 210>>,
    Q = #otr_msg{type = reveal_signature,
		 value =
		     #otr_msg_reveal_signature{revealed_key = RevKey,
					       enc_sig = EncSig,
					       mac_enc_sig = MacEncSig}},
    {ok, R} = otr_message:encode(Q).  %}}}F

encode_signature(_Config) -> %F{{{
    R = <<"?OTR:AAISAAAB0n3kDM4JfUWOnSwxHjqmli+gpHt+ePIO"
	  "e3JFys7tuJ5ydfoQbIpAB12ItXx5WaN8WtJnGT9tEXm2S"
	  "ERhu1ymXcL4mCiO2fPPapSMUDOJvqu2oCANMWJCF7dvAC"
	  "Yuh1RyAoHd19SCjxk8jQDzXD2HNXXgitxTvLyi/F8ci0H"
	  "zM5rQADBlE4kpU6Wajdmqp9drAG9nlr6drLXa4OMDf1Tt"
	  "hiFqekdtgCc3X9u3/S0MdQ4n/2WtdHdICKlUP2HmDOKQ8"
	  "F2/RdhlVn/0db6wng78rupICL8KSII6lyQ4ke5AD0tlEF"
	  "Mfe2/K0T2IEv0Ct24UzEXN+j6caHNgT0vPz2IfM31wRay"
	  "ci0XBVjCeCPXtBOkr49i7jduqcTzf4wp8iOslf8JuKJH5"
	  "Y4N45eZugyDE8LBvh1LghtBSssn9oi+2JokDD89w3Lcup"
	  "79ZZrEm3qeEsmIQxtjc9SvYKYt18u/xj64JiObvhFIBPr"
	  "WKPLkEy/rJZisTGc3E17aixmHP1nj9sWLa7QWuupWmERS"
	  "dH9N4Obk+fTTtEqAYogmAPIqdDaunDqOGfx2qTvoLzsWD"
	  "0vfanX0iBYKhTAxo2qibb+O2z1AUioqJvQYElExkvYNOH"
	  "QPPxNo+QT0LTTQREOvgXGCnLzHLN71piA==.">>,
    EncSig = <<125, 228, 12, 206, 9, 125, 69, 142, 157, 44,
	       49, 30, 58, 166, 150, 47, 160, 164, 123, 126, 120, 242,
	       14, 123, 114, 69, 202, 206, 237, 184, 158, 114, 117,
	       250, 16, 108, 138, 64, 7, 93, 136, 181, 124, 121, 89,
	       163, 124, 90, 210, 103, 25, 63, 109, 17, 121, 182, 72,
	       68, 97, 187, 92, 166, 93, 194, 248, 152, 40, 142, 217,
	       243, 207, 106, 148, 140, 80, 51, 137, 190, 171, 182,
	       160, 32, 13, 49, 98, 66, 23, 183, 111, 0, 38, 46, 135,
	       84, 114, 2, 129, 221, 215, 212, 130, 143, 25, 60, 141,
	       0, 243, 92, 61, 135, 53, 117, 224, 138, 220, 83, 188,
	       188, 162, 252, 95, 28, 139, 65, 243, 51, 154, 208, 0,
	       48, 101, 19, 137, 41, 83, 165, 154, 141, 217, 170, 167,
	       215, 107, 0, 111, 103, 150, 190, 157, 172, 181, 218,
	       224, 227, 3, 127, 84, 237, 134, 33, 106, 122, 71, 109,
	       128, 39, 55, 95, 219, 183, 253, 45, 12, 117, 14, 39,
	       255, 101, 173, 116, 119, 72, 8, 169, 84, 63, 97, 230,
	       12, 226, 144, 240, 93, 191, 69, 216, 101, 86, 127, 244,
	       117, 190, 176, 158, 14, 252, 174, 234, 72, 8, 191, 10,
	       72, 130, 58, 151, 36, 56, 145, 238, 64, 15, 75, 101, 16,
	       83, 31, 123, 111, 202, 209, 61, 136, 18, 253, 2, 183,
	       110, 20, 204, 69, 205, 250, 62, 156, 104, 115, 96, 79,
	       75, 207, 207, 98, 31, 51, 125, 112, 69, 172, 156, 139,
	       69, 193, 86, 48, 158, 8, 245, 237, 4, 233, 43, 227, 216,
	       187, 141, 219, 170, 113, 60, 223, 227, 10, 124, 136,
	       235, 37, 127, 194, 110, 40, 145, 249, 99, 131, 120, 229,
	       230, 110, 131, 32, 196, 240, 176, 111, 135, 82, 224,
	       134, 208, 82, 178, 201, 253, 162, 47, 182, 38, 137, 3,
	       15, 207, 112, 220, 183, 46, 167, 191, 89, 102, 177, 38,
	       222, 167, 132, 178, 98, 16, 198, 216, 220, 245, 43, 216,
	       41, 139, 117, 242, 239, 241, 143, 174, 9, 136, 230, 239,
	       132, 82, 1, 62, 181, 138, 60, 185, 4, 203, 250, 201,
	       102, 43, 19, 25, 205, 196, 215, 182, 162, 198, 97, 207,
	       214, 120, 253, 177, 98, 218, 237, 5, 174, 186, 149, 166,
	       17, 20, 157, 31, 211, 120, 57, 185, 62, 125, 52, 237,
	       18, 160, 24, 162, 9, 128, 60, 138, 157, 13, 171, 167,
	       14, 163, 134, 127, 29, 170, 78, 250, 11, 206, 197, 131,
	       210, 247, 218, 157, 125, 34, 5, 130, 161, 76, 12, 104,
	       218, 168, 155, 111, 227, 182, 207, 80, 20, 138, 138,
	       137, 189, 6, 4, 148, 76, 100, 189, 131, 78, 29, 3, 207,
	       196, 218>>,
    MacEncSig = <<62, 65, 61, 11, 77, 52, 17, 16, 235, 224,
		  92, 96, 167, 47, 49, 203, 55, 189, 105, 136>>,
    Q = #otr_msg{type = signature,
		 value =
		     #otr_msg_signature{enc_sig = EncSig,
					mac_enc_sig = MacEncSig}},
    {ok, R} = otr_message:encode(Q). %}}}F

encode_data_1(_Config) -> %F{{{
    R = <<"?OTR:AAIDAAAAAAEAAAABAAAAwNrWiTNVRLbfXoektbMU"
	  "n9WfuJfT/OKEeThJum1VUgJOe40dlBDuTYOW+qhAEK7m9"
	  "9m7+fdbAeHdPKR14BQ5cOG7w2e0a37essAQPp4r105vne"
	  "I5XbHWBQspfIHfObz1iChK75GBvSb/LiLA0moBim+Vjfg"
	  "mrcC25bpYgBExuoalXJ+0/WAm3nQqtgR2USvONUphg/YY"
	  "wKfDwQaf/9vMbFjd2Fa47lE1lFFLZSRw3w5KVy9cs8e6A"
	  "S0GAuHG5He+GAAAAAAAAAABAAAAE5jPPXpVrMzhw59c04"
	  "KqmPcNOEJLhOeX3O/VWuO2B5fU5vdzN6NraQAAAAA=.">>,
    MpiDhy = <<218, 214, 137, 51, 85, 68, 182, 223, 94, 135,
	       164, 181, 179, 20, 159, 213, 159, 184, 151, 211, 252,
	       226, 132, 121, 56, 73, 186, 109, 85, 82, 2, 78, 123,
	       141, 29, 148, 16, 238, 77, 131, 150, 250, 168, 64, 16,
	       174, 230, 247, 217, 187, 249, 247, 91, 1, 225, 221, 60,
	       164, 117, 224, 20, 57, 112, 225, 187, 195, 103, 180,
	       107, 126, 222, 178, 192, 16, 62, 158, 43, 215, 78, 111,
	       157, 226, 57, 93, 177, 214, 5, 11, 41, 124, 129, 223,
	       57, 188, 245, 136, 40, 74, 239, 145, 129, 189, 38, 255,
	       46, 34, 192, 210, 106, 1, 138, 111, 149, 141, 248, 38,
	       173, 192, 182, 229, 186, 88, 128, 17, 49, 186, 134, 165,
	       92, 159, 180, 253, 96, 38, 222, 116, 42, 182, 4, 118,
	       81, 43, 206, 53, 74, 97, 131, 246, 24, 192, 167, 195,
	       193, 6, 159, 255, 219, 204, 108, 88, 221, 216, 86, 184,
	       238, 81, 53, 148, 81, 75, 101, 36, 112, 223, 14, 74, 87,
	       47, 92, 179, 199, 186, 1, 45, 6, 2, 225, 198, 228, 119,
	       190, 24>>,
    EncData = <<152, 207, 61, 122, 85, 172, 204, 225, 195,
		159, 92, 211, 130, 170, 152, 247, 13, 56, 66>>,
    Mac = <<75, 132, 231, 151, 220, 239, 213, 90, 227, 182,
	    7, 151, 212, 230, 247, 115, 55, 163, 107, 105>>,
    Q = #otr_msg{type = data,
		 value =
		     #otr_msg_data{flags = 0, sender_keyid = 1,
				   recipient_keyid = 1, mpi_dhy = MpiDhy,
				   ctr_init = <<0, 0, 0, 0, 0, 0, 0, 1>>,
				   enc_data = EncData, mac = Mac,
				   old_mac_keys = <<>>}},
    {ok, R} = otr_message:encode(Q).  %}}}F

encode_data_2(_Config) -> %F{{{
    R = <<"?OTR:AAIDAAAAAAIAAAADAAAAwJamDA7Dg2QNRCc+4gJR"
	  "3H2tXB/EHKOBGb7kDVFTJItn+Djs6zh4hy7PPCrYAVr81"
	  "d9qaccXkaAER1TAvKmL/1VwYHeedRU97wEc4yc5ruiUcJ"
	  "izRifWdeoYV3V8MWsyehuLsi7Wc6/n2yp25UpOLeiczcl"
	  "/SPR+BMz+hdOBTylxXMLhjdeV99HzwepWeU0Dg97rd+BG"
	  "xq1jLEwo+tJ3DZM+NLaFagM8GTrlZ8vRioVOqAPLPAC0p"
	  "u3Ss4skRV251AAAAAAAAAABAAAADW3+eaa9o1udN2vmml"
	  "D2fLbbFLhiGMX1nOOdToTLMpL0LAAAABR24QC8o2e4uet"
	  "+3uZoqppch8VAPw==.">>,
    MpiDhy = <<150, 166, 12, 14, 195, 131, 100, 13, 68, 39,
	       62, 226, 2, 81, 220, 125, 173, 92, 31, 196, 28, 163,
	       129, 25, 190, 228, 13, 81, 83, 36, 139, 103, 248, 56,
	       236, 235, 56, 120, 135, 46, 207, 60, 42, 216, 1, 90,
	       252, 213, 223, 106, 105, 199, 23, 145, 160, 4, 71, 84,
	       192, 188, 169, 139, 255, 85, 112, 96, 119, 158, 117, 21,
	       61, 239, 1, 28, 227, 39, 57, 174, 232, 148, 112, 152,
	       179, 70, 39, 214, 117, 234, 24, 87, 117, 124, 49, 107,
	       50, 122, 27, 139, 178, 46, 214, 115, 175, 231, 219, 42,
	       118, 229, 74, 78, 45, 232, 156, 205, 201, 127, 72, 244,
	       126, 4, 204, 254, 133, 211, 129, 79, 41, 113, 92, 194,
	       225, 141, 215, 149, 247, 209, 243, 193, 234, 86, 121,
	       77, 3, 131, 222, 235, 119, 224, 70, 198, 173, 99, 44,
	       76, 40, 250, 210, 119, 13, 147, 62, 52, 182, 133, 106,
	       3, 60, 25, 58, 229, 103, 203, 209, 138, 133, 78, 168, 3,
	       203, 60, 0, 180, 166, 237, 210, 179, 139, 36, 69, 93,
	       185, 212>>,
    EncData = <<109, 254, 121, 166, 189, 163, 91, 157, 55,
		107, 230, 154, 80>>,
    Mac = <<246, 124, 182, 219, 20, 184, 98, 24, 197, 245,
	    156, 227, 157, 78, 132, 203, 50, 146, 244, 44>>,
    OMC = <<118, 225, 0, 188, 163, 103, 184, 185, 235, 126,
	    222, 230, 104, 170, 154, 92, 135, 197, 64, 63>>,
    Q = #otr_msg{type = data,
		 value =
		     #otr_msg_data{flags = 0, sender_keyid = 2,
				   recipient_keyid = 3, mpi_dhy = MpiDhy,
				   ctr_init = <<0, 0, 0, 0, 0, 0, 0, 1>>,
				   enc_data = EncData, mac = Mac,
				   old_mac_keys = OMC}},
    {ok, R} = otr_message:encode(Q).  %}}}F

%}}}F

