-module(otr_mcgs_SUITE).

-author("Stefan Grundmann <sg2342@googlemail.com>").

-compile(export_all).

-include("ct.hrl").

-include("otr_internal.hrl").

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

init_per_testcase(_TestCase, Config) ->
    {ok, Mcgs1} = otr_mcgs:start_link(),
    register(mcgs1, Mcgs1),
    {ok, Mcgs2} = otr_mcgs:start_link(),
    register(mcgs2, Mcgs2),
    Config.

end_per_testcase(_TestCase, Config) ->
    catch unlink(whereis(mcgs1)),
    catch exit(whereis(mcgs1), shutdown),
    catch unlink(whereis(mcgs2)),
    catch exit(whereis(mcgs2), shutdown),
    Config.

all() ->
    [set_keys_1, set_keys_2, set_keys_3, set_keys_4,
     get_key, encrypt_1, encrypt_2, encrypt_3, decrypt_1,
     decrypt_2, decrypt_3, decrypt_4, decrypt_5, cover].

set_keys_1(_Config) ->
    Dh = otr_crypto:dh_gen_key(),
    {_, Y} = otr_crypto:dh_gen_key(),
    ok = otr_mcgs:set_keys(mcgs1, {5, Dh, 1, Y}).

set_keys_2(_Config) ->
    {ok, {1, Dh}} = otr_mcgs:get_key(mcgs1),
    {_, Y} = otr_crypto:dh_gen_key(),
    ok = otr_mcgs:set_keys(mcgs1, {1, Dh, 1, Y}).

set_keys_3(_Config) ->
    {ok, {1, Dh}} = otr_mcgs:get_key(mcgs1),
    {_, Y} = otr_crypto:dh_gen_key(),
    ok = otr_mcgs:set_keys(mcgs1, {1, Dh, 1, Y}),
    ok = otr_mcgs:set_keys(mcgs1, {1, Dh, 1, Y}).

set_keys_4(_Config) ->
    {ok, {1, Dh1 = {_, Y1}}} = otr_mcgs:get_key(mcgs1),
    {ok, {1, Dh2 = {_, Y2}}} = otr_mcgs:get_key(mcgs2),
    ok = otr_mcgs:set_keys(mcgs1, {1, Dh1, 1, Y2}),
    ok = otr_mcgs:set_keys(mcgs2, {1, Dh2, 1, Y1}),
    {ok, #otr_msg_data{} = M1} = otr_mcgs:encrypt(mcgs1,
						  {"foo", [], 0}),
    {ok, {"foo", []}} = otr_mcgs:decrypt(mcgs2, M1),
    {ok, #otr_msg_data{} = M2} = otr_mcgs:encrypt(mcgs1,
						  {"foo", [], 0}),
    {ok, {"foo", []}} = otr_mcgs:decrypt(mcgs2, M2),
    {ok, #otr_msg_data{} = M3} = otr_mcgs:encrypt(mcgs2,
						  {"foo", [], 0}),
    {ok, {"foo", []}} = otr_mcgs:decrypt(mcgs1, M3),
    {ok, #otr_msg_data{} = M4} = otr_mcgs:encrypt(mcgs2,
						  {"foo", [], 0}),
    {ok, {"foo", []}} = otr_mcgs:decrypt(mcgs1, M4),
    {ok, {2, Dh5 = {_, _}}} = otr_mcgs:get_key(mcgs1),
    {ok, {1, _ = {_, Y6}}} = otr_mcgs:get_key(mcgs2),
    ok = otr_mcgs:set_keys(mcgs1, {2, Dh5, 1, Y6}).

get_key(_Config) ->
    {ok, {1, {_, _}}} = otr_mcgs:get_key(mcgs1).

encrypt_1(_Config) ->
    {_, Y} = otr_crypto:dh_gen_key(),
    {ok, {1, Dh}} = otr_mcgs:get_key(mcgs1),
    ok = otr_mcgs:set_keys(mcgs1, {1, Dh, 1, Y}),
    {ok, #otr_msg_data{flags = 0}} = otr_mcgs:encrypt(mcgs1,
						      "foo").

encrypt_2(_Config) ->
    {_, Y} = otr_crypto:dh_gen_key(),
    {ok, {1, Dh}} = otr_mcgs:get_key(mcgs1),
    ok = otr_mcgs:set_keys(mcgs1, {1, Dh, 1, Y}),
    {ok, #otr_msg_data{flags = 1}} = otr_mcgs:encrypt(mcgs1,
						      {"foo", [], 1}).

encrypt_3(_Config) ->
    {_, Y} = otr_crypto:dh_gen_key(),
    {ok, {1, Dh}} = otr_mcgs:get_key(mcgs1),
    ok = otr_mcgs:set_keys(mcgs1, {1, Dh, 1, Y}),
    {ok, #otr_msg_data{flags = 0}} = otr_mcgs:encrypt(mcgs1,
						      {"foo", []}).

decrypt_1(_Config) ->
    {ok, {1, Dh1 = {_, Y1}}} = otr_mcgs:get_key(mcgs1),
    {ok, {1, Dh2 = {_, Y2}}} = otr_mcgs:get_key(mcgs2),
    ok = otr_mcgs:set_keys(mcgs1, {1, Dh1, 1, Y2}),
    ok = otr_mcgs:set_keys(mcgs2, {1, Dh2, 1, Y1}),
    {ok, M} = otr_mcgs:encrypt(mcgs1, {"foo", [], 0}),
    {rejected, no_keys, _} = otr_mcgs:decrypt(mcgs2,
					   M#otr_msg_data{sender_keyid = 88}).

decrypt_2(_Config) ->
    {ok, {1, Dh1 = {_, Y1}}} = otr_mcgs:get_key(mcgs1),
    {ok, {1, Dh2 = {_, Y2}}} = otr_mcgs:get_key(mcgs2),
    ok = otr_mcgs:set_keys(mcgs1, {1, Dh1, 1, Y2}),
    ok = otr_mcgs:set_keys(mcgs2, {1, Dh2, 1, Y1}),
    {ok, M} = otr_mcgs:encrypt(mcgs1, {"foo", [], 0}),
    {rejected, mac_missmatch, _} = otr_mcgs:decrypt(mcgs2,
						 M#otr_msg_data{mac =
								    <<0:160>>}).

decrypt_3(_Config) ->
    {ok, {1, Dh1 = {_, Y1}}} = otr_mcgs:get_key(mcgs1),
    {ok, {1, Dh2 = {_, Y2}}} = otr_mcgs:get_key(mcgs2),
    ok = otr_mcgs:set_keys(mcgs1, {1, Dh1, 1, Y2}),
    ok = otr_mcgs:set_keys(mcgs2, {1, Dh2, 1, Y1}),
    {ok, M1} = otr_mcgs:encrypt(mcgs1, {"foo", [], 0}),
    {ok, _} = otr_mcgs:decrypt(mcgs2, M1),
    {rejected, ctr_to_low, _} = otr_mcgs:decrypt(mcgs2, M1).

decrypt_4(_Config) ->
    {ok, {1, Dh1 = {_, Y1}}} = otr_mcgs:get_key(mcgs1),
    {ok, {1, Dh2 = {_, Y2}}} = otr_mcgs:get_key(mcgs2),
    ok = otr_mcgs:set_keys(mcgs1, {1, Dh1, 1, Y2}),
    ok = otr_mcgs:set_keys(mcgs2, {1, Dh2, 1, Y1}),
    F = fun (X) ->
		SA = "foo" ++ integer_to_list(X),
		SB = "bar" ++ integer_to_list(X),
		{ok, MA} = otr_mcgs:encrypt(mcgs1, SA),
		{ok, {SA, []}} = otr_mcgs:decrypt(mcgs2, MA),
		{ok, MB} = otr_mcgs:encrypt(mcgs2, SB),
		{ok, {SB, []}} = otr_mcgs:decrypt(mcgs1, MB)
	end,
    lists:foreach(F, lists:seq(1, 10)),
    ok.

decrypt_5(_Config) ->
    {ok, {1, Dh1 = {_, Y1}}} = otr_mcgs:get_key(mcgs1),
    {ok, {1, Dh2 = {_, Y2}}} = otr_mcgs:get_key(mcgs2),
    ok = otr_mcgs:set_keys(mcgs1, {1, Dh1, 1, Y2}),
    ok = otr_mcgs:set_keys(mcgs2, {1, Dh2, 1, Y1}),
    F = fun (X) ->
		SA = "foo" ++ integer_to_list(X),
		SB = "bar" ++ integer_to_list(X),
		{ok, MA1} = otr_mcgs:encrypt(mcgs1, SA),
		{ok, {SA, []}} = otr_mcgs:decrypt(mcgs2, MA1),
		{ok, MA2} = otr_mcgs:encrypt(mcgs1, SA),
		{ok, {SA, []}} = otr_mcgs:decrypt(mcgs2, MA2),
		{ok, MB1} = otr_mcgs:encrypt(mcgs2, SB),
		{ok, {SB, []}} = otr_mcgs:decrypt(mcgs1, MB1),
		{ok, MB2} = otr_mcgs:encrypt(mcgs2, SB),
		{ok, {SB, []}} = otr_mcgs:decrypt(mcgs1, MB2)
	end,
    lists:foreach(F, lists:seq(1, 10)),
    ok.

cover(_Config) ->
    ct:comment("achive 100% coverage: call code_change/4, "
	       "terminate/3 and the handle_... functions "
	       "that are meant to fail"),
    ok = otr_mcgs:terminate(a, b),
    {ok, b} = otr_mcgs:code_change(a, b, c),
    {stop, {undefined_info, a}, b} = otr_mcgs:handle_info(a,
							  b),
    {stop, {undefined_call, a}, c} = otr_mcgs:handle_call(a,
							  b, c),
    {stop, {undefined_cast, a}, b} = otr_mcgs:handle_cast(a,
							  b),
    ok.
