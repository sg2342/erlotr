-module(otr_app).

-author("Stefan Grundmann <sg2342@googlemail.com>").

-behaviour(application).

-export([start/2, stop/1]).

start(_Type, _StartArgs) -> otr_sup:start_link().

stop(_State) -> ok.

