%%
%% Purpose: Off-the-Record Messaging
%%          (http://www.cypherpunks.ca/otr/Protocol-v2-3.1.0.html)
%%          application module
%%

-module(otr_app).

-author("Stefan Grundmann <sg2342@googlemail.com>").

-copyright("Copyright 2009 Stefan Grundmann").

-behaviour(application).

-export([start/2, stop/1]).

start(_Type, _StartArgs) -> otr_sup:start_link().

stop(_State) -> ok.

