%%
%% Purpose: Off-the-Record Messaging
%%          (http://www.cypherpunks.ca/otr/Protocol-v2-3.1.0.html)
%%          application supervisor
%%

-module(otr_sup).

-author("Stefan Grundmann <sg2342@googlemail.com>").

-copyright("Copyright 2009 Stefan Grundmann").

-behaviour(supervisor).

-define(SERVER, ?MODULE).

-export([init/1, start_child/1, stop_child/1, start_link/0]).

start_child(Args) -> supervisor:start_child(?MODULE, [Args]).

% XXX
% I'm not sure if this is The_Way(tm) to 
% stop supervisors that are supervised by a simple_one_for_one
% supervisor 
% XXX
stop_child(Pid) -> 
    Pid ! {'EXIT', whereis(?SERVER), shutdown}, ok.
    

start_link() ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, []).

init([]) ->
    Ctx = {otr_ctx_sup, 
           {otr_ctx_sup, start_link, []}, temporary,
	   infinity, supervisor, [otr_ctx_sup]},
    {ok, {{simple_one_for_one, 10, 1}, [Ctx]}}.
