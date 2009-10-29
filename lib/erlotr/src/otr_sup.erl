-module(otr_sup).

-author("Stefan Grundmann <sg2342@googlemail.com>").


-behaviour(supervisor).


-export([init/1, start_child/1, start_link/0]).

start_child(Args) -> supervisor:start_child(?MODULE, [Args]).

start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

init([]) ->
    Fsm = {otr_fsm, 
           {otr_fsm, start_link, []}, temporary,
	   brutal_kill, worker, [otr_fsm]},
    {ok, {{simple_one_for_one, 10, 1}, [Fsm]}}.
