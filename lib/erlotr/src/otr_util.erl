-module(otr_util).

-author("Stefan Grundmann <sg2342@googlemail.com>").

-export([erlint/1, mpint/1]).

erlint(B) -> crypto:erlint(B).

mpint(I) -> 
    <<_:32, R/binary>> = crypto:mpint(I),
    ZerosStripped = strip_zeros(R),
    <<(size(ZerosStripped)):32, ZerosStripped/binary>>.

strip_zeros(<<0, T/binary>>) -> strip_zeros(T);
strip_zeros(Stripped) -> Stripped.
