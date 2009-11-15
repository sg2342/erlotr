-module(otr_mcgs_SUITE).

-author("Stefan Grundmann <sg2342@googlemail.com>").

-compile(export_all).

init_per_suite(Config) -> Config.

end_per_suite(Config) -> Config.

init_per_testcase(_TestCase, Config) -> Config.

end_per_testcase(_TestCase, Config) -> Config.

all() -> [foo].

foo(_C) -> ok.
