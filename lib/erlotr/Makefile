TEST_LOGDIR="../../log"

DIALIZER_FLAGS?=-n -Wunmatched_returns -Werror_handling -Wrace_conditions

build: ebin/erlotr.app 
	@erl -make

ebin/erlotr.app: ebin src/erlotr.app.src src/vsn
	@VSN=`cat src/vsn`; \
	echo VSN=$${VSN}; \
	sed -e s/%VSN%/$${VSN}/\; src/erlotr.app.src > ebin/erlotr.app

dialyzer:
	dialyzer ${DIALIZER_FLAGS} --src src/*.erl

ebin:
	@mkdir -p ebin

clean:
	@rm -rf ebin
	@rm -rf test/*.beam

ct_test: build
	mkdir -p ${TEST_LOGDIR}
	ERL_LIBS="$${ERL_LIBS}:`pwd`/.." \
	 erl -sname unit-test -spec test/erlotr.spec \
	-logdir ${TEST_LOGDIR} \
	-cover test/erlotr.cover \
	-s crypto_aux start \
	-s ct_run script_start \
	-s erlang halt

