ERL_BASE=/usr/local/lib/erlang
RUN_TEST=${ERL_BASE}/lib/common_test-1.4.5/priv/bin/run_test
ERL=${ERL_BASE}/bin/erl

ERL_PA=-pa ${PWD}/lib/*/ebin

TEST_SPEC?=test.spec

APPLICATIONS=erlotr

all: test

ebin_subdirs:
	for A in ${APPLICATIONS} ; do mkdir -p lib/$$A/ebin; done

build: ebin_subdirs applications
	${ERL} ${ERL_PA} -make

shell:
	${ERL} ${ERL_PA}


clean:
	for A in ${APPLICATIONS} ; \
	    do \
	    rm -rf lib/$$A/ebin; \
	    rm -f lib/$$A/test/*.beam; \
	    done

shiny: clean
	rm -rf log 

logdir:
	mkdir -p log
	cat /dev/null > log/cover.db

applications:
	for A in ${APPLICATIONS} ; do \
		V=`VSNF=lib/$$A/src/vsn;\
		    [ -e $$VSNF ] \
			&& cat $$VSNF \
			|| echo -n  0.0 `; \
		[ -e lib/$$A/src/$$A.app.src ] \
		    && cat lib/$$A/src/$$A.app.src | \
			sed -e"s,%VSN%,$$V," > lib/$$A/ebin/$$A.app \
		    || true ;\
	done

test: logdir build ${TEST_SPEC}
	ERL_LIBS="${ERL_LIBS}:`pwd`/lib" \
	erl -sname otr_test -spec ${TEST_SPEC} -logdir ${PWD}/log \
	-cover cover.spec -s ct_run script_start -s erlang halt
