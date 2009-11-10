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
	rm -f test.spec
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


test.spec: test.spec.in
	cat test.spec.in | sed s%@PATH@%${PWD}% > test.spec

test: logdir build ${TEST_SPEC}
	${RUN_TEST} ${ERL_PA} -spec ${TEST_SPEC} -logdir ${PWD}/log -cover cover.spec -include ${PWD}/"lib/erlotr/src"

