PREFIX?=/usr/local
TEST_LOGDIR?="../../log"

DIALIZER_FLAGS?=-n -Wunmatched_returns -Werror_handling -Wrace_conditions

build: ebin/crypto_aux.app priv/lib/crypto_aux.so
	@erl -make

ebin/crypto_aux.app: ebin src/crypto_aux.app.src src/vsn
	@VSN=`cat src/vsn`; \
	echo VSN=$${VSN}; \
	sed -e s/%VSN%/$${VSN}/\; src/crypto_aux.app.src > ebin/crypto_aux.app

priv/lib/crypto_aux.so : priv/lib c_src/crypto_aux.c
	case `uname` in \
	    FreeBSD) \
		case `uname -m` in \
		    i386) \
			FLAGS="-shared -lcrypto -L$(PREFIX)/lib -fPIC -m32" \
			;; \
		    amd64) \
			FLAGS="-shared -lcrypto -L$(PREFIX)/lib -fPIC -m64" \
			;; \
		esac;; \
	    Linux) \
		case `uname -m` in \
		    i386) \
			FLAGS="-m32 -fPIC -shared -lcrypt -lcrypto -L$(PREFIX)/lib"\
			;; \
		    amd64) \
			FLAGS="-m64 -fPIC -shared -lcrypt -lcrypto -L$(PREFIX)/lib"\
			;; \
		esac;; \
	    Darwin) \
		FLAGS="-bundle -fPIC -flat_namespace -undefined suppress -fno-common -lcrypto -m64" \
		;; \
	esac; \
	$(CC) $(CFLAGS) $(LDFLAGS) $$FLAGS  -Wall -Werror \
	    -DCRYPTO_AUX_NO_HW_ACCELERATED_ENGINE \
	    -I$(PREFIX)/lib/erlang/usr/include \
	    -o priv/lib/crypto_aux.so  c_src/crypto_aux.c 

priv/lib:
	mkdir -p priv/lib


dialyzer:
	dialyzer ${DIALIZER_FLAGS} --src src/*.erl

ebin:
	@mkdir -p ebin

clean:
	@rm -rf ebin
	@rm -rf priv
	@rm -rf test/*.beam

ct_test: build
	mkdir -p ${TEST_LOGDIR}
	erl -sname unit-test -spec test/crypto_aux.spec \
	-logdir ${TEST_LOGDIR} \
	-cover test/crypto_aux.cover \
	-s ct_run script_start \
	-s erlang halt

