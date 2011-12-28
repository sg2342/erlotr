all: build

build: erlotr_build

clean: erlotr_clean

ct_test: erlotr_ct_test

dialyzer: erlotr_dialyzer

erlotr_build:
	${MAKE} -C lib/erlotr build

erlotr_clean:
	${MAKE} -C lib/erlotr clean

erlotr_ct_test:
	${MAKE} -C lib/erlotr ct_test

erlotr_dialyzer:
	${MAKE} -C lib/erlotr dialyzer
