CFLAGS+=$(shell pkg-config --cflags r_socket)
LDFLAGS+=$(shell pkg-config --libs r_socket)

TESTS=ctest ao_functions.o ctest.o simpreadwrite simpreadwrite32
CC=gcc -std=c99

all: $(TESTS)

ao_functions.o: ao_functions.c *.h 
	${CC} ${CFLAGS} ${LDFLAGS} -c -o $@ $<

ctest.o: ctest.c *.h
	${CC} ${CFLAGS} -c -o $@ $<

simpreadwrite: simpreadwrite.c
	${CC} -o simpreadwrite simpreadwrite.c 

simpreadwrite32: simpreadwrite.c
	${CC} -m32 -o simpreadwrite32 simpreadwrite.c 

ctest: ctest.o ao_functions.o *.h
	${CC} $(CFLAGS) ${LDFLAGS} -o $@ $^ 

clean:
	rm -f $(TESTS)
	rm -f a.out

.PHONY: $(TESTS)
