LIBS  = 
CFLAGS = -Wall -pedantic -O2 -Werror -Wextra -fexceptions

SRC=$(wildcard src/*.c)

network_tester: $(SRC)
	${CC} -o $@ $^ $(CFLAGS) $(LIBS)

clean :
	-rm network_tester
