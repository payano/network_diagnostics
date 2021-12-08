LIBS  = 
CFLAGS = -Wall -pedantic -O2 -Werror -Wextra -fexceptions

SRC=$(wildcard src/*.c)

%.o : %.c
	gcc -c $(CFLAGS) $< -o $@

network_tester: $(SRC)
	gcc -o $@ $^ $(CFLAGS) $(LIBS)

clean :
	-rm network_tester
