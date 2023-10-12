INC    = ../include
CFLAGS = -O2 -Wall -I $(INC)

build: libxt_daf.so

lib%.so: lib%.o
	gcc -shared -o $@ $^

lib%.o: lib%.c
	gcc $(CFLAGS) -fPIC -c -o $@ $<

clean:
	@rm -f *.o *.so

