CC = cc
CFLAGS = -O3 -pthread -fomit-frame-pointer -DINTEL

all: procrule

procrule.o: procrule.c yarn.h xxh3.h xxhash.h
	$(CC) $(CFLAGS) -I/opt/local/include -c procrule.c

ruleproc.o: ruleproc.c mdxfind.h
	$(CC) $(CFLAGS) -c ruleproc.c

yarn.o: yarn.c yarn.h
	$(CC) $(CFLAGS) -c yarn.c

procrule: procrule.o ruleproc.o yarn.o
	$(CC) -L/usr/local/lib -L/opt/local/lib -pthread -o procrule procrule.o ruleproc.o yarn.o -lJudy

clean:
	rm -f procrule *.o
