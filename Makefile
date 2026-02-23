# Auto-detect architecture and OS
UNAME_M := $(shell uname -m)
UNAME_S := $(shell uname -s)

CC=cc

ifeq ($(UNAME_M),x86_64)
  COPTS=-DINTEL
else ifeq ($(UNAME_M),i386)
  COPTS=-DINTEL
else ifeq ($(UNAME_M),i686)
  COPTS=-DINTEL
else ifeq ($(UNAME_M),aarch64)
  COPTS=-DARM
else ifeq ($(UNAME_M),arm64)
  COPTS=-DARM
else ifneq (,$(findstring arm,$(UNAME_M)))
  COPTS=-DARM
else ifneq (,$(findstring ppc,$(UNAME_M)))
  COPTS=-DPOWERPC
else
  COPTS=
endif

# GCC (non-Darwin) needs -fgnu89-inline and explicit -mssse3 for INTEL
ifneq ($(UNAME_S),Darwin)
  COPTS += -fgnu89-inline
  ifneq (,$(findstring INTEL,$(COPTS)))
    COPTS += -mssse3
  endif
endif

# Find Judy.h include path
ifneq (,$(wildcard /opt/local/include/Judy.h))
  JUDY_INC=-I/opt/local/include
  JUDY_LIB=-L/opt/local/lib
else ifneq (,$(wildcard /opt/homebrew/include/Judy.h))
  JUDY_INC=-I/opt/homebrew/include
  JUDY_LIB=-L/opt/homebrew/lib
else ifneq (,$(wildcard /usr/local/include/Judy.h))
  JUDY_INC=-I/usr/local/include
  JUDY_LIB=-L/usr/local/lib
else
  JUDY_INC=
  JUDY_LIB=
endif

CFLAGS=-fomit-frame-pointer -pthread -O3 $(COPTS)

all: procrule

procrule.o: procrule.c yarn.h xxh3.h xxhash.h
	$(CC) $(CFLAGS) $(JUDY_INC) -c procrule.c
ruleproc.o: ruleproc.c mdxfind.h
	$(CC) $(CFLAGS) -c ruleproc.c
yarn.o: yarn.c yarn.h
	$(CC) $(CFLAGS) -c yarn.c
procrule: procrule.o ruleproc.o yarn.o
	$(CC) -pthread $(JUDY_LIB) -o procrule procrule.o ruleproc.o yarn.o -lJudy
clean:
	rm -f procrule *.o
