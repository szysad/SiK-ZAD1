CC = gcc
CFLAGS = -Wall -g
TARGETS = testhttp_raw

all: $(TARGETS) 

debug: CFLAGS += -DDEBUG -g
debug: $(TARGETS)

testhttp_raw.o: testhttp_raw.c

testhttp_raw: testhttp_raw.o

clean:
	rm -f *.o *~ $(TARGETS) 
