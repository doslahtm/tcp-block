LDLIBS=-lpcap

all: tcp-block

tcp-block: main.o tcp-block.o ethhdr.o ip.o mac.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f tcp-block *.o
