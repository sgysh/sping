TARGETS := sping

.PHONY : all clean

all: $(TARGETS)

sping: sping.cc
	g++ -std=c++11 -o $@ $<
	sudo setcap 'CAP_NET_RAW+ep' $@

clean:
	rm -v $(TARGETS)

