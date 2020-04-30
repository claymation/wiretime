CC	:= $(CROSS_COMPILE)$(CC)
CFLAGS	?= -Wall -Wextra -O3

BINS	= wiretime

.PHONY: all
all: $(BINS)

.PHONY: clean
clean:
	rm -f $(BINS)
