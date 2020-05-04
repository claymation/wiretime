CC	:= $(CROSS_COMPILE)$(CC)
CFLAGS	?= -Wall -Wextra -O0
INSTALL ?= install

BINS	= wiretime spin

.PHONY: all
all: $(BINS)

.PHONY: install
install:
	$(foreach bin,$(BINS), \
		$(INSTALL) -D -m 0755 $(bin) $(PREFIX)/usr/bin/$(bin);)

.PHONY: clean
clean:
	rm -f $(BINS)
