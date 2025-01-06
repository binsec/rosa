TARGETS = $(sort $(dir $(wildcard */)))

all: $(TARGETS)


%/: FORCE
	$(MAKE) -C $@

clean:
	for target_dir in $(TARGETS); do \
		$(MAKE) -C $$target_dir clean; \
	done

FORCE: ;


.PHONY: all clean FORCE
