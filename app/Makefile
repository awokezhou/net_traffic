
MAKE_PART = core


.PHONY: $(MAKE_PART)
all: $(MAKE_PART)


$(MAKE_PART):
	$(MAKE) -C $@


clean:
	for dir in $(MAKE_PART); do \
		$(MAKE) -C $$dir clean; \
	done


include make.common