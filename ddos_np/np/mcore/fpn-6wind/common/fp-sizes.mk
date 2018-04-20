#
# common directives for dumping the shared memory structure
#
all: fp-sizes

OBJ_DIR?=$(CURDIR)

$(OBJ_DIR)/fp-sizes.o: $(DIST_FP)/common/fp-sizes.c
	@[ -d $(OBJ_DIR) ] || mkdir -p $(OBJ_DIR)
	@$(COMPILE.c) -MD $(OUTPUT_OPTION) $<

.PHONY: fp-sizes
fp-sizes: $(OBJ_DIR)/fp-sizes.o
	@echo ---------- fpn struct sizes ------------
	@$(OBJDUMP) -t $< | \
		sed -rne 's/^([^[:space:]]+[[:space:]]+){4}0*([[:xdigit:]]+) +(_OFFSETOF_|_SIZEOF_)(.+)$$/0x\2 \3\4)/; ta' \
			-e 'd; :a' \
			-e 's/_SIZEOF_/sizeof(/' \
			-e 's/_OFFSETOF_/offsetof(/' \
			-e 's/STRUCT_/struct /' \
			-e 's/_FIELD_/->/g' \
			-e 'p' | \
		while read -r size type; \
		do \
			echo "$$type=$$(($$size+0))"; \
		done
	@echo ----------------------------------------

-include $(OBJ_DIR)/fp-sizes.d

clean: clean-fp-sizes

clean-fp-sizes:
	@rm -f $(OBJ_DIR)/fp-sizes.d $(OBJ_DIR)/fp-sizes.o
