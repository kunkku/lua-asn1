# Copyright (c) 2015-2025 Kaarle Ritvanen
# See LICENSE file for license details

ROOT_DIR := /
MOD_DIR := $(ROOT_DIR)/usr/share/lua/common/asn1

all: install

$(MOD_DIR)/%.lua: asn1/%.lua
	install -d $(MOD_DIR)
	install -m 644 $< $@

install: $(foreach f,$(shell find asn1 -name '*.lua'),$(MOD_DIR)/$(notdir $(f)))

.PHONY: all install
