# Copyright (c) 2015 Kaarle Ritvanen
# See LICENSE file for license details

ROOT_DIR := /
LUA_VERSION := 5.2
MOD_DIR := $(ROOT_DIR)/usr/share/lua/$(LUA_VERSION)/asn1

all: install

$(MOD_DIR)/%.lua: asn1/%.lua
	install -d $(MOD_DIR)
	install -m 644 $< $@

install: $(foreach f,$(shell find asn1 -name '*.lua'),$(MOD_DIR)/$(notdir $(f)))

.PHONY: all install
