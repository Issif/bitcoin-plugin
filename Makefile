#
# Copyright (C) 2023 Thomas Labarussias.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
# the License. You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.
#

SHELL=/bin/bash -o pipefail
GO ?= go

NAME := bitcoin
OUTPUT := lib$(NAME).so
# DESTDIR := /usr/share/falco/plugins
DESTDIR := .

ifeq ($(DEBUG), 1)
    GODEBUGFLAGS= GODEBUG=cgocheck=2
else
    GODEBUGFLAGS= GODEBUG=cgocheck=0
endif

all: build

clean:
	@rm -f lib$(NAME).so

build: clean
	@$(GODEBUGFLAGS) $(GO) build -buildmode=c-shared -buildvcs=false -o $(OUTPUT) ./plugin

install: build
	mv $(OUTPUT) $(DESTDIR)/
