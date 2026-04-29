PREFIX  ?= /usr/local
BINDIR   = $(PREFIX)/bin

CC      ?= cc
PKG_CONFIG ?= pkg-config

CFLAGS  ?= -O2 -g
CFLAGS  += -std=c11 -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wno-sign-conversion \
           -Wstrict-prototypes -Wmissing-prototypes -Wno-unused-parameter \
           -fstack-protector-strong -D_FORTIFY_SOURCE=2

CFLAGS  += $(shell $(PKG_CONFIG) --cflags libsodium libcurl)
LDLIBS  += $(shell $(PKG_CONFIG) --libs libsodium libcurl)

# Hardening flags: GNU-ld-only on Linux, no-op on macOS / BSD.
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
  CFLAGS  += -fPIE
  LDFLAGS += -Wl,-z,now -Wl,-z,relro -pie -fPIE
endif

SRC_DIR   = src
CMD_DIR   = src/commands
BUILD_DIR = build
BIN       = $(BUILD_DIR)/vid-transfer

CORE_SRC = \
    $(SRC_DIR)/util.c \
    $(SRC_DIR)/secure_mem.c \
    $(SRC_DIR)/base58.c \
    $(SRC_DIR)/crypto.c \
    $(SRC_DIR)/keypair.c \
    $(SRC_DIR)/pairing.c \
    $(SRC_DIR)/bip39_wordlist.c \
    $(SRC_DIR)/relay.c \
    $(SRC_DIR)/solana_rpc.c \
    $(SRC_DIR)/tower.c \
    $(SRC_DIR)/bundle.c

CMD_SRC = \
    $(CMD_DIR)/cmd_init.c \
    $(CMD_DIR)/cmd_doctor.c \
    $(CMD_DIR)/cmd_status.c \
    $(CMD_DIR)/cmd_send.c \
    $(CMD_DIR)/cmd_receive.c \
    $(CMD_DIR)/cmd_swap.c

ALL_SRC = $(CORE_SRC) $(CMD_SRC) $(SRC_DIR)/main.c
OBJ     = $(ALL_SRC:%.c=$(BUILD_DIR)/%.o)

.PHONY: all clean install uninstall debug release tidy
.DEFAULT_GOAL := all

all: $(BIN)

debug: CFLAGS += -O0 -DDEBUG -fsanitize=address,undefined
debug: LDFLAGS += -fsanitize=address,undefined
debug: $(BIN)

release: CFLAGS := -O3 -DNDEBUG $(filter-out -O2 -g,$(CFLAGS))
release: $(BIN)

$(BIN): $(OBJ) | $(BUILD_DIR)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)
	@echo "Built: $@"

$(BUILD_DIR)/%.o: %.c | $(BUILD_DIR)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)

clean:
	rm -rf $(BUILD_DIR)

install: $(BIN)
	install -d $(DESTDIR)$(BINDIR)
	install -m 0755 $(BIN) $(DESTDIR)$(BINDIR)/vid-transfer

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/vid-transfer

tidy:
	@echo "Re-formatting (clang-format if available)..."
	@command -v clang-format >/dev/null && find $(SRC_DIR) -name '*.[ch]' -exec clang-format -i {} + || echo "clang-format not installed; skipped"
