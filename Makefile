CC=gcc
CFLAGS=-Wall -Wextra

# Detect OS
ifeq ($(OS),Windows_NT)
    OS_TYPE := windows
    EXE_EXT := .exe
else
    UNAME_S := $(shell uname -s)
    ifeq ($(UNAME_S),Linux)
        OS_TYPE := linux
        EXE_EXT :=
    endif
    ifeq ($(UNAME_S),Darwin)
        OS_TYPE := macos
        EXE_EXT :=
    endif
endif

# OS-specific source directories
LINUX_SRC := src/linux_ubuntu_22_04
MACOS_SRC := src/macos
WINDOWS_SRC := src/windows

# Build targets
all: $(OS_TYPE)

linux: clean
    $(CC) $(CFLAGS) $(LINUX_SRC)/network_config.c -o bin/network_config$(EXE_EXT)
    $(CC) $(CFLAGS) $(LINUX_SRC)/logging_auditing.c -o bin/logging_auditing$(EXE_EXT)
    $(CC) $(CFLAGS) $(LINUX_SRC)/access_control.c -o bin/access_control$(EXE_EXT)

macos: clean
    $(CC) $(CFLAGS) $(MACOS_SRC)/network_config.c -o bin/network_config$(EXE_EXT)
    $(CC) $(CFLAGS) $(MACOS_SRC)/logging_auditing.c -o bin/logging_auditing$(EXE_EXT)
    $(CC) $(CFLAGS) $(MACOS_SRC)/access_control.c -o bin/access_control$(EXE_EXT)

windows: clean
    $(CC) $(CFLAGS) $(WINDOWS_SRC)/network_config.c -o bin/network_config$(EXE_EXT)
    $(CC) $(CFLAGS) $(WINDOWS_SRC)/logging_auditing.c -o bin/logging_auditing$(EXE_EXT)
    $(CC) $(CFLAGS) $(WINDOWS_SRC)/access_control.c -o bin/access_control$(EXE_EXT)

clean:
    rm -f bin/*$(EXE_EXT)