CMD_CLANG ?= clang
CMD_GO ?= go
CMD_RM ?= rm

.PHONY: all
all: ebpf assets build
	@echo $(shell date)

.PHONY: clean
clean:
	$(CMD_RM) -f app/bytecode/*.d
	$(CMD_RM) -f app/bytecode/*.o
	$(CMD_RM) -f assets/ebpf_probe.go
	$(CMD_RM) -f bin/estrace

.PHONY: ebpf
ebpf:
	clang \
	--target=bpf \
	-c \
	-nostdlibinc \
	-no-canonical-prefixes \
	-O2 \
	-isystem external/bionic/libc/include \
	-isystem external/bionic/libc/kernel/uapi \
	-isystem external/bionic/libc/kernel/uapi/asm-arm64 \
	-isystem external/bionic/libc/kernel/android/uapi \
	-I       external/system/core/libcutils/include \
	-I       external/libbpf/src \
	-g \
	-MD -MF app/bytecode/raw_syscalls.d \
	-o app/bytecode/raw_syscalls.o \
	src/raw_syscalls.c

.PHONY: assets
assets:
	$(CMD_GO) run github.com/shuLhan/go-bindata/cmd/go-bindata -pkg assets -o "app/assets/ebpf_probe.go" $(wildcard ./app/bytecode/*.o app/config/table.json)

.PHONY: build
build:
	GOARCH=arm64 GOOS=android CGO_ENABLED=1 CC=aarch64-linux-android29-clang $(CMD_GO) build -ldflags "-w -s" -o bin/estrace .