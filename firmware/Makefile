# Four build axes, all of which the campaign consumes:
#   TARGET  = secureboot | supervisor   (security oracle vs safety oracle)
#   VARIANT = base | hardened           (countermeasures off/on)
#   OPT     = -O0 | -O2 | -Os           (the compiler study)
#   ISA     = cm3 | rv32                (the architecture-independence claim)
#
# `make matrix` builds the full cross product for the default ISA. The -O sweep
# is not incidental: showing the optimiser deleting countermeasures is one of
# the strongest results in this project.
#
# ISA=cm3 build paths are deliberately UNSUFFIXED (build/secureboot-base-O2 and
# so on). The determinism and regression gates reference those paths literally,
# and the whole regression-baseline table is keyed to them -- renaming them to
# add an architecture tag would silently break both gates and invalidate every
# number in RESULTS.md's comparison table. rv32 gets the suffix instead.

TARGET  ?= secureboot
VARIANT ?= base
OPT     ?= -O2
ISA     ?= cm3

ifeq ($(ISA),rv32)
CROSS        ?= riscv64-unknown-elf-
# rv32i, no compressed instructions: every instruction is exactly 4 bytes,
# which keeps "skip k instructions" an unambiguous fault model rather than one
# whose byte width depends on which instructions happen to be at the trigger.
# Thumb-2 already forced that complexity on the Cortex-M side (see
# _skip_bytes in the backend); there is no reason to import it here too.
ARCH         := -march=rv32i -mabi=ilp32
LDSCRIPT     := common/link_rv32.ld
STARTUP      := common/startup_rv32.c
BUILD_SUFFIX := -rv32
else
CROSS        ?= arm-none-eabi-
ARCH         := -mcpu=cortex-m3 -mthumb
LDSCRIPT     := common/link_cm3.ld
STARTUP      := common/startup_cm3.c
BUILD_SUFFIX :=
endif

CC      := $(CROSS)gcc
OBJCOPY := $(CROSS)objcopy
OBJDUMP := $(CROSS)objdump

BUILD   := build/$(TARGET)-$(VARIANT)$(OPT)$(BUILD_SUFFIX)

CFLAGS  := $(ARCH) $(OPT) -g3 -ffreestanding -fno-builtin -fno-common \
           -fno-stack-protector -Wall -Wextra -Icommon -Icrypto
LDFLAGS := $(ARCH) -nostdlib -nostartfiles -T $(LDSCRIPT) \
           -Wl,--gc-sections -Wl,-Map=$(BUILD)/fw.map

SRCS := $(STARTUP) common/oracle.c common/minilib.c

ifeq ($(TARGET),secureboot)
SRCS += secureboot/main.c crypto/sha256.c
ifeq ($(VARIANT),hardened)
SRCS   += secureboot/verify_hardened.c
CFLAGS += -DUSE_HARDENED=1
else
SRCS   += secureboot/verify.c
endif
else
SRCS += supervisor/main.c supervisor/safety.c
ifeq ($(VARIANT),hardened)
CFLAGS += -DUSE_HARDENED=1
endif
endif

OBJS := $(SRCS:%.c=$(BUILD)/%.o)

all: $(BUILD)/fw.elf $(BUILD)/fw.bin $(BUILD)/fw.lst

$(BUILD)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/fw.elf: $(OBJS)
	$(CC) $(OBJS) $(LDFLAGS) -o $@

$(BUILD)/fw.bin: $(BUILD)/fw.elf
	$(OBJCOPY) -O binary $< $@

# Open the hardened -O2 listing and confirm the duplicated checks appear TWICE.
# If the optimiser folded them, the countermeasure does not exist.
$(BUILD)/fw.lst: $(BUILD)/fw.elf
	$(OBJDUMP) -d -S $< > $@

matrix:
	@for t in secureboot supervisor; do for v in base hardened; do for o in -O0 -O2 -Os; do \
	  $(MAKE) --no-print-directory TARGET=$$t VARIANT=$$v OPT=$$o ISA=$(ISA) || exit 1; \
	done; done; done
	@echo "built:"; ls -d build/*

# Same cross product on RV32. Separate target rather than folded into `matrix`
# so the Cortex-M gates stay runnable on a machine with only the ARM toolchain.
matrix-rv32:
	@$(MAKE) --no-print-directory matrix ISA=rv32

clean:
	rm -rf build
.PHONY: all clean matrix
