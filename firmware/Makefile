# Three build axes, all of which the campaign consumes:
#   TARGET  = secureboot | supervisor   (security oracle vs safety oracle)
#   VARIANT = base | hardened           (countermeasures off/on)
#   OPT     = -O0 | -O2 | -Os           (the compiler study)
#
# `make matrix` builds the full cross product. Run the SAME campaign against
# every binary. The -O sweep is not incidental: showing the optimiser deleting
# countermeasures is one of the strongest results in this project.

CROSS   ?= arm-none-eabi-
CC      := $(CROSS)gcc
OBJCOPY := $(CROSS)objcopy
OBJDUMP := $(CROSS)objdump

TARGET  ?= secureboot
VARIANT ?= base
OPT     ?= -O2

ARCH    := -mcpu=cortex-m3 -mthumb
BUILD   := build/$(TARGET)-$(VARIANT)$(OPT)

CFLAGS  := $(ARCH) $(OPT) -g3 -ffreestanding -fno-builtin -fno-common \
           -fno-stack-protector -Wall -Wextra -Icommon -Icrypto
LDFLAGS := $(ARCH) -nostdlib -nostartfiles -T common/link_cm3.ld \
           -Wl,--gc-sections -Wl,-Map=$(BUILD)/fw.map

SRCS := common/startup_cm3.c common/oracle.c common/minilib.c

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
	  $(MAKE) --no-print-directory TARGET=$$t VARIANT=$$v OPT=$$o || exit 1; \
	done; done; done
	@echo "built:"; ls -d build/*

clean:
	rm -rf build
.PHONY: all clean matrix
