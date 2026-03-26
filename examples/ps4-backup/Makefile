LIBPS4      := ../../libPS4

CC          := gcc
OBJCOPY     := objcopy
ODIR        := build
SDIR        := source
IDIRS       := -I$(LIBPS4)/include -Iinclude
LDIRS       := -L$(LIBPS4)
MAPFILE     := $(shell basename "$(CURDIR)").map

# أضفنا -g هنا لتمكين معلومات التصحيح لـ GDB
CFLAGS      := $(IDIRS) -Os -g -std=c11 -ffunction-sections -fdata-sections -fno-builtin -nostartfiles -nostdlib -Wall -Wextra -masm=intel -march=btver2 -mtune=btver2 -m64 -mabi=sysv -mcmodel=small -fpie -fPIC
LFLAGS      := $(LDIRS) -Xlinker -T $(LIBPS4)/linker.x -Xlinker -Map="$(MAPFILE)" -Wl,--build-id=none -Wl,--gc-sections
CFILES      := $(wildcard $(SDIR)/*.c)
SFILES      := $(wildcard $(SDIR)/*.s)
OBJS        := $(patsubst $(SDIR)/%.c, $(ODIR)/%.o, $(CFILES)) $(patsubst $(SDIR)/%.s, $(ODIR)/%.o, $(SFILES))

LIBS        := -lPS4

# أسماء الملفات النهائية
PROJ_NAME   := $(shell basename "$(CURDIR)")
TARGET_BIN  := $(PROJ_NAME).bin
TARGET_ELF  := $(PROJ_NAME).elf

all: $(TARGET_BIN)

$(TARGET_BIN): $(TARGET_ELF)
	$(OBJCOPY) -O binary $(TARGET_ELF) $(TARGET_BIN)

$(TARGET_ELF): $(ODIR) $(OBJS)
	# هنا نقوم بإنشاء ملف ELF الحقيقي بدلاً من ملف مؤقت
	$(CC) -fuse-ld=gold $(LIBPS4)/crt0.s $(ODIR)/*.o -o $(TARGET_ELF) $(CFLAGS) $(LFLAGS) $(LIBS)

$(ODIR)/%.o: $(SDIR)/%.c
	$(CC) -c -o $@ $< $(CFLAGS)

$(ODIR)/%.o: $(SDIR)/%.s
	$(CC) -c -o $@ $< $(CFLAGS)

$(ODIR):
	@mkdir $@

.PHONY: clean

clean:
	rm -rf $(TARGET_BIN) $(TARGET_ELF) $(MAPFILE) $(ODIR)
