TARGET = clens
#CC = gcc

# Source files
C_SRC  = $(wildcard *.c)
C_SRC += $(wildcard filters/*.c)
C_SRC += $(wildcard pkts/*.c)

OBJDIR = build
$(shell mkdir -p $(OBJDIR) >/dev/null)
OBJECTS = $(C_SRC:%.c=$(OBJDIR)/%.o)

# Compiler flags
INC = -I. -I/usr/include/libusb-1.0/

CFLAGS = -std=gnu99 -ggdb3 -Og -rdynamic
CFLAGS += $(INC)
CFLAGS += -Wall -Wextra -Werror -Wno-unused-parameter
CFLAGS += -D_POSIX_C_SOURCE=201702 -D_GNU_SOURCE
LFLAGS = -L /usr/lib -lcgraph -lusb-1.0
LFLAGS = -L /usr/lib -lcgraph

# File dependency generation
DEPDIR = .deps
$(shell mkdir -p $(DEPDIR) >/dev/null)
DEPS = $(OBJECTS:$(OBJDIR)/%.o=$(DEPDIR)/%.d)
-include $(DEPS)
$(DEPDIR)/%.d : %.c .deps
	@mkdir -p $(dir $@)
	@$(CC) $(CFLAGS) $< -MM -MT $(@:$(DEPDIR)/%.d=%.o) >$@

# Targets
$(TARGET): $(OBJECTS) libdill/.libs/libdill.a
	$(CC) $(CFLAGS) -o $@ $+ $(LFLAGS)

$(OBJDIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(APP_INC) -c -o $@ $<

libdill/.libs/libdill.a:
	$(MAKE) -C libdill

.PHONY: all
all: $(TARGET)

.PHONY: clean
clean:
	-rm -f $(TARGET) tags
	-rm -rf $(OBJDIR) $(DEPDIR)

tags: $(C_SRC)
	ctags -R .

.DEFAULT_GOAL := all
