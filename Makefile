#
TARGETS := xlb

MANAGEMENT_DAEMON := xlbd

CMDLINE_TOOLS := xlb_cmdline
COMMON_H      =  ${CMDLINE_TOOLS:_cmdline=_common.h}

RMI_SOURCES := route.c
RMI_SOURCES += icmp.c
RMI_SOURCES += mac.c
RMI_SOURCES += xlb_util.c
RMI_OBJECTS = ${RMI_SOURCES:.c=.o}

# Generate file name-scheme based on TARGETS
KERN_SOURCES = ${TARGETS:=_kern.c}
USER_SOURCES = ${TARGETS:=_user.c}
KERN_OBJECTS = ${KERN_SOURCES:.c=.o}
USER_OBJECTS = ${USER_SOURCES:.c=.o}

# Notice: the kbuilddir can be redefined on make cmdline
kbuilddir ?= /lib/modules/$(shell uname -r)/build/
KERNEL=$(kbuilddir)

CFLAGS := -g -O2 -Wall

# Local copy of kernel/tools/lib/
#CFLAGS += -I./tools/lib
CFLAGS += -I$(KERNEL)/tools/lib
#
# Local copy of uapi/linux/bpf.h kept under ./tools/include
# needed due to enum dependency in bpf_helpers.h
#CFLAGS += -I./tools/include
# For building libbpf there is a lot of kernel includes in tools/include/
CFLAGS += -I$(KERNEL)/tools/include
CFLAGS += -I$(KERNEL)/tools/perf
CFLAGS += -I$(KERNEL)/usr/include
# Strange dependency to "selftests" due to "bpf_util.h"
#CFLAGS += -I$(KERNEL)/tools/testing/selftests/bpf/

LDFLAGS= -lelf

# Objects that xxx_user program is linked with:
OBJECT_BPF_SYSCALLS  = tools/lib/bpf/bpf.o
OBJECT_LOADBPF = bpf_load.o
OBJECTS = $(OBJECT_BPF_SYSCALLS) $(OBJECT_LOADBPF)
#
# The tools/lib/bpf/libbpf is avail via a library
OBJECT_BPF_LIBBPF  = tools/lib/bpf/libbpf.o

# Allows pointing LLC/CLANG to another LLVM backend, redefine on cmdline:
#  make LLC=~/git/llvm/build/bin/llc CLANG=~/git/llvm/build/bin/clang
LLC ?= llc
CLANG ?= clang

CC = gcc

NOSTDINC_FLAGS := -nostdinc -isystem $(shell $(CC) -print-file-name=include)

# Copy of uapi/linux/bpf.h stored here:

LINUXINCLUDE := -I$(KERNEL)/arch/x86/include
LINUXINCLUDE += -I$(KERNEL)/arch/x86/include/generated/uapi
LINUXINCLUDE += -I$(KERNEL)/arch/x86/include/generated
LINUXINCLUDE += -I$(KERNEL)/include
LINUXINCLUDE += -I$(KERNEL)/arch/x86/include/uapi
LINUXINCLUDE += -I$(KERNEL)/include/uapi
LINUXINCLUDE += -I$(KERNEL)/include/generated/uapi
LINUXINCLUDE += -include $(KERNEL)/include/linux/kconfig.h
LINUXINCLUDE += -I$(KERNEL)/tools/lib

#LINUXINCLUDE += -I./tools/include/

#EXTRA_CFLAGS=-Werror
EXTRA_CFLAGS= -D__BPF_TRACING__

all: dependencies $(TARGETS) $(KERN_OBJECTS) $(CMDLINE_TOOLS) $(MANAGEMENT_DAEMON)

.PHONY: dependencies clean verify_cmds verify_llvm_target_bpf $(CLANG) $(LLC)

# Manually define dependencies to e.g. include files
napi_monitor:        napi_monitor.h
napi_monitor_kern.o: napi_monitor.h

clean:
	@find . -type f \
		\( -name '*~' \
		-o -name '*.ll' \
		-o -name '*.bc' \
		-o -name 'core' \) \
		-exec rm -vf '{}' \;
	rm -f $(OBJECTS)
	rm -f $(TARGETS)
	rm -f $(KERN_OBJECTS)
	rm -f $(USER_OBJECTS)
	rm -f $(RMI_OBJECTS)
	rm -f $(OBJECT_BPF_LIBBPF) libbpf.a

dependencies: verify_llvm_target_bpf linux-src-devel-headers

linux-src:
	@if ! test -d $(KERNEL)/; then \
		echo "ERROR: Need kernel source code to compile against" ;\
		echo "(Cannot open directory: $(KERNEL))" ;\
		exit 1; \
	else true; fi

linux-src-libbpf: linux-src
	@if ! test -d $(KERNEL)/tools/lib/bpf/; then \
		echo "ERROR: Need kernel source code to compile against" ;\
		echo "       and specifically tools/lib/bpf/ "; \
		exit 1; \
	else true; fi

linux-src-devel-headers: linux-src-libbpf
	@if ! test -d $(KERNEL)/usr/include/ ; then \
		echo -n "WARNING: Need kernel source devel headers"; \
		echo    " likely need to run:"; \
		echo "       (in kernel source dir: $(KERNEL))"; \
		echo -e "\n  make headers_install\n"; \
		true ; \
	else true; fi

verify_cmds: $(CLANG) $(LLC)
	@for TOOL in $^ ; do \
		if ! (which -- "$${TOOL}" > /dev/null 2>&1); then \
			echo "*** ERROR: Cannot find LLVM tool $${TOOL}" ;\
			exit 1; \
		else true; fi; \
	done

verify_llvm_target_bpf: verify_cmds
	@if ! (${LLC} -march=bpf -mattr=help > /dev/null 2>&1); then \
		echo "*** ERROR: LLVM (${LLC}) does not support 'bpf' target" ;\
		echo "   NOTICE: LLVM version >= 3.7.1 required" ;\
		exit 2; \
	else true; fi

# Helpers for bpf syscalls (from tools/lib/bpf/bpf.c)
$(OBJECT_BPF_SYSCALLS): %.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $<

$(OBJECT_LOADBPF): bpf_load.c bpf_load.h
	$(CC) $(CFLAGS) -o $@ -c $<

# ISSUE: The libbpf.a library creates a kernel source dependency, for
# include files from tools/include/
$(OBJECT_BPF_LIBBPF): %.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $<
#
libbpf.a: $(OBJECT_BPF_LIBBPF) $(OBJECT_BPF_SYSCALLS)
	$(RM) $@; $(AR) rcs $@ $^

# Compiling of eBPF restricted-C code with LLVM
#  clang option -S generated output file with suffix .ll
#   which is the non-binary LLVM assembly language format
#   (normally LLVM bitcode format .bc is generated)
#
# Use -Wno-address-of-packed-member as eBPF verifier enforces
# unaligned access checks where necessary
#
$(KERN_OBJECTS): %.o: %.c bpf_helpers.h
	$(CLANG) -S $(NOSTDINC_FLAGS) $(LINUXINCLUDE) $(EXTRA_CFLAGS) \
	    -D__KERNEL__ -D__ASM_SYSREG_H \
	    -Wall \
	    -Wno-unused-value -Wno-pointer-sign \
	    -D__TARGET_ARCH_$(ARCH) \
	    -Wno-compare-distinct-pointer-types \
	    -Wno-gnu-variable-sized-type-not-at-end \
	    -Wno-tautological-compare \
	    -Wno-unknown-warning-option \
	    -Wno-address-of-packed-member \
	    -O2 -emit-llvm -c $<
	$(LLC) -march=bpf -filetype=obj -o $@ ${@:.o=.ll}

$(TARGETS): %: %_user.c $(OBJECTS) Makefile
	$(CC) $(CFLAGS) $(OBJECTS) $(LDFLAGS) -o $@ $<

$(CMDLINE_TOOLS): %: %.c $(OBJECTS) Makefile $(COMMON_H) $(RMI_OBJECTS) rmi.h
	$(CC) -g $(CFLAGS) $(OBJECTS) $(RMI_OBJECTS) $(LDFLAGS) -o $@ $<

$(MANAGEMENT_DAEMON): %: %.c $(OBJECTS) Makefile $(COMMON_H) $(RMI_OBJECTS) rmi.h
	$(CC) -g $(CFLAGS) $(OBJECTS) $(RMI_OBJECTS) $(LDFLAGS) -o $@ $< -lyaml
