TARGETNAME	:= rlm_eap_md5

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME).a
endif

SOURCES		:= $(TARGETNAME).c eap_md5.c

SRC_CFLAGS	:=

ifneq "$(WITH_CACHE_EAP)" ""
SRC_CFLAGS  += -DWITH_CACHE_EAP
endif

TGT_LDLIBS	:=
SRC_INCDIRS	:= ../../ ../../libeap/
TGT_PREREQS	:= libfreeradius-eap.a
