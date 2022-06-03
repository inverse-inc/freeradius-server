TARGETNAME	:= rlm_eap_ttls

ifneq "$(OPENSSL_LIBS)" ""
TARGET		:= $(TARGETNAME).a
endif

SOURCES		:= $(TARGETNAME).c ttls.c

SRC_CFLAGS	:=

ifneq "$(WITH_CACHE_EAP)" ""
SRC_CFLAGS  += -DWITH_CACHE_EAP
endif

SRC_INCDIRS	:= ../../ ../../libeap/
TGT_PREREQS	:= libfreeradius-eap.a
