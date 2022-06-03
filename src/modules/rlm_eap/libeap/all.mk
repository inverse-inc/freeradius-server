TARGET := libfreeradius-eap.a

SOURCES	:= eapcommon.c eapcrypto.c eap_chbind.c eapsimlib.c fips186prf.c comp128.c
ifneq (${OPENSSL_LIBS},)
SOURCES		+= eap_tls.c mppe_keys.c
endif

SRC_CFLAGS	:= -DEAPLIB

ifneq "$(WITH_CACHE_EAP)" ""
SOURCES		+= serialize.c
TGT_LDLIBS	:= -ljson-c
SRC_CFLAGS  += -DWITH_CACHE_EAP
endif

SRC_INCDIRS	:= . ..
