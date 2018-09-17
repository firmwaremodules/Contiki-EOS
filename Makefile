CONTIKI_PROJECT = eos
CONTIKI = ../..

PROJECT_SOURCEFILES += ecdsa-engine.c uecc.c uecc-test-ecdsa.c
MODULES_REL += ecdsa-engines ecdsa-engines/sw

# Configure the ECDSA software engine for EOS signing
CFLAGS += -DuECC_CURVE=4 #uECC_secp256k1

include $(CONTIKI)/Makefile.identify-target

all: $(CONTIKI_PROJECT)


include $(CONTIKI)/Makefile.include
