CONTIKI_PROJECT = eos
CONTIKI = ../..

PROJECT_SOURCEFILES += ecdsa-engine.c 
MODULES_REL += ecdsa-engines ecdsa-engines/sw ecdsa-engines/hw

# Configure the ECDSA software engine for EOS signing
CFLAGS += -DuECC_CURVE=4 #uECC_secp256k1

include $(CONTIKI)/Makefile.identify-target

all: $(CONTIKI_PROJECT)


include $(CONTIKI)/Makefile.include
