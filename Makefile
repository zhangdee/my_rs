VER_MAIN = 1

PLATFORM = ti81xx

MAKE = make

COMPILE_PREFIX :=
CC := $(COMPILE_PREFIX)gcc

ALG_DIR = ./reed_solomon
COMMON_DIR = ./common

#FILES = $(subst ./, , $(foreach dir,.,$(wildcard $(dir)/*.c)) )
ALG_FILES = $(wildcard $(ALG_DIR)/*.c)
COMMON_FILES = $(wildcard $(COMMON_DIR)/*.c)
ENC_FILES = $(COMMON_FILES) $(ALG_FILES) ./block_code_enc.c
DEC_FILES = $(COMMON_FILES) $(ALG_FILES) ./block_code_dec.c


# define configs file 
#CONFIGS_DIR = ./configs
#CONFIG_NAMES := $(notdir $(wildcard ./configs/*_defconfig))
#PLATFORMS := $(subst _defconfig,,$(CONFIG_NAMES))
#MAKEFLAGS += --no-print-directory

.PHONY: install libs clean all config platform

help:
	@echo
	@echo "      make all,compile all the files"
	@echo
	@echo "    make libs PLATFORM=xxx; only compile for xxx PLATFORM "
	@echo
	@echo "    make install; install to _install"
	@echo "    "
	@echo "    clean:      : remove all generated files"
	@echo
	
default:help

demo_enc:
	@echo $(ENC_FILES)
	$(CC) ./demo/fec_enc_demo.c $(ENC_FILES) -I$(ALG_DIR) -I$(COMMON_DIR) -DRS_ENCODE -o fec_enc_demo

demo_dec:
	@echo $(DEC_FILES)
	$(CC) ./demo/fec_dec_demo.c $(DEC_FILES) -I$(ALG_DIR) -I$(COMMON_DIR) -DRS_DECODE -o fec_dec_demo


#all:
#	@for dir in $(PLATFORMS);do $(MAKE)  platform PLATFORM=$$dir  CONFIG=$(CONFIG)||exit "$$?"; done


#platform: config
#	$(MAKE)  -fMAKEFILE.MK  -C ./ all
#	$(MAKE)  -fMAKEFILE.MK  -C ./ clean

#install:
#	$(MAKE)  -fMAKEFILE.MK  -C ./ install 

#clean:
#	$(MAKE)  -fMAKEFILE.MK  -C ./ distclean

