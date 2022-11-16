CFLAGS +=-L/usr/local/ssl/lib/ -I./lib -g
LDFLAGS += TCMALG.a -L. -lftddl -g

CC = gcc
DEFS += -DTCM_POSIX=1 
DIR_OUT := out
DIR_LIB := lib
DIR_UTILS := tcmutils
TCMLIB := TCMLIB.a

#SRC_FILES = $(wildcard ${DIR_LIB}/*.c), $(wildcard ${DIR_UTILS}/*.c)
#SRC_UTILS = ${DIR_UTILS}/test_startup.c ${DIR_UTILS}/test_physical_enable.c ${DIR_UTILS}/test_set_activate.c ${DIR_UTILS}/test_force_clear.c \
#			${DIR_UTILS}/test_get_pubek.c ${DIR_UTILS}/test_takeownership.c ${DIR_UTILS}/test_ownerclear.c ${DIR_UTILS}/test_ap.c \
#			${DIR_UTILS}/test_getcapability.c ${DIR_UTILS}/test_createkey.c ${DIR_UTILS}/test_loadkey.c ${DIR_UTILS}/test_getpubkey.c \
#			${DIR_UTILS}/test_evictkey.c	${DIR_UTILS}/test_sign.c ${DIR_UTILS}/test_pcr.c
SRC_UTILS = ${DIR_UTILS}/test_getcapability.c 

OBJ_UTILS = $(patsubst ${DIR_UTILS}/%.c,${DIR_OUT}/%.o, ${SRC_UTILS}) 
BIN = $(patsubst ${DIR_UTILS}/%.c,${DIR_OUT}/%, ${SRC_UTILS}) 

SRC_LIB_ALL = $(wildcard ${DIR_LIB}/*.c)
#SRC_LIB = $(filter-out ${DIR_LIB}/crypto.c ${DIR_LIB}/keys.c ${DIR_LIB}/pcrs.c ${DIR_LIB}/serialize.c ${DIR_LIB}/tcm_marshalling.c, $(SRC_LIB_ALL))
# SRC_LIB = $(filter-out ${DIR_LIB}/crypto.c  ${DIR_LIB}/pcrs.c , $(SRC_LIB_ALL))
SRC_LIB = $(SRC_LIB_ALL)

OBJ_LIB = $(patsubst ${DIR_LIB}/%.c,${DIR_OUT}/%.o, ${SRC_LIB}) 

all:$(DIR_OUT) $(BIN)

$(DIR_OUT): 
	mkdir -p $(DIR_OUT)

$(BIN):$(DIR_OUT)/%:$(DIR_OUT)/%.o $(OBJ_UTILS) $(TCMLIB)
	$(CC) $< $(TCMLIB) $(LDFLAGS) $(DEFS) -o $@

$(TCMLIB):$(OBJ_LIB)
	ar  -r $(TCMLIB) $(OBJ_LIB)

$(OBJ_LIB):${DIR_OUT}/%.o:${DIR_LIB}/%.c
	$(CC) $(DEFS) $(CFLAGS) -c $< -o $@ 

$(OBJ_UTILS):${DIR_OUT}/%.o:${DIR_UTILS}/%.c
	$(CC) $(DEFS) $(CFLAGS) -c $< -o $@ 

test:
	echo ${BIN}

clean:
	rm -rf $(DIR_OUT)/*.o $(TCMLIB) 
#!pubek !SM2_Signing.key

.PHONY:all clean




