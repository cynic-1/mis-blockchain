#CFLAGS += -L/usr/local/ssl/lib/ -I./lib -g
CFLAGS += -I./lib -g
LDFLAGS += TCMALG.a -L. -lftddl -g

CC = gcc
DEFS += -DTCM_POSIX=1 
DIR_OUT := out
DIR_LIB := lib
DIR_UTILS := tcmutils
TCMLIB := TCMLIB.a

SRC = ./main.c ./bridge.c
OBJ = $(patsubst %.c, %.o,$(SRC))

SRC_LIB = $(wildcard ./lib/*.c)
OBJ_LIB = $(patsubst %.c, %.o,$(SRC_LIB))

main: $(OBJ_LIB) $(OBJ) $(TCMLIB)
	$(CC) $(OBJ) $(TCMLIB) $(LDFLAGS) $(DEFS) -o main

$(TCMLIB) : $(OBJ_LIB)
	ar -r $(TCMLIB) $(OBJ_LIB)

$(OBJ_LIB): %.o: %.c
	$(CC) $(DEFS) $(CFLAGS) -c $< -o $@ 

$(OBJ) : %.o: %.c
	$(CC) $(DEFS) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(OBJ_LIB) main

test:
	@echo ${CFLAGS}
	@echo ${LDFLAGS}
	@echo ${OBJ}
	@echo ${SRC_LIB}
	@echo ${OBJ_LIB}
