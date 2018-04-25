
SRC_FILES = $(wildcard *.c)
OBJ_FILES = $(patsubst %.c, $(OBJ_PATH)/%.o, $(SRC_FILES))

all: $(OBJ_FILES)

$(OBJ_FILES): $(OBJ_PATH)/%.o : %.c
	$(CC) $(CFLAGS) -c $< -o $@
	
include $(APP_PATH)/make.common

