
NT_OBJ_PATH := $(APP_PATH)/obj
NT_BIN_PATH := $(APP_PATH)/bin
NT_LIB_PATH := $(APP_PATH)/lib

SOURCE_FILES = $(wildcard *.c)
OBJ_FILES := $(patsubst %.c,%.o,$(SOURCE_FILES))
OBJS := $(wildcard $(NT_OBJ_PATH)/*.o)
NT_BIN_NAME = net_traffic_main
EXE := $(NT_BIN_PATH)/$(NT_BIN_NAME)

LDFLAGS += -ffunction-sections -Wl,--gc-sections 

all:$(EXE)
$(EXE):$(OBJ_FILES) $(OBJS)
	$(CC) $(LDFLAGS) $^ -L$(NT_LIB_PATH) $(LIBS) -o $@ -lm

$(OBJ_FILES):%.o : %.c
	$(CC) $(CFLAGS) -c $<  -o $@ 


.PHONY:clean
clean:
	rm -rf $(EXE) $(OBJ_FILES) $(OBJS)

	
include $(APP_PATH)/make.common

