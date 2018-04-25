

EXEC = $(BIN_PATH)/net_traffic_app
OBJ_FILES = $(wildcard $(OBJ_PATH)/*.o)
COMPILE_PATH = core


all: compile  build


.PHONY:compile
compile: $(COMPILE_PATH)
	@echo "-------compile-----------"
	$(MAKE) -C $^


.PHONY:build
build:
	$(CC) $(LFLAGS) $(CFLAGS) -o $(EXEC) $(OBJ_FILES) $(LIBS)


.PHONY:clean
clean:
	-rm -rf $(OBJ_FILES) $(EXEC)


include make.common
