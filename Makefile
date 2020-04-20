EXE := enumy

SRC_DIR := src
OBJ_DIR := obj

SRC := $(wildcard $(SRC_DIR)/*.c)
OBJ := $(SRC:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)

CPPFLAGS := -Iinclude -lcap
LDFLAGS  := -Llib -lcap
LDLIBS := -lncursesw -lpthread -lm -lcap
CFLAGS := -W 

.PHONY: all clean

all: $(EXE)

$(EXE): $(OBJ)
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@ -lncursesw -lpthread $(STATIC) $(ARCH) -s

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@ -lncursesw -lpthread $(STATIC) $(ARCH) -s

$(OBJ_DIR):
	mkdir $@

clean:
	$(RM) $(OBJ)
