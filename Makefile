EXE := enumy

SRC_DIR := src
OBJ_DIR := obj

SRC := $(wildcard $(SRC_DIR)/*.c)
OBJ := $(SRC:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)

CPPFLAGS := -Iinclude
LDFLAGS  := -Llib
LDLIBS := -lm
.PHONY: all clean

all: $(EXE)

$(EXE): $(OBJ)
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@ -g -lncursesw -lpthread -static

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@ -g -lncursesw -lpthread -static

$(OBJ_DIR):
	mkdir $@

clean:
	$(RM) $(OBJ)
