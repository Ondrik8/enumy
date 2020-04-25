EXE := enumy

SRC_DIR := src
SCAN_DIR := src/scans
OBJ_DIR := obj
OBJ_SCAN_DIR := obj

SRC := $(wildcard $(SRC_DIR)/*.c)
OBJ := $(SRC:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)

SRC_SCAN := $(wildcard $(SCAN_DIR)/*.c)
OBJ_SCAN := $(SRC_SCAN:$(SCAN_DIR)/%.c=$(OBJ_SCAN_DIR)/%.o)

CPPFLAGS := -Iinclude -lcap
LDFLAGS  := -Llib -lcap
LDLIBS := -lncursesw -lpthread -lm -lcap
CFLAGS := -W 

.PHONY: all clean

all: $(EXE)

$(EXE): $(OBJ) $(OBJ_SCAN)
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@ -lncursesw -lpthread $(STATIC) $(ARCH) 

$(EXE_SCAN): $(OBJ_SCAN)
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@ -lncursesw -lpthread $(STATIC) $(ARCH) 
	
$(OBJ_SCAN_DIR)/%.o: $(SCAN_DIR)/%.c | $(OBJ_SCAN_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@ -lncursesw -lpthread $(STATIC) $(ARCH) 

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@ -lncursesw -lpthread $(STATIC) $(ARCH) -g -pg

$(OBJ_DIR):
	mkdir $@

clean:
	$(RM) $(OBJ) $(OBJ_SCAN)

.PHONY: cov

cov: 
	make clean 
	cov-build --dir cov-int make 
	tar czvf enumy-cov.tgz cov-int
	echo curl --form token=`cat cov-token` \
	--form email=`cat email` \
	--form file=@enumy-cov.tgz\
	--form version="Version" \
	--form description="Description" \
	https://scan.coverity.com/builds?project=luke-goddard%2Fenumy
