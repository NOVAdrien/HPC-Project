# Paramètres
CC = gcc
CFLAGS = -std=gnu11 -O3 -march=native -Wall -Wextra -pipe

SRC_DIR = src
BUILD_DIR = builds

# Sources et objets
SRC = $(SRC_DIR)/mitm.c
OBJ = $(BUILD_DIR)/mitm.o

# Nom du fichier
TARGET = mitm

.PHONY: all clean run

# Compilation complète
all: $(TARGET)

# Création de l'exécutable
$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^

# Compilation d'un .c vers un .o dans builds/
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

# Nettoyage
clean:
	rm -f $(BUILD_DIR)/*.o $(TARGET)

# Exécution selon les paramètres sur le site : https://ppar.tme-crypto.fr/<username>/<n>
run: $(TARGET)
	./$(TARGET) --n 20 --C0 ab608b105290528d --C1 03abc7b389f440ed
