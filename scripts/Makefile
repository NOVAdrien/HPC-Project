# ======================
# Compiler and options
# ======================

MPICC      = mpicc
CFLAGS     = -O3 -Wall -fopenmp
LDFLAGS    = -fopenmp

# ======================
# Program
# ======================

TARGET     = mitm_mpi_2_block
SRC        = mitm_mpi_2_block.c
HEADERS    = communication.h utilities.h

# ======================
# MPI execution (optionnal)
# ======================

NP         ?= 18
MAP        ?= ppr:9:node
RUN        = mpirun -machinefile $$OAR_NODEFILE -np $(NP) --map-by $(MAP)

# ======================
# Rules
# ======================

all: $(TARGET)

$(TARGET): $(SRC) $(HEADERS)
        $(MPICC) $(CFLAGS) $(SRC) -o $@ $(LDFLAGS)

run: $(TARGET)