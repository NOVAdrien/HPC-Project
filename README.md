# Parallel Meet-in-the-Middle Attack (MPI + OpenMP)

This project implements a high-performance parallel Meet-in-the-Middle (MITM) attack using a hybrid *MPI + OpenMP* approach on the Grid’5000 platform.

Two execution modes are provided:
1. *Interactive mode*, using a Makefile.
2. *Non-interactive (batch) mode*, using a job.sh script.

---

## Requirements

- Grid’5000 environment
- mpicc (MPI compiler)
- OpenMP support
- OAR job scheduler

---

## 1. Interactive Mode (recommended for testing)

This mode allows you to manually reserve resources and launch experiments interactively.

### 1.1 Reserve resources

Reserve the number of nodes you want using OAR:

bash
oarsub -I -l nodes=<NB_NODES>,walltime=HH:MM:SS


Example:
bash
oarsub -I -l nodes=50,walltime=01:00:00


Once the job starts, you will be connected to a frontend node with access to the allocated compute nodes via $OAR_NODEFILE.

---

### 1.2 Compile the program

Inside the project directory:

bash
make


This compiles the MPI + OpenMP binary:

mitm_mpi_2_block


---

### 1.3 Run the program

Use the Makefile target run and pass runtime parameters via ARGS.

bash
make run ARGS="--n <N> --C0 <KEY0> --C1 <KEY1>"


#### Parameters
- --n : problem size (e.g. 30, 36, 38)
- --C0 : first hexadecimal key
- --C1 : second hexadecimal key

Example:
bash
make run ARGS="--n 30 --C0 f5ab93c4313512dd --C1 33876ac77f205cd5"


#### MPI configuration (interactive mode)
The following parameters can be overridden if needed:
- NP : total number of MPI ranks (default: 18)
- MAP : MPI rank placement (default: ppr:9:node)

Example:
bash
make run NP=100 MAP=ppr:2:node ARGS="--n 36 --C0 ... --C1 ..."


---

## 2. Non-Interactive Mode (Batch execution)

This mode is intended for long experiments and automated runs.

### 2.1 Edit job.sh

The job.sh script controls all execution parameters.

Key variables to configure:

bash
N=38
C0="a9bf4a972ee54312"
C1="1831ee7f563077ed"

PPR=1
export OMP_NUM_THREADS=18


#### Meaning of parameters
- N : size of the MITM instance
- C0, C1 : cryptographic keys
- PPR : number of MPI ranks per node
- OMP_NUM_THREADS : number of OpenMP threads per rank

The total number of MPI ranks is computed automatically as:

NP = number_of_nodes × PPR


---

### 2.2 Submit the job

Make the script executable (once):

bash
chmod +x job.sh


Submit the job:

bash
oarsub -l nodes=<NB_NODES>,walltime=HH:MM:SS ./job.sh


Example:
bash
oarsub -l nodes=50,walltime=01:30:00 ./job.sh


---

## 3. Cleaning the build

To remove the binary and object files:

bash
make clean


---

## Notes

- The application is *memory- and communication-bound*.
- Increasing the number of MPI ranks reduces memory usage per rank but increases communication costs.
- Increasing OpenMP threads beyond a certain point may degrade performance due to memory bandwidth contention.

Choosing the right balance between:
- MPI ranks per node (PPR)
- OpenMP threads per rank (OMP_NUM_THREADS) is essential for optimal performance.

---

## Authors

- Adrien Pangueil
- Karim Hecheime