# Direct Meet-in-the-Middle Attack (MPI + OpenMP)

## Overview

This project implements a **parallel Meet-in-the-Middle (MITM) attack** for solving the following problem.

We are given two functions and a predicate:

$$
f, g : {0,1}^n -> {0,1}^n
$$

$$
pi : {0,1}^n x {0,1}^n -> {0,1}
$$

The goal is to find a **golden collision** `(x, y)` such that:

$$
f(x) = g(y)
$$

and

$$
pi(x, y) = 1
$$

A naive brute-force approach would require:

$$
2^{2n}
$$

operations.

The Meet-in-the-Middle attack reduces this complexity to approximately:

$$
3 * 2^n
$$

operations, at the cost of:

$$
2^n
$$

words of memory, assuming that the functions behave like random functions.

The objective of this project is to **push the value of `n` as high as possible**, prioritizing scalability over raw execution time, using **MPI (distributed memory)** and **OpenMP (shared memory)** parallelism.

---

## Algorithm

The classical Meet-in-the-Middle algorithm works as follows:

1. Initialize a dictionary `D`
2. For each value `x` in the space `{0,1}^n`, insert the pair:

```

f(x) -> x

````

into the dictionary `D`

3. For each value `y` in the space `{0,1}^n`:
- Retrieve all values `x` such that:

  ```
  f(x) = g(y)
  ```

- For each candidate pair `(x, y)`, test the predicate `pi(x, y)`

4. Return `(x, y)` when the predicate evaluates to true

This approach replaces a quadratic search over all `(x, y)` pairs with two linear passes over the search space.

---

## Parallelization Strategy

### MPI (Distributed Memory)

- The search space `{0,1}^n` is **partitioned across MPI ranks**
- The dictionary is **sharded** using a modulo-based strategy:

$$
destination\_rank = z mod p
$$

- Each MPI process stores only its local shard of the dictionary
- Dictionary construction and probing rely on `MPI_Alltoallv`
- Final results are gathered on rank 0 using `MPI_Gatherv`

This avoids a centralized dictionary and allows the program to scale across multiple compute nodes.

---

### OpenMP (Shared Memory)

- The probing phase is parallelized using **OpenMP**
- Each MPI process uses multiple threads to:
- Probe the local dictionary
- Validate candidate key pairs
- Critical sections are limited to result reservation only

---

### Block Processing

To control memory usage:

- The search space is processed in **fixed-size chunks**
- Dictionary construction and probing are performed block by block
- This ensures bounded memory usage even for large values of `n`

---

## Cryptographic Instance

The provided instance corresponds to a **Double-SPECK64-128 construction**.

The functions are defined as:

$$
f(x) = E(x, P_0)
$$

$$
g(y) = D(y, C_0)
$$

$$
pi(x, y) = [ E(y, E(x, P_1)) = C_1 ]
$$

Where:

- `E` is the SPECK64-128 encryption function
- `D` is the corresponding decryption function
- `(P_0, C_0)` and `(P_1, C_1)` are plaintext–ciphertext pairs

No cryptographic background is required to understand or use the code; the problem can be viewed purely as a **distributed data-structure and search problem**.

---

## Build Instructions

### Requirements

- MPI implementation (`mpicc`, `mpirun`)
- OpenMP support
- C compiler compatible with `-O3 -Wall`

### Compilation

```bash
make
````

This produces the executable:

```bash
mitm_mpi_2_block
```

The code compiles **without warnings** using `-Wall`.

---

## Execution

### Run inside an OAR allocation

```bash
make run ARGS="--n 30 --C0 f5ab93c4313512dd --C1 33876ac77f205cd5"
```

### Parameters

* `--n N`
  Block size (the search space contains `2^n` elements)

* `--C0`
  First ciphertext (hexadecimal)

* `--C1`
  Second ciphertext (hexadecimal)

All arguments are mandatory.

### MPI Configuration (Makefile)

```makefile
NP  ?= 18
MAP ?= ppr:9:node
```

These values can be overridden at runtime if needed.

---

## Output

* Each MPI rank reports its execution time
* The root process gathers and prints:

  * The total number of golden collisions found
  * The corresponding key pairs `(K1, K2)`
* All reported solutions are validated using:

  * `f(K1) = g(K2)`
  * `pi(K1, K2) = 1`

---

## Performance Considerations

* **Main bottleneck**: memory access and dictionary probing
* **MPI communication cost** increases with the number of processes
* **OpenMP scaling** is limited by dictionary contention
* Large values of `n` require:

  * careful tuning of chunk size
  * balanced MPI/OpenMP configuration to avoid oversubscription

Values of `n >= 40` are challenging and require multiple compute nodes.

---

## Project Files

* `mitm_mpi_2_block.c` — main MPI + OpenMP implementation
* `communication.h` — MPI sharded exchange routines
* `utilities.h` — dynamic array utilities
* `Makefile` — build and execution rules
* `README.md` — project documentation

---

## Notes

* Designed for execution on Grid’5000 / OAR clusters
* Large computations should be run at night or on weekends
* The sharded dictionary approach avoids global memory bottlenecks
* The implementation strictly follows MPI initialization and finalization rules

---

## Authors

* Adrien PANGUEL
* Karim HECHEIME

Course: Parallel Programming and Cryptography
Submission deadline: **January 5th, 23:59**


Dis-moi 👍
```
