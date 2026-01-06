# include <inttypes.h>
# include <stdbool.h>
# include <stdio.h>
# include <stdlib.h>
# include <sys/time.h>
# include <assert.h>
# include <getopt.h>
# include <err.h>
# include <assert.h>

# include <mpi.h>
# include <omp.h>

# include "communication.h"
# include "utilities.h"

typedef uint64_t u64;       /* portable 64-bit integer */
typedef uint32_t u32;       /* portable 32-bit integer */
struct __attribute__ ((packed)) entry { u32 k; u64 v; };  /* hash table entry */

/***************************** global variables ******************************/

u64 n = 0;         /* block size (in bits) */
u64 mask;          /* this is 2**n - 1 */

u64 dict_size;     /* number of slots in the hash table */
struct entry *A;   /* the hash table */

/* (P, C) : two plaintext-ciphertext pairs */
u32 P[2][2] = {{0, 0}, {0xffffffff, 0xffffffff}};
u32 C[2][2];

/************************ tools and utility functions *************************/

double wtime()
{
	struct timeval ts;
	gettimeofday(&ts, NULL);

	return (double)ts.tv_sec + ts.tv_usec / 1E6;
}

// murmur64 hash functions, tailorized for 64-bit ints / Cf. Daniel Lemire
u64 murmur64(u64 x)
{
    x ^= x >> 33;
    x *= 0xff51afd7ed558ccdull;
    x ^= x >> 33;
    x *= 0xc4ceb9fe1a85ec53ull;
    x ^= x >> 33;
    return x;
}

/* represent n in 4 bytes */
void human_format(u64 n, char *target)
{
    if (n < 1000)
    {
        sprintf(target, "%" PRId64, n);
        return;
    }
    if (n < 1000000)
    {
        sprintf(target, "%.1fK", n / 1e3);
        return;
    }
    if (n < 1000000000)
    {
        sprintf(target, "%.1fM", n / 1e6);
        return;
    }
    if (n < 1000000000000ll)
    {
        sprintf(target, "%.1fG", n / 1e9);
        return;
    }
    if (n < 1000000000000000ll)
    {
        sprintf(target, "%.1fT", n / 1e12);
        return;
    }
}

/******************************** SPECK block cipher **************************/

# define ROTL32(x,r) (((x)<<(r)) | (x>>(32-(r))))
# define ROTR32(x,r) (((x)>>(r)) | ((x)<<(32-(r))))

# define ER32(x,y,k) (x = ROTR32(x, 8), x += y, x ^= k, y = ROTL32(y, 3), y ^= x)
# define DR32(x,y,k) (y ^=x, y = ROTR32(y, 3), x ^= k, x -= y, x = ROTL32(x, 8))

void Speck64128KeySchedule(const u32 K[],u32 rk[])
{
    u32 i, D = K[3], C = K[2], B = K[1], A = K[0];

    for(i = 0; i < 27;)
    {
        rk[i] = A; ER32(B, A, i++);
        rk[i] = A; ER32(C, A, i++);
        rk[i] = A; ER32(D, A, i++);
    }
}

void Speck64128Encrypt(const u32 Pt[], u32 Ct[], const u32 rk[])
{
    u32 i;
    Ct[0] = Pt[0];
    Ct[1] = Pt[1];

    for(i = 0; i < 27;)
    {
        ER32(Ct[1], Ct[0], rk[i++]);
    }
}

void Speck64128Decrypt(u32 Pt[], const u32 Ct[], u32 const rk[])
{
    int i;
    Pt[0] = Ct[0];
    Pt[1] = Ct[1];

    for(i = 26; i >= 0;)
    {
        DR32(Pt[1],Pt[0],rk[i--]);
    }
}

/******************************** dictionary ********************************/

/*
 * "classic" hash table for 64-bit key-value pairs, with linear probing.  
 * It operates under the assumption that the keys are somewhat random 64-bit integers.
 * The keys are only stored modulo 2**32 - 5 (a prime number), and this can lead 
 * to some false positives.
 */
static const u32 EMPTY = 0xffffffff;
static const u64 PRIME = 0xfffffffb;

/* allocate a hash table with `size` slots (12*size bytes) */
void dict_setup(u64 size)
{
	dict_size = size;
	char hdsize[8];
	human_format(dict_size * sizeof(*A), hdsize);

	printf("Dictionary size: %sB\n", hdsize);

	A = malloc(sizeof(*A) * dict_size);

	if (A == NULL)
    {
		err(1, "impossible to allocate the dictionnary");
    }

	for (u64 i = 0; i < dict_size; i++)
    {
		A[i].k = EMPTY;
    }
}

/* Insert the binding key |----> value in the dictionnary */
void dict_insert(u64 key, u64 value)
{
    u64 h = murmur64(key) % dict_size;

    for (;;)
    {
        if (A[h].k == EMPTY)
        {
            break;
        }

        h += 1;
        
        if (h == dict_size)
        {
            h = 0;
        }
    }

    assert(A[h].k == EMPTY);

    A[h].k = key % PRIME;
    A[h].v = value;
}

/* Query the dictionnary with this `key`.  Write values (potentially) 
 *  matching the key in `values` and return their number. The `values`
 *  array must be preallocated of size (at least) `maxval`.
 *  The function returns -1 if there are more than `maxval` results.
 */
int dict_probe(u64 key, int maxval, u64 values[])
{
    u32 k = key % PRIME;
    u64 h = murmur64(key) % dict_size;
    int nval = 0;

    for (;;)
    {
        if (A[h].k == EMPTY)
        {
            return nval;
        }

        if (A[h].k == k)
        {
        	if (nval == maxval)
            {
        		return -1;
            }

            values[nval] = A[h].v;
            nval += 1;
        }

        h += 1;
        
        if (h == dict_size)
        {
            h = 0;
        }
   	}
}

/***************************** MITM problem ***********************************/

/* f : {0, 1}^n --> {0, 1}^n.  Speck64-128 encryption of P[0], using k */
u64 f(u64 k)
{
    assert((k & mask) == k);
    u32 K[4] = {k & 0xffffffff, k >> 32, 0, 0};
    u32 rk[27];
    Speck64128KeySchedule(K, rk);

    u32 Ct[2];
    Speck64128Encrypt(P[0], Ct, rk);
    
    return ((u64) Ct[0] ^ ((u64) Ct[1] << 32)) & mask;
}

/* g : {0, 1}^n --> {0, 1}^n.  speck64-128 decryption of C[0], using k */
u64 g(u64 k)
{
    assert((k & mask) == k);
    u32 K[4] = {k & 0xffffffff, k >> 32, 0, 0};
    u32 rk[27];
    Speck64128KeySchedule(K, rk);

    u32 Pt[2];
    Speck64128Decrypt(Pt, C[0], rk);
    
    return ((u64) Pt[0] ^ ((u64) Pt[1] << 32)) & mask;
}

bool is_good_pair(u64 k1, u64 k2)
{
    u32 Ka[4] = {k1 & 0xffffffff, k1 >> 32, 0, 0};
    u32 Kb[4] = {k2 & 0xffffffff, k2 >> 32, 0, 0};
    u32 rka[27];
    u32 rkb[27];
    Speck64128KeySchedule(Ka, rka);
    Speck64128KeySchedule(Kb, rkb);

    u32 mid[2];
    u32 Ct[2];
    Speck64128Encrypt(P[1], mid, rka);
    Speck64128Encrypt(mid, Ct, rkb);
    
    return (Ct[0] == C[1][0]) && (Ct[1] == C[1][1]);
}

/******************************************************************************/

/* search the "golden collision" */
int golden_claw_search(int maxres, u64 **K1, u64 **K2, int my_rank, int p)
{
	/****************************************************************
	 * 0. Local initialization
	 ****************************************************************/
	u64 N = 1ull << n;
	u64 start = (my_rank * N) / p;
	u64 end = ((my_rank + 1) * N) / p;

	/*
     * "Block" processing to avoid memory explosion.
     *
     * Idea:
     *  - STEP 1: build the dictionary by successively exchanging blocks of (z=f(x),x)
     *  - STEP 2+3: exchange blocks of (z=g(y),y) and probe immediately.
	 *
     * This way, we never keep an array of size ~2*(N/p) u64 in memory.
     */
	const u64 CHUNK_KEYS = 1ull << 20; /* ~1M keys/block (adjust if necessary) */

	/****************************************************************
	 * STEP 1: Building the partitioned dictionary (sequential, in blocks)
	 ****************************************************************/
	for (u64 base = start; base < end; base += CHUNK_KEYS)
    {
		u64 limit = base + CHUNK_KEYS;

		if (limit > end)
        {
			limit = end;
        }

		u64 local_count = limit - base;

		struct u64_darray *dict_zx = malloc(p * sizeof(struct u64_darray));

		if (!dict_zx)
        {
			perror("malloc dict_zx");
			return -1;
		}

		/* initial capacity: ~2*(local_count/p) u64 values per destination */
		int init_cap = (int)(2 * (local_count / (u64)p + 1));

		if (init_cap < 16)
        {
			init_cap = 16;
        }

		for (int rank = 0; rank < p; rank++)
        {
			initialize_u64_darray(&(dict_zx[rank]), init_cap);
        }

		for (u64 x = base; x < limit; x++)
        {
			u64 z = f(x);
			int dest_rank = (int)(z % (u64)p);

			append(&(dict_zx[dest_rank]), z);
			append(&(dict_zx[dest_rank]), x);
		}

		u64 *dict_zx_recv = NULL;
		int dict_zx_recv_size = exchange(&dict_zx_recv, dict_zx, p, my_rank);

		free(dict_zx);

		for (int i = 0; i < dict_zx_recv_size - 1; i += 2)
        {
			dict_insert(dict_zx_recv[i], dict_zx_recv[i + 1]);
        }

		free(dict_zx_recv);
	}

	/****************************************************************
	 * STEP 2+3: (z=g(y),y) in blocks + immediate probe (OpenMP)
	 ****************************************************************/
	int nres = 0;
	u64 ncandidates = 0;

	u64 k1[maxres];
	u64 k2[maxres];

	int overflow = 0;

	for (u64 base = start; base < end; base += CHUNK_KEYS)
    {
		u64 limit = base + CHUNK_KEYS;

		if (limit > end)
        {
			limit = end;
        }

		u64 local_count = limit - base;

		struct u64_darray *dict_zy = malloc(p * sizeof(struct u64_darray));

		if (!dict_zy)
        {
			perror("malloc dict_zy");
			return -1;
		}

		int init_cap = (int)(2 * (local_count / (u64)p + 1));

		if (init_cap < 16)
        {
			init_cap = 16;
        }

		for (int rank = 0; rank < p; rank++)
        {
			initialize_u64_darray(&(dict_zy[rank]), init_cap);
        }

		for (u64 y = base; y < limit; y++)
        {
			u64 z = g(y);
			int dest_rank = (int)(z % (u64)p);

			append(&(dict_zy[dest_rank]), z);
			append(&(dict_zy[dest_rank]), y);
		}

		u64 *dict_zy_recv = NULL;
		int dict_zy_recv_size = exchange(&dict_zy_recv, dict_zy, p, my_rank);

		free(dict_zy);

# pragma omp parallel
		{
			u64 xbuf[256];
			int local_overflow = 0;

# pragma omp for reduction(+:ncandidates) schedule(static)
			for (int i = 0; i < dict_zy_recv_size; i += 2)
            {
				u64 z = dict_zy_recv[i];
				u64 y = dict_zy_recv[i + 1];

				int nx = dict_probe(z, 256, xbuf);
				assert(nx >= 0);
				ncandidates += (u64)nx;

				for (int j = 0; j < nx; j++)
                {
					if (!is_good_pair(xbuf[j], y))
                    {
						continue;
                    }

					int idx = -1;
# pragma omp critical(reserve_result_slot)
					{
						if (nres < maxres)
                        {
							idx = nres++;
                        }
						else
                        {
							local_overflow = 1;
                        }
					}

					if (idx >= 0)
                    {
						k1[idx] = xbuf[j];
						k2[idx] = y;
					}
				}
			}

# pragma omp critical
			{
				if (local_overflow)
                {
					overflow = 1;
                }
			}
		}

		free(dict_zy_recv);
	}

	int global_overflow = 0;

	MPI_Allreduce(&overflow, &global_overflow, 1, MPI_INT, MPI_MAX, MPI_COMM_WORLD);

	if (global_overflow)
    {
		return -1;
    }

	int *global_nres = NULL;
	int *displs = NULL;

	if (my_rank == 0)
    {
		global_nres = malloc(p * sizeof(int));
		displs = malloc(p * sizeof(int));
	}

	MPI_Gather(&nres, 1, MPI_INT, global_nres, 1, MPI_INT, 0, MPI_COMM_WORLD);

	int total_nres = 0;

	if (my_rank == 0)
    {
		displs[0] = 0;

		for (int i = 0; i < p; i++)
        {
			total_nres += global_nres[i];

			if (i > 0)
            {
				displs[i] = displs[i - 1] + global_nres[i - 1];
            }
		}

		*K1 = malloc(total_nres * sizeof(u64));
		*K2 = malloc(total_nres * sizeof(u64));
	}

	MPI_Gatherv(k1, nres, MPI_UNSIGNED_LONG_LONG, *K1, global_nres, displs, MPI_UNSIGNED_LONG_LONG, 0, MPI_COMM_WORLD);

	MPI_Gatherv(k2, nres, MPI_UNSIGNED_LONG_LONG, *K2, global_nres, displs, MPI_UNSIGNED_LONG_LONG, 0, MPI_COMM_WORLD);

	if (my_rank == 0)
    {
		printf("Total results gathered: %d\n", total_nres);

		for (int i = 0; i < total_nres; i++)
        {
			printf("K1[%d] = %llu, K2[%d] = %llu\n", i,
                (unsigned long long)(*K1)[i], i, (unsigned long long)(*K2)[i]);
		}
	}

	return total_nres;
}

/************************** command-line options ****************************/

void usage(char **argv)
{
        printf("%s [OPTIONS]\n\n", argv[0]);
        printf("Options:\n");
        printf("--n N                       block size [default 24]\n");
        printf("--C0 N                      1st ciphertext (in hex)\n");
        printf("--C1 N                      2nd ciphertext (in hex)\n");
        printf("\n");
        printf("All arguments are required\n");
        exit(0);
}

void process_command_line_options(int argc, char ** argv)
{
    struct option longopts[4] = {
            {"n", required_argument, NULL, 'n'},
            {"C0", required_argument, NULL, '0'},
            {"C1", required_argument, NULL, '1'},
            {NULL, 0, NULL, 0}
    };

    char ch;
    int set = 0;
    
    while ((ch = getopt_long(argc, argv, "", longopts, NULL)) != -1)
    {
        switch (ch)
        {
        case 'n':
                n = atoi(optarg);
                mask = (1ull << n) - 1;
                break;

        case '0':
                set |= 1;
                u64 c0 = strtoull(optarg, NULL, 16);
                C[0][0] = c0 & 0xffffffff;
                C[0][1] = c0 >> 32;
                break;

        case '1':
                set |= 2;
                u64 c1 = strtoull(optarg, NULL, 16);
                C[1][0] = c1 & 0xffffffff;
                C[1][1] = c1 >> 32;
                break;

        default:
                errx(1, "Unknown option\n");
        }
    }

    if (n == 0 || set != 3)
    {
        usage(argv);
        exit(1);
    }
}

/******************************************************************************/

int main(int argc, char **argv)
{
    /****************************************************************
     * 1. MPI initialization
     * **************************************************************/

    MPI_Init(&argc, &argv); // initialise MPI

    int my_rank, p;
    MPI_Comm_rank(MPI_COMM_WORLD, &my_rank);
    MPI_Comm_size(MPI_COMM_WORLD, &p);

    /****************************************************************
     * 2. Reading the problem parameters
     * **************************************************************/

    process_command_line_options(argc, argv);

    if (my_rank == 0)
    {
        printf("Running with n=%" PRIu64 ", C0=(%08x,%08x), C1=(%08x,%08x)\n", n, C[0][0], C[0][1], C[1][0], C[1][1]);
        printf("Number of MPI processes: %d\n", p);
    }

    /****************************************************************
     * 3. OpenMP configuration
     * **************************************************************/

    int max_threads = omp_get_max_threads();
    int num_cores = omp_get_num_procs();

    if (my_rank == 0)
    {
        printf("Max OpenMP threads: %d\n", max_threads);
        printf("Logical cores: %d\n", num_cores);
    }

    /****************************************************************
     * 4. Initializing local dictionary
     * **************************************************************/

    u64 dict_alloc_size = (u64)(n < 10 ? 1.125 * (1ull << n) : 1.125 * (1ull << n) / p);
    dict_setup(dict_alloc_size);

    /****************************************************************
     * 5. "Golden claw" collision detection
     * **************************************************************/

    u64 *K1 = NULL, *K2 = NULL;

    double start_time = MPI_Wtime();
    int nkey = golden_claw_search(16, &K1, &K2, my_rank, p);
    double end_time = MPI_Wtime();

    printf("[rank %d] Time taken = %.6f seconds\n", my_rank, end_time - start_time);

    /****************************************************************
     * 6. Validating results (only on root)
     * **************************************************************/

    if (my_rank == 0 && nkey > 0)
    {
        for (int i = 0; i < nkey; i++)
        {
            printf("Validation step %d:\n", i);
            printf("f(K1[i]) = %lu ; g(K2[i]) = %lu\n", f(K1[i]), g(K2[i]));

            assert(f(K1[i]) == g(K2[i]));
            assert(is_good_pair(K1[i], K2[i]));

            printf("Solution found: (%" PRIx64 ", %" PRIx64 ")\n", K1[i], K2[i]);
        }
    }

    /****************************************************************
     * 7. Memory release
     * **************************************************************/

    free(K1);
    free(K2);

    /****************************************************************
     * 8. MPI finalization
     * **************************************************************/
    MPI_Barrier(MPI_COMM_WORLD);
    MPI_Finalize();

    return 0;
}
