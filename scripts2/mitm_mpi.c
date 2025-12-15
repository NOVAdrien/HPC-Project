#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <assert.h>
#include <getopt.h>
#include <err.h>
#include <assert.h>
#include <mpi.h>

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
    if (n < 1000) {
        sprintf(target, "%" PRId64, n);
        return;
    }
    if (n < 1000000) {
        sprintf(target, "%.1fK", n / 1e3);
        return;
    }
    if (n < 1000000000) {
        sprintf(target, "%.1fM", n / 1e6);
        return;
    }
    if (n < 1000000000000ll) {
        sprintf(target, "%.1fG", n / 1e9);
        return;
    }
    if (n < 1000000000000000ll) {
        sprintf(target, "%.1fT", n / 1e12);
        return;
    }
}

/******************************** SPECK block cipher **************************/

#define ROTL32(x,r) (((x)<<(r)) | (x>>(32-(r))))
#define ROTR32(x,r) (((x)>>(r)) | ((x)<<(32-(r))))

#define ER32(x,y,k) (x=ROTR32(x,8), x+=y, x^=k, y=ROTL32(y,3), y^=x)
#define DR32(x,y,k) (y^=x, y=ROTR32(y,3), x^=k, x-=y, x=ROTL32(x,8))

void Speck64128KeySchedule(const u32 K[],u32 rk[])
{
    u32 i,D=K[3],C=K[2],B=K[1],A=K[0];
    for(i=0;i<27;){
        rk[i]=A; ER32(B,A,i++);
        rk[i]=A; ER32(C,A,i++);
        rk[i]=A; ER32(D,A,i++);
    }
}

void Speck64128Encrypt(const u32 Pt[], u32 Ct[], const u32 rk[])
{
    u32 i;
    Ct[0]=Pt[0]; Ct[1]=Pt[1];
    for(i=0;i<27;)
        ER32(Ct[1],Ct[0],rk[i++]);
}

void Speck64128Decrypt(u32 Pt[], const u32 Ct[], u32 const rk[])
{
    int i;
    Pt[0]=Ct[0]; Pt[1]=Ct[1];
    for(i=26;i>=0;)
        DR32(Pt[1],Pt[0],rk[i--]);
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
		err(1, "impossible to allocate the dictionnary");
	for (u64 i = 0; i < dict_size; i++)
		A[i].k = EMPTY;
}

/* Insert the binding key |----> value in the dictionnary */
void dict_insert(u64 key, u64 value)
{
    u64 h = murmur64(key) % dict_size;
    for (;;) {
        if (A[h].k == EMPTY)
            break;
        h += 1;
        if (h == dict_size)
            h = 0;
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
    for (;;) {
        if (A[h].k == EMPTY)
            return nval;
        if (A[h].k == k) {
        	if (nval == maxval)
        		return -1;
            values[nval] = A[h].v;
            nval += 1;
        }
        h += 1;
        if (h == dict_size)
            h = 0;
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
int golden_claw_search(int maxres, u64 k1[], u64 k2[])
{
    double start = wtime();
    u64 N = 1ull << n;
    for (u64 x = 0; x < N; x++) {
        u64 z = f(x);
        dict_insert(z, x);
    }

    double mid = wtime();
    printf("Fill: %.1fs\n", mid - start);
    
    int nres = 0;
    u64 ncandidates = 0;
    u64 x[256];
    for (u64 z = 0; z < N; z++) {
        u64 y = g(z);
        int nx = dict_probe(y, 256, x);
        assert(nx >= 0);
        ncandidates += nx;
        for (int i = 0; i < nx; i++)
            if (is_good_pair(x[i], z)) {
            	if (nres == maxres)
            		return -1;
            	k1[nres] = x[i];
            	k2[nres] = z;
            	printf("SOLUTION FOUND!\n");
            	nres += 1;
            }
    }
    printf("Probe: %.1fs. %" PRId64 " candidate pairs tested\n", wtime() - mid, ncandidates);
    return nres;
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
        while ((ch = getopt_long(argc, argv, "", longopts, NULL)) != -1) {
                switch (ch) {
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
        if (n == 0 || set != 3) {
        	usage(argv);
        	exit(1);
        }
}

/******************************************************************************/

int main(int argc, char **argv)
{
    /* ============================
       1. Initialisation MPI
       ============================ */
    MPI_Init(&argc, &argv);

    int rank, num_procs;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    MPI_Comm_size(MPI_COMM_WORLD, &num_procs);

    /* ============================
       2. Options - n, C0, C1
       ============================ */
    if (rank == 0)
        process_command_line_options(argc, argv);

    // Broadcast pour que tous les processus connaissent n, mask, C[]
    MPI_Bcast(&n, 1, MPI_UINT64_T, 0, MPI_COMM_WORLD);
    MPI_Bcast(&mask, 1, MPI_UINT64_T, 0, MPI_COMM_WORLD);
    MPI_Bcast(C, 4, MPI_UINT32_T, 0, MPI_COMM_WORLD);

    /* ============================
       3. Répartition des clés
       ============================ */
    u64 N = 1ull << n;   // nombre total de clés

    u64 chunk = N / num_procs;
    u64 start = rank * chunk;
    u64 end   = (rank == num_procs - 1) ? N : start + chunk;

    if (rank == 0) {
        printf("MPI started with %d processes.\n", num_procs);
        printf("Each process handles %llu keys (~2^%llu total)\n",
               (unsigned long long)chunk, (unsigned long long)n);
    }

    MPI_Barrier(MPI_COMM_WORLD);

    /* ============================
       4. Dictionnaire local
       ============================ */
    u64 local_dict_size = chunk * 1.3; // marge de sécurité
    dict_setup(local_dict_size);

    /* ============================
       5. Calcul f(x) local
       ============================ */
    printf("[Rank %d] Computed %llu f(x) values locally.\n",
           rank, (unsigned long long)(end - start));

    MPI_Barrier(MPI_COMM_WORLD);

    /* =======================================================
       6. REDISTRIBUTION DES PAIRES (f(x), x)
       ======================================================= */
    typedef struct {
        u64 fx;
        u64 x;
    } kv_t;

    /* 6.1 Buffers d’envoi */
    kv_t **sendbuf = malloc(num_procs * sizeof(kv_t *));
    int  *sendcount = calloc(num_procs, sizeof(int));

    for (int p = 0; p < num_procs; p++) {
        sendbuf[p] = malloc((end - start) * sizeof(kv_t));
    }

    /* 6.2 Remplissage : chaque processus détermine l’owner de f(x) */
    for (u64 x = start; x < end; x++) {
        u64 fx = f(x);
        int owner = murmur64(fx) % num_procs;

        int idx = sendcount[owner]++;
        sendbuf[owner][idx].fx = fx;
        sendbuf[owner][idx].x  = x;
    }

    /* 6.3 Alltoall des tailles */
    int *recvcount = calloc(num_procs, sizeof(int));
    MPI_Alltoall(sendcount, 1, MPI_INT,
                 recvcount, 1, MPI_INT,
                 MPI_COMM_WORLD);

    /* 6.4 Offsets */
    int *sdispls = malloc(num_procs * sizeof(int));
    int *rdispls = malloc(num_procs * sizeof(int));

    sdispls[0] = 0;
    rdispls[0] = 0;

    int send_total = sendcount[0];
    int recv_total = recvcount[0];

    for (int p = 1; p < num_procs; p++) {
        sdispls[p] = sdispls[p-1] + sendcount[p-1];
        rdispls[p] = rdispls[p-1] + recvcount[p-1];
        send_total += sendcount[p];
        recv_total += recvcount[p];
    }

    /* 6.5 Buffers linéarisés */
    kv_t *sendflat = malloc(send_total * sizeof(kv_t));
    kv_t *recvflat = malloc(recv_total * sizeof(kv_t));

    for (int p = 0; p < num_procs; p++) {
        memcpy(sendflat + sdispls[p],
               sendbuf[p],
               sendcount[p] * sizeof(kv_t));
    }

    /* 6.6 Alltoallv réel */
    MPI_Alltoallv(sendflat, sendcount, sdispls, MPI_BYTE,
                  recvflat, recvcount, rdispls, MPI_BYTE,
                  MPI_COMM_WORLD);

    /* 6.7 Insertion dans le dictionnaire FINAL */
    for (int i = 0; i < recv_total; i++) {
        dict_insert(recvflat[i].fx, recvflat[i].x);
    }

    printf("[Rank %d] Final dictionary contains %d redistributed entries.\n",
           rank, recv_total);

    /* Cleanup redistribution buffers */
    for (int p = 0; p < num_procs; p++)
        free(sendbuf[p]);

    free(sendbuf);
    free(sendcount);
    free(recvcount);
    free(sendflat);
    free(recvflat);
    free(sdispls);
    free(rdispls);

    /* ============================
       7. Fin
       ============================ */
    free(A);
    MPI_Finalize();
    return 0;
}
