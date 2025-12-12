#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <assert.h>
#include <getopt.h>
#include <err.h>
#include <mpi.h>
#include <omp.h>

/*
 * MITM parallel version (MPI + OpenMP)
 * - Sharding is done on the key f(x) (same hash used for probing g(y)).
 * - Phase 1: each MPI rank computes f(x) on its x-range, builds send buffers
 *            partitioned by owner = murmur64(fx) % P, then Alltoallv to send
 *            all (fx,x) pairs to their owners. Owners build local dictionaries.
 * - Phase 2: each MPI rank computes g(z) on its z-range, builds send buffers
 *            partitioned by owner = murmur64(gz) % P, then Alltoallv to send
 *            all (gz,z) queries to owners. Owners probe their local dict and
 *            check is_good_pair for candidate x values. Results are gathered
 *            to rank 0 which prints and validates them.
 *
 * Notes:
 * - This file starts from the original sequential mitm.c and keeps the SPECK
 *   implementation and dict code mostly unchanged, but distributed.
 * - Communications use MPI_Alltoallv to avoid deadlocks and to be efficient
 *   for large many-to-many transfers.
 * - OpenMP is used to speed up local f/g computations and local probing loops.
 */

typedef uint64_t u64;       /* portable 64-bit integer */
typedef uint32_t u32;       /* portable 32-bit integer */
struct __attribute__ ((packed)) entry { u32 k; u64 v; };  /* hash table entry */

/***************************** global variables ******************************/

u64 n = 0;         /* block size (in bits) */
u64 mask;          /* this is 2**n - 1 */

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
void human_format(u64 nval, char *target)
{
    if (nval < 1000) {
        sprintf(target, "%" PRId64, nval);
        return;
    }
    if (nval < 1000000) {
        sprintf(target, "%.1fK", nval / 1e3);
        return;
    }
    if (nval < 1000000000) {
        sprintf(target, "%.1fM", nval / 1e6);
        return;
    }
    if (nval < 1000000000000ll) {
        sprintf(target, "%.1fG", nval / 1e9);
        return;
    }
    if (nval < 1000000000000000ll) {
        sprintf(target, "%.1fT", nval / 1e12);
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

/* We reuse the original hash-table design but allocate it per-shard (per rank) */
/* Each rank's dict holds the keys whose hash mapping points to that rank. */
/* The dict implementation is basically the one from the original program. */

static const u32 EMPTY = 0xffffffff;
static const u64 PRIME = 0xfffffffb;

u64 dict_size_local;     /* number of slots in the local hash table */
struct entry *A_local;   /* the local hash table */

/* allocate a local hash table with `size` slots (12*size bytes) */
void dict_setup_local(u64 size)
{
    dict_size_local = size;
    char hdsize[32];
    human_format(dict_size_local * sizeof(*A_local), hdsize);
    printf("[rank ?] Local dictionary size: %sB\n", hdsize);

    A_local = malloc(sizeof(*A_local) * dict_size_local);
    if (A_local == NULL)
        err(1, "impossible to allocate the local dictionnary");
    for (u64 i = 0; i < dict_size_local; i++)
        A_local[i].k = EMPTY;
}

/* Insert the binding key |----> value in the local dictionnary */
void dict_insert_local(u64 key, u64 value)
{
    u64 h = murmur64(key) % dict_size_local;
    for (;;) {
        if (A_local[h].k == EMPTY)
            break;
        h += 1;
        if (h == dict_size_local)
            h = 0;
    }
    assert(A_local[h].k == EMPTY);
    A_local[h].k = key % PRIME;
    A_local[h].v = value;
}

/* Query the local dictionnary with this `key`.  Write values (potentially)
 * matching the key in `values` and return their number. The `values`
 * array must be preallocated of size (at least) `maxval`.
 * The function returns -1 if there are more than `maxval` results.
 */
int dict_probe_local(u64 key, int maxval, u64 values[])
{
    u32 k = key % PRIME;
    u64 h = murmur64(key) % dict_size_local;
    int nval = 0;
    for (;;) {
        if (A_local[h].k == EMPTY)
            return nval;
        if (A_local[h].k == k) {
            if (nval == maxval)
                return -1;
            values[nval] = A_local[h].v;
            nval += 1;
        }
        h += 1;
        if (h == dict_size_local)
            h = 0;
    }
}

/***************************** MITM problem ***********************************/

/* (P, C) : two plaintext-ciphertext pairs (kept from original interface) */
u32 Ptxt[2][2] = {{0, 0}, {0xffffffff, 0xffffffff}};
u32 Ctxt[2][2];

/* f : {0, 1}^n --> {0, 1}^n.  Speck64-128 encryption of P[0], using k */
 u64 f(u64 k)
{
    assert((k & mask) == k);
    u32 K[4] = {k & 0xffffffff, k >> 32, 0, 0};
    u32 rk[27];
    Speck64128KeySchedule(K, rk);
    u32 Ct[2];
    Speck64128Encrypt(Ptxt[0], Ct, rk);
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
    Speck64128Decrypt(Pt, Ctxt[0], rk);
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
    Speck64128Encrypt(Ptxt[1], mid, rka);
    Speck64128Encrypt(mid, Ct, rkb);
    return (Ct[0] == Ctxt[1][0]) && (Ct[1] == Ctxt[1][1]);
}

/*******************************************************************************
 * Parallel implementation using MPI_Alltoallv for exchanging many (key,val)
 * pairs.  The code tries to remain close to the sequential mitm.c API but
 * distributes both memory and work.
 ******************************************************************************/

/* helper: build sendcounts and displs arrays for Alltoallv from per-dest counts */
static void build_counts_and_displs(int P, int *sendcounts_u64, int *sdispls)
{
    sdispls[0] = 0;
    for (int i = 1; i < P; i++)
        sdispls[i] = sdispls[i-1] + sendcounts_u64[i-1];
}

int main(int argc, char **argv)
{
    int rank = 0;
    int P = 1;

    MPI_Init(&argc, &argv);
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    MPI_Comm_size(MPI_COMM_WORLD, &P);

    printf("[rank %d/%d] MPI initialized correctly\n", rank, P);
    fflush(stdout);

    /* parse command-line options (copied from original code) */
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
            {
                u64 c0 = strtoull(optarg, NULL, 16);
                Ctxt[0][0] = c0 & 0xffffffff;
                Ctxt[0][1] = c0 >> 32;
            }
            break;
        case '1':
            set |= 2;
            {
                u64 c1 = strtoull(optarg, NULL, 16);
                Ctxt[1][0] = c1 & 0xffffffff;
                Ctxt[1][1] = c1 >> 32;
            }
            break;
        default:
            if (rank==0) fprintf(stderr, "Unknown option\n");
            MPI_Finalize();
            return 1;
        }
    }
    if (n == 0 || set != 3) {
        if (rank==0) {
            printf("Usage: %s --n N --C0 HEX --C1 HEX\n", argv[0]);
        }
        MPI_Finalize();
        return 1;
    }

    if (rank==0) printf("Running with n=%d on %d ranks\n", (int)n, P);

    u64 N = 1ull << n;

    /* estimate local dictionary size: we allocate slightly more than N/P */
    u64 local_slots = (u64)(1.125 * ((double)N / (double)P));
    dict_setup_local(local_slots);

    /* compute local x range (each rank handles contiguous block) */
    u64 chunk = N / P;
    u64 x_start = rank * chunk;
    u64 x_end   = (rank == P-1) ? N : x_start + chunk; // last rank takes remainder

    /********************* PHASE 1: build (f(x) -> x) pairs and exchange **********/
    /* Each rank computes f(x) for x in its interval and groups outgoing
     * pairs by destination owner = murmur64(fx) % P. We then exchange all
     * pairs using MPI_Alltoallv so that each rank receives the pairs it
     * must store in its local dictionary.
     ******************************************************************************/

    double t0 = wtime();

    /* first pass: compute counts per destination */
    int *send_counts_elems = calloc(P, sizeof(int)); // counts in number of u64 elements
    u64 *tmp_fx = NULL; // we will store pairs temporarily per-thread via dynamic lists

    /* To avoid heavy locking we build per-destination vectors in two phases:
     *  - first compute pair counts per dest using a simple loop
     *  - allocate a flat buffer for all pairs and fill it in a second parallel loop
     */

    // Phase 1a: count how many pairs will go to each destination
    for (u64 x = x_start; x < x_end; x++) {
        u64 fx = f(x);
        int owner = (int)(murmur64(fx) % (u64)P);
        send_counts_elems[owner] += 2; // we send two u64 elements: key then value
    }

    // build send displacements
    int *sdispls = calloc(P, sizeof(int));
    build_counts_and_displs(P, send_counts_elems, sdispls);
    int total_send_elems = 0;
    for (int i=0;i<P;i++) total_send_elems += send_counts_elems[i];

    // allocate flat send buffer (u64 elements)
    u64 *sendbuf = malloc(sizeof(u64) * total_send_elems);
    if (!sendbuf) err(1, "malloc sendbuf failed");

    // temp counters to fill sendbuf by destination
    int *pos = calloc(P, sizeof(int));
    for (int i=0;i<P;i++) pos[i] = sdispls[i];

    // Phase 1b: fill sendbuf with (fx,x) pairs
    for (u64 x = x_start; x < x_end; x++) {
        u64 fx = f(x);
        int owner = (int)(murmur64(fx) % (u64)P);
        int idx = pos[owner];
    sendbuf[idx]   = fx;
    sendbuf[idx+1] = x;
    pos[owner] += 2;

    }
    free(pos);

    // exchange counts to get recvcounts
    int *recv_counts_elems = calloc(P, sizeof(int));
    MPI_Alltoall(send_counts_elems, 1, MPI_INT, recv_counts_elems, 1, MPI_INT, MPI_COMM_WORLD);

    int *rdispls = calloc(P, sizeof(int));
    build_counts_and_displs(P, recv_counts_elems, rdispls);
    int total_recv_elems = 0; for (int i=0;i<P;i++) total_recv_elems += recv_counts_elems[i];

    u64 *recvbuf = malloc(sizeof(u64) * (total_recv_elems > 0 ? total_recv_elems : 1));
    if (!recvbuf && total_recv_elems>0) err(1, "malloc recvbuf failed");

    // Alltoallv exchange (units: u64 elements)
    MPI_Alltoallv(sendbuf, send_counts_elems, sdispls, MPI_UNSIGNED_LONG_LONG,
                  recvbuf, recv_counts_elems, rdispls, MPI_UNSIGNED_LONG_LONG,
                  MPI_COMM_WORLD);

    // insert received pairs into local dictionary
    int nelems = total_recv_elems;
    for (int i = 0; i < nelems; i += 2) {
        u64 key = recvbuf[i];
        u64 val = recvbuf[i+1];
        dict_insert_local(key, val);
    }

    double t1 = wtime();
    if (rank==0) printf("Phase1 (build dict + exchange) time: %.3fs\n", t1 - t0);

    free(sendbuf); free(recvbuf); free(send_counts_elems); free(recv_counts_elems);
    free(sdispls); free(rdispls);

    MPI_Barrier(MPI_COMM_WORLD);

    /********************* PHASE 2: compute g(z) and exchange queries ************/
    /* Each rank computes g(z) for z in its interval, groups (gz,z) per owner,
     * sends them to owner via Alltoallv. Owner probes local dict and verifies
     * candidate pairs with is_good_pair. Found solutions are stored locally and
     * later gathered to rank 0.
     ******************************************************************************/

    // Phase 2a: count queries per destination
    int *q_send_counts_elems = calloc(P, sizeof(int));
    for (u64 z = x_start; z < x_end; z++) {
        u64 gz = g(z);
        int owner = (int)(murmur64(gz) % (u64)P);
        q_send_counts_elems[owner] += 2; // gz and z
    }
    int *q_sdispls = calloc(P, sizeof(int));
    build_counts_and_displs(P, q_send_counts_elems, q_sdispls);
    int q_total_send = 0; for (int i=0;i<P;i++) q_total_send += q_send_counts_elems[i];
    u64 *q_sendbuf = malloc(sizeof(u64) * (q_total_send>0 ? q_total_send : 1));
    if (!q_sendbuf && q_total_send>0) err(1, "malloc q_sendbuf failed");
    int *q_pos = calloc(P, sizeof(int)); for (int i=0;i<P;i++) q_pos[i] = q_sdispls[i];

    for (u64 z = x_start; z < x_end; z++) {
        u64 gz = g(z);
        int owner = (int)(murmur64(gz) % (u64)P);
        int idx = q_pos[owner];
        q_sendbuf[idx] = gz;
        q_sendbuf[idx+1] = z;
        q_pos[owner] += 2;
    }
    free(q_pos);

    int *q_recv_counts_elems = calloc(P, sizeof(int));
    MPI_Alltoall(q_send_counts_elems, 1, MPI_INT, q_recv_counts_elems, 1, MPI_INT, MPI_COMM_WORLD);
    int *q_rdispls = calloc(P, sizeof(int));
    build_counts_and_displs(P, q_recv_counts_elems, q_rdispls);
    int q_total_recv = 0; for (int i=0;i<P;i++) q_total_recv += q_recv_counts_elems[i];
    u64 *q_recvbuf = malloc(sizeof(u64) * (q_total_recv>0 ? q_total_recv : 1));
    if (!q_recvbuf && q_total_recv>0) err(1, "malloc q_recvbuf failed");

    MPI_Alltoallv(q_sendbuf, q_send_counts_elems, q_sdispls, MPI_UNSIGNED_LONG_LONG,
                  q_recvbuf, q_recv_counts_elems, q_rdispls, MPI_UNSIGNED_LONG_LONG,
                  MPI_COMM_WORLD);

    // Process received queries: for each (gz,z) probe local dictionary and validate
    // We will gather results in dynamic arrays
    u64 *found_k1 = NULL; u64 *found_k2 = NULL; int found_cnt = 0; int found_cap = 0;

    int nqueries = q_total_recv / 2;
    #pragma omp parallel
    {
        // per-thread buffer for candidate x results (to avoid races on temporary arrays)
        u64 local_xs[256];
        #pragma omp for schedule(dynamic)
        for (int qi = 0; qi < q_total_recv; qi += 2) {
            u64 gz = q_recvbuf[qi];
            u64 z  = q_recvbuf[qi+1];
            int nx = dict_probe_local(gz, 256, local_xs);
            if (nx < 0) nx = 256; // safety
            for (int i = 0; i < nx; i++) {
                u64 x = local_xs[i];
                if (is_good_pair(x, z)) {
                    // append to global found arrays (protected by critical)
                    #pragma omp critical
                    {
                        if (found_cnt == found_cap) {
                            found_cap = (found_cap == 0) ? 16 : found_cap * 2;
                            found_k1 = realloc(found_k1, sizeof(u64) * found_cap);
                            found_k2 = realloc(found_k2, sizeof(u64) * found_cap);
                        }
                        found_k1[found_cnt] = x;
                        found_k2[found_cnt] = z;
                        found_cnt++;
                    }
                }
            }
        }
    }

    // Gather found counts to rank 0
    int *all_counts = NULL;
    if (rank == 0) all_counts = malloc(sizeof(int) * P);
    MPI_Gather(&found_cnt, 1, MPI_INT, all_counts, 1, MPI_INT, 0, MPI_COMM_WORLD);

    u64 *gather_k1 = NULL; u64 *gather_k2 = NULL; int *displs_k = NULL;
    if (rank == 0) {
        int total_found = 0;
        displs_k = malloc(sizeof(int) * P);
        displs_k[0] = 0;
        for (int i=0;i<P;i++) {
            if (i>0) displs_k[i] = displs_k[i-1] + all_counts[i-1];
            total_found += all_counts[i];
        }
        gather_k1 = malloc(sizeof(u64) * total_found);
        gather_k2 = malloc(sizeof(u64) * total_found);
    }

    // gather arrays (use MPI_Gatherv)
    int *sendcounts_k = malloc(sizeof(int) * P);
    int *recvcounts_k = NULL;
    for (int i=0;i<P;i++) sendcounts_k[i] = found_cnt;
    if (rank==0) {
        recvcounts_k = malloc(sizeof(int) * P);
        for (int i=0;i<P;i++) recvcounts_k[i] = all_counts[i];
    }

    // Need to provide displacements in terms of counts for Gatherv; compute prefix sums
    int *recvdispls_k = NULL;
    if (rank==0) {
        recvdispls_k = malloc(sizeof(int) * P);
        recvdispls_k[0] = 0;
        for (int i=1;i<P;i++) recvdispls_k[i] = recvdispls_k[i-1] + recvcounts_k[i-1];
    }

    // gather k1
    MPI_Gatherv(found_k1, found_cnt, MPI_UNSIGNED_LONG_LONG,
                gather_k1, recvcounts_k, recvdispls_k, MPI_UNSIGNED_LONG_LONG,
                0, MPI_COMM_WORLD);
    // gather k2
    MPI_Gatherv(found_k2, found_cnt, MPI_UNSIGNED_LONG_LONG,
                gather_k2, recvcounts_k, recvdispls_k, MPI_UNSIGNED_LONG_LONG,
                0, MPI_COMM_WORLD);

    // Rank 0 prints and validates
    if (rank == 0) {
        int total = 0;
        for (int i=0;i<P;i++) total += all_counts[i];
        printf("Total solutions found across ranks: %d\n", total);
        for (int i=0;i<total;i++) {
            u64 x = gather_k1[i]; u64 z = gather_k2[i];
            // validation
            assert(f(x) == g(z));
            assert(is_good_pair(x,z));
            printf("Solution: (0x%016" PRIx64 ", 0x%016" PRIx64 ")\n", x, z);
        }
    }

    MPI_Barrier(MPI_COMM_WORLD);
    if (rank==0) printf("Done.\n");

    /* cleanup */
    if (A_local) free(A_local);
    if (all_counts) free(all_counts);
    if (displs_k) free(displs_k);
    if (gather_k1) free(gather_k1);
    if (gather_k2) free(gather_k2);
    if (sendcounts_k) free(sendcounts_k);
    if (recvcounts_k) free(recvcounts_k);
    if (recvdispls_k) free(recvdispls_k);
    free(q_sendbuf); free(q_recvbuf); free(q_send_counts_elems); free(q_recv_counts_elems);

    MPI_Finalize();
    return 0;
}

