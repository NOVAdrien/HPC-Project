# ifndef COMMUNICATION_H
# define COMMUNICATION_H

# include <mpi.h>
# include <stdlib.h>
# include <string.h>

# include "utilities.h"

int exchange(u64 **recv, struct u64_darray *send, int p, int my_rank)
{
	/**************************************************************************
	 * STEP 1: Send sizes + compute send displacements
	 **************************************************************************/

	MPI_Request size_request[p];
	int send_sizes[p];
	int send_total_size = 0;

	/* Packets: (source_rank, message_size) */
	int sender_packet[2 * (p - 1)];
	int i = 0;

	for (int dest_rank = 0; dest_rank < p; dest_rank++)
	{
		if (dest_rank == my_rank)
		{
			continue;
		}

		sender_packet[i + 0] = my_rank;
		sender_packet[i + 1] = send[dest_rank].size;

		MPI_Isend(sender_packet + i, 2, MPI_INT,
		          dest_rank, 0, MPI_COMM_WORLD,
		          &size_request[dest_rank]);

		send_sizes[dest_rank] = send[dest_rank].size;
		send_total_size += send_sizes[dest_rank];
		i += 2;
	}

	size_request[my_rank] = MPI_REQUEST_NULL;
	MPI_Waitall(p, size_request, MPI_STATUSES_IGNORE);

	send_sizes[my_rank] = send[my_rank].size;
	send_total_size += send_sizes[my_rank];

	int send_displacements[p];
	send_displacements[0] = 0;

	for (int dest_rank = 1; dest_rank < p; dest_rank++)
	{
		send_displacements[dest_rank] = send_displacements[dest_rank - 1] + send_sizes[dest_rank - 1];
	}

	/**************************************************************************
	 * STEP 2: Receive sizes + compute receive displacements
	 **************************************************************************/

	MPI_Request recv_size_request;
	int recv_sizes[p];
	int recv_total_size = 0;

	for (int sender = 0; sender < p; sender++)
	{
		if (sender == my_rank)
		{
			continue;
		}

		int recv_packet[2];
		MPI_Irecv(recv_packet, 2, MPI_INT, MPI_ANY_SOURCE, 0, MPI_COMM_WORLD, &recv_size_request);
		MPI_Wait(&recv_size_request, MPI_STATUS_IGNORE);

		recv_sizes[recv_packet[0]] = recv_packet[1];
		recv_total_size += recv_packet[1];
	}

	recv_sizes[my_rank] = send[my_rank].size;
	recv_total_size += recv_sizes[my_rank];

	int recv_displacements[p];
	recv_displacements[0] = 0;

	for (int sender = 1; sender < p; sender++)
	{
		recv_displacements[sender] = recv_displacements[sender - 1] + recv_sizes[sender - 1];
	}

	/**************************************************************************
	 * STEP 3: Build contiguous buffers + MPI_Alltoallv
	 **************************************************************************/

	u64 *contiguous_send = malloc(send_total_size * sizeof(u64));

# pragma omp parallel for
	for (int sender = 0; sender < p; sender++)
	{
		memcpy(contiguous_send + send_displacements[sender],
			   send[sender].data,
			   send[sender].size * sizeof(u64));
		free_u64_darray(&(send[sender]));
	}

	/* Aligned allocation for better memory access */
	*recv = aligned_alloc(32, recv_total_size * sizeof(u64));

	MPI_Alltoallv(contiguous_send,
	              send_sizes, send_displacements, MPI_UINT64_T,
	              *recv,
	              recv_sizes, recv_displacements, MPI_UINT64_T,
	              MPI_COMM_WORLD);

	free(contiguous_send);

	return recv_total_size;
}

# endif