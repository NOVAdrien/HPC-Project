# pragma once

# include <assert.h>
# include <stdlib.h>
# include <malloc.h>
# include <stdio.h>

typedef uint64_t u64; /* portable 64-bit integer */

struct u64_darray
{
	u64 *data;
	int size;
	int capacity;
};

void initialize_u64_darray(struct u64_darray *a, int capacity)
{
	a->capacity = capacity;
	a->size = 0;
	a->data = (u64 *)malloc(a->capacity * sizeof(u64));
}

void append(struct u64_darray *a, u64 val)
{
	if (a->size >= a->capacity)
	{
		a->data = realloc(a->data, 2 * a->capacity * sizeof(u64));
		a->capacity *= 2;
	}

	a->data[a->size++] = val;
}


void free_u64_darray(struct u64_darray *a)
{
	free(a->data);
}
