// SPDX-License-Identifier: BSD-3-Clause

#include "osmem.h"

#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "block_meta.h"

#define MMAP_THRESHOLD (128 * 1024)
#define ALIGNMENT 8
#define ALIGN(size) (((size) + (ALIGNMENT - 1)) & ~(ALIGNMENT - 1))
#define STRUCT_SIZE ALIGN(sizeof(struct block_meta))

// functia de aliniere am luat-o din cele 2 link-uri pe care le-ati pus
// sursa de inspiratie a fost din cele 2 link-uri

int ok_prealloc;
struct block_meta *head;

struct block_meta *last_block_list(void)
{
	struct block_meta *current = head;

	if (current == NULL)
		return NULL;

	while (current->next)
		current = current->next;

	return current;
}

void add_first_list(struct block_meta *block)
{
	if (head == NULL) {
		head = block;
		head->next = NULL;
		head->prev = NULL;
		return;
	}

	block->next = head;
	head->prev = block;
	block->prev = NULL;

	head = block;
}

void add_last_list(struct block_meta *block)
{
	struct block_meta *last;

	last = last_block_list();
	if (last == NULL) {
		head = block;
		head->next = NULL;
		head->prev = NULL;
		return;
	}

	last->next = block;
	block->next = NULL;
	block->prev = last;
}

void delete_block_list(struct block_meta *block)
{
	if (block->prev) {
		struct block_meta *current;

		current = block->prev;
		current->next = block->next;

		if (block->next)
			block->next->prev = current;
		return;
	}

	if (block->next) {
		block->next->prev = NULL;
		return;
	}

	head = NULL;
}

void prealloc_heap(void)
{
	ok_prealloc = 1;
	struct block_meta *block = NULL;

	block = sbrk(MMAP_THRESHOLD);
	DIE(block == NULL, "SBRK ESUAT");

	block->size = MMAP_THRESHOLD;
	block->status = 0;
	add_last_list(block);
}

struct block_meta *find_best(int size)
{
	struct block_meta *current = head, *best = NULL;

	while (current) {
		if (current->status == 0 && current->size >= (size_t) size) {
			if (best == NULL)
				best = current;
			else if (best->size > current->size)
				best = current;
		}
		current = current->next;
	}

	return best;
}

void split_block(struct block_meta *block, int size)
{
	if (block == NULL)
		return;

	if (block->size - size < STRUCT_SIZE + 8)
		return;

	struct block_meta *new_block = (void *)block + size;

	new_block->status = 0;
	new_block->size = block->size - size;

	new_block->next = block->next;
	new_block->prev = block;
	if (block->next)
		block->next->prev = new_block;
	block->next = new_block;

	block->size = size;
	block->status = 1;
}

void coalesce_block(void)
{
	struct block_meta *current = head, *next_block = NULL;
	int ok = 0;

	while (current) {
		ok = 0;
		if (current->status == 0) {
			next_block = current->next;
			if (next_block == NULL)
				return;
			if (next_block->status == 0) {
				current->size = current->size + next_block->size;

				if (next_block->next)
					next_block->next->prev = current;
				current->next = next_block->next;
				ok = 1;
			}
		}

		if (current && ok == 0)
			current = current->next;
	}
}

int minim_size(int a, int b)
{
	if (a < b)
		return a;
	return b;
}

void *os_malloc(size_t size)
{
	if (size == 0)
		return NULL;
	int size_align = ALIGN(size) + STRUCT_SIZE;

	if (ok_prealloc == 0 && size_align < MMAP_THRESHOLD)
		prealloc_heap();

	struct block_meta *block;

	if (size_align >= MMAP_THRESHOLD) {
		block = mmap(NULL, size_align, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		DIE(block == MAP_FAILED, "MMAP ESUAT");

		block->size = size_align;
		block->status = 2;
		add_first_list(block);

		return (void *)block + STRUCT_SIZE;

	} else {
		coalesce_block();
		struct block_meta *block = find_best(size_align);

		if (block) {
			if (block->size - size_align >= STRUCT_SIZE + ALIGN(1))
				split_block(block, size_align);
			else
				block->status = 1;

			return (void *)block + STRUCT_SIZE;

		} else {
			block = last_block_list();

			if (block->status == 0) {
				block->status = 1;
				int size1 = block->size;

				block->size = size_align;
				void *p;

				p = sbrk(size_align - size1);
				DIE(p == NULL, "SBRK ESUAT");
				return (void *)block + STRUCT_SIZE;
			}

			block = NULL;
			block = sbrk(size_align);
			DIE(block == NULL, "SBRK ESUAT");

			block->status = 1;
			block->size = size_align;
			add_last_list(block);

			return (void *)block + STRUCT_SIZE;
		}
	}
}

void os_free(void *ptr)
{
	if (ptr == NULL)
		return;

	struct block_meta *block = ptr - STRUCT_SIZE;

	if (block->status == 1) {
		block->status = 0;

	} else if (block->status == 2) {
		delete_block_list(block);
		int ret = munmap((void *)block, block->size);

		DIE(ret == -1, "MUNMAP ESUAT");
	}
}

void *os_calloc(size_t nmemb, size_t size)
{
	size = nmemb * size;
	if (size == 0)
		return NULL;

	long page_size = sysconf(_SC_PAGESIZE);
	int size_align = ALIGN(size) + STRUCT_SIZE;

	if (ok_prealloc == 0 && size_align < page_size)
		prealloc_heap();

	struct block_meta *block;

	if (size_align >= page_size) {
		block = mmap(NULL, size_align, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

		DIE(block == MAP_FAILED, "MMAP ESUAT");
		block->size = size_align;
		block->status = 2;
		add_first_list(block);

		memset((void *)block + STRUCT_SIZE, 0, size_align - STRUCT_SIZE);
		return (void *)block + STRUCT_SIZE;

	} else {
		coalesce_block();
		struct block_meta *block = find_best(size_align);

		if (block) {
			if (block->size - size_align >= STRUCT_SIZE + ALIGN(1))
				split_block(block, size_align);
			else
				block->status = 1;
			memset((void *)block + STRUCT_SIZE, 0, size_align - STRUCT_SIZE);
			return (void *)block + STRUCT_SIZE;

		} else {
			block = last_block_list();

			if (block->status == 0) {
				block->status = 1;
				int size1 = block->size;

				block->size = size_align;
				void *p;

				p = sbrk(size_align - size1);
				DIE(p == NULL, "SBRK ESUAT");
				memset((void *)block + STRUCT_SIZE, 0, size_align - STRUCT_SIZE);
				return (void *)block + STRUCT_SIZE;
			}

			block = NULL;
			block = sbrk(size_align);
			DIE(block == NULL, "SBRK ESUAT");

			block->status = 1;
			block->size = size_align;
			add_last_list(block);

			memset((void *)block + STRUCT_SIZE, 0, size_align - STRUCT_SIZE);
			return (void *)block + STRUCT_SIZE;
		}
	}
}

void *os_realloc(void *ptr, size_t size)
{
	size_t size_align = ALIGN(size) + STRUCT_SIZE;

	if (ptr == NULL) {
		ptr = os_malloc(size);
		return ptr;
	}

	if (size == 0) {
		os_free(ptr);
		return NULL;
	}
	struct block_meta *block = ptr - STRUCT_SIZE;
	int first_size = block->size;

	if (block->status == 0)
		return NULL;

	if (block->status == 2 || size_align >= MMAP_THRESHOLD) {
		void *p = os_malloc(size);

		DIE(p == NULL, "OS_MALLOC ESUAT");
		struct block_meta *new_block;

		new_block = p - STRUCT_SIZE;
		int size_cpy = minim_size(block->size, new_block->size);

		memcpy(p, ptr, size_cpy - STRUCT_SIZE);
		os_free(ptr);
		return p;
	}


	if (block->size >= size_align) {
		split_block(block, size_align);
		return ptr;
	}

	if (block->next == NULL) {
		int size = block->size;

		block->size = size_align;
		void *p;

		p = sbrk(size_align - size);
		DIE(p == NULL, "SBRK ESUAT");
		return ptr;
	}

	coalesce_block();
	struct block_meta *next_block;

	next_block = block->next;
	if (next_block != NULL && next_block->status == 0) {
		block->size += next_block->size;
		block->next = next_block->next;
		if (next_block->next)
			next_block->next->prev = block;

		if (block->size >= size_align) {
			split_block(block, size_align);
			return ptr;
		}
	}

	split_block(block, first_size);

	void *p = os_malloc(size);

	DIE(p == NULL, "OS_MALLOC ESUAT");
	struct block_meta *new_block;

	new_block = p - STRUCT_SIZE;
	memcpy(p, ptr, new_block->size - STRUCT_SIZE);
	os_free(ptr);
	return p;
}
