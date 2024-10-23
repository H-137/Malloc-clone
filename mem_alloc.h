/*
 * Author: Matthew Leopold - leopolmb@bc.edu
 */

#include<stdio.h>
#include<stdlib.h>

#define PAGE_SIZE 4096
#define WORD_SIZE 8
#define SUCCESS 0
#define FAILURE -1

typedef struct Header {
    size_t size;
    struct Header * next;
    struct Header * previous;
} Header;

Header * free_list;

void * mem_alloc(size_t);
void mem_free(void *);
