/*
 * Author: Matthew Leopold - leopolmb@bc.edu
 */

#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>

#include "mem_alloc.h"

void print_list() {
    if (free_list == NULL) {
        printf("(Empty list.)\n");
    } else {
        Header * header = free_list;
        while (header != NULL) {
            printf("%p -> ", header);
            header = header->next;
        }
        putchar('\n');
    }
}

size_t get_size(Header * header) {
    return (header->size >> 1) << 1;
}

void print_header(Header * header) {
    printf("\tAddr: %p\n"
            "\tSize:%lu\n"
            "\tPrevious: %p\n"
            "\tNext: %p\n", 
            header, get_size(header), header -> previous, header -> next); 
}

int is_allocated(Header * header) {
    return (header->size) & 1;
}

int is_free(Header * header) {
    return ! is_allocated(header);
}

void set_allocated(Header * header) {
    header->size = header->size | 1;
}

void set_free(Header * header) {
    header->size = (header->size >> 1) << 1;
}

int mem_init() {
    free_list = mmap(NULL, PAGE_SIZE - sizeof(Header), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (free_list == MAP_FAILED) {  
        return FAILURE;
    }
    free_list->size = PAGE_SIZE - sizeof(Header);
    return SUCCESS;
}

Header * get_header(void * mem) {
    return (Header *)((char *)mem - sizeof(Header));
}

int same_page(Header * h1, Header * h2) {
    return ((uintptr_t)h1 >> 12) == ((uintptr_t)h2 >> 12);
}

int mem_extend(Header * last) {
    Header * header;
    header = mmap(NULL, PAGE_SIZE - sizeof(Header), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (header == MAP_FAILED) {
        return FAILURE;
    }
    last->next = header;
    header->previous = last;
    header->size = PAGE_SIZE - sizeof(Header);
    return SUCCESS;
}

void * mem_alloc(size_t requested_size) { 
    if (requested_size > PAGE_SIZE - sizeof(Header)) {
        return NULL;
    }
    if (free_list == NULL) {
        if (mem_init() == FAILURE) {
            return NULL;
        }
    }
    int aligned_size = requested_size + ((WORD_SIZE - (requested_size % WORD_SIZE)) % WORD_SIZE);
    Header * header = free_list;
    while (header->next != NULL && (is_allocated(header) || header->size < requested_size)) {
        header = header->next;
    }   
    if (is_allocated(header) || header->size < requested_size) {
        if (mem_extend(header) == FAILURE) {
            return NULL;
        }
        header = header -> next;
    }
    if (header->size > (aligned_size + sizeof(Header))) {
        Header * new_header = (Header *)((char *)header + sizeof(Header) + aligned_size);
        new_header->size = header->size - aligned_size - sizeof(Header);
        header->size = aligned_size;
        new_header->next = header->next;
        header->next = new_header;
        new_header->previous = header;
        if (new_header->next != NULL) {
            new_header->next->previous = new_header;
        }     
    }
    set_allocated(header);
    return (void *)((char *)header + sizeof(Header));
}

void mem_free(void * ptr) {
    Header * header = get_header(ptr);
    set_free(header); 
    if (header->next != NULL) {
         if (same_page(header, header->next) && is_free(header->next)) {
            header->size += header->next->size + sizeof(Header);
            if (header->next->next == NULL) {
                header->next = NULL;
            } else {       
                header->next = header->next->next;
                header->next->previous = header;
            }
        } 
    }
    if (header->previous != NULL) {
        if (same_page(header, header->previous) && is_free(header->previous)) {
            header->previous->size += header->size + sizeof(Header);
            header->next->previous = header->previous;
            header->previous->next = header->next;
            header = header->previous;
        }
    }
    if (header->size == PAGE_SIZE - sizeof(Header)){
        if (header->previous != NULL && header->next != NULL) {
            header->next->previous = header->previous;
            header->previous->next = header->next;
        } else if (header->previous != NULL) {
            header->previous->next = NULL;  
        } else if (header->next != NULL) {
            free_list = header->next;
            header->next->previous = NULL;
        } else { 
            free_list = NULL; 
        }
        munmap(header, PAGE_SIZE - sizeof(Header));
    }
}
