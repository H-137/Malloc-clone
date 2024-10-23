/*
 * Author: Amittai Aviram - aviram@bc.edu
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mem_alloc.h"

void print_list();
void print_header(Header *);
Header * get_header(void *);

int main() {
    print_list();
    puts("Allocating \"test.\"");
    char * test = (char *) mem_alloc(5);
    print_header(get_header(test));
    strcpy(test, "BC");
    puts(test);
    puts("Allocating \"nums.\"");
    int * nums = (int *) mem_alloc(128 * sizeof(int));
    print_header(get_header(nums));
    for (int i = 0; i < 128; ++i) {
        nums[i] = i + 1;
    }
    for (int i = 0; i < 128; ++i) {
        printf("%d ", nums[i]);
    }
    putchar('\n');
    print_list();
    puts("Allocating \"nums2.\"");
    long * nums2 = (long *) mem_alloc(509 * sizeof(long));
    for (int i = 0; i < 509; ++i) {
        nums2[i] = 509 - i;
    }
    print_list();
    puts("Freeing \"nums.\"");
    mem_free(nums);
    print_list();
    puts("Freeing \"test.\"");
    mem_free(test);
    print_list();
    puts("Allocating \"nums.\"");
    nums = (int *) mem_alloc(128 * sizeof(int));
    print_list();
    puts("Freeing \"nums2.\"");
    mem_free(nums2);
    print_list();
    puts("Freeing \"nums.\"");
    mem_free(nums);
    print_list();
    puts("Allocating \"test.\"");
    test = (char *) mem_alloc(5);
    strcpy(test, "BC");
    puts(test);
    puts("Freeing \"test.\"");
    mem_free(test);
    print_list();

    return EXIT_SUCCESS;
}

