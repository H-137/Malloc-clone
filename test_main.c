/*
 * Author: Amittai Aviram - aviram@bc.edu
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mem_alloc.h"

// Debugging function forward declarations:
Header * get_header(void * mem);
size_t get_size(Header * header);
int same_page(Header * h1, Header * h2);
int is_allocated(Header * header);
int is_free(Header * header);

void print_list();

extern Header * free_list;

int main() {
    assert(!free_list);
    char * test = (char *) mem_alloc(5);
    Header * test_header = get_header(test);
    assert(test_header);
    assert(test_header == free_list);
    assert(get_size(test_header) == 8);
    assert(!test_header->previous);
    assert(test_header->next == (Header *)((char *)test_header + get_size(test_header) + sizeof(Header)));
    strcpy(test, "BC");
    assert(!strcmp(test, "BC"));
    int * nums = (int *) mem_alloc(128 * sizeof(int));
    assert(nums);
    Header * nums_header = get_header(nums);
    assert(nums_header == test_header->next);
    assert(nums_header->previous == test_header);
    assert(nums_header == free_list->next);
    assert(get_size(nums_header) == 128 * sizeof(int));
    assert(nums_header->next == (Header *)((char *)nums_header + get_size(nums_header) + sizeof(Header)));
    for (int i = 0; i < 128; ++i) {
        nums[i] = i + 1;
    }
    for (int i = 0; i < 128; ++i) {
        assert(nums[i] == i + 1);
    }
    assert(free_list == test_header);
    assert(free_list->next == nums_header);
    assert(free_list->next->next);
    assert(is_free(free_list->next->next));
    assert(!free_list->next->next->next);
    long * nums2 = (long *) mem_alloc(509 * sizeof(long));
    for (int i = 0; i < 509; ++i) {
        nums2[i] = 509 - i;
    }
    for (int i = 0; i < 509; ++i) {
        assert(nums2[i] == 509 - i);
    }
    Header * nums2_header = get_header(nums2);
    assert(get_size(nums2_header) == 509 * sizeof(long));
    assert(free_list == test_header);
    assert(free_list->next == nums_header);
    assert(free_list->next->next);
    assert(is_free(free_list->next->next));
    assert(free_list->next->next->next == nums2_header);
    assert(!free_list->next->next->next->next);
    assert(same_page(test_header, nums_header));
    assert(!same_page(test_header, nums2_header));
    assert(!same_page(nums_header, nums2_header));
    mem_free(nums);
    assert(free_list == test_header);
    assert(free_list->next == nums_header);
    assert(free_list->next->next == nums2_header);
    assert(!same_page(free_list, nums2_header));
    mem_free(test);
    assert(free_list == nums2_header);
    assert(!free_list->previous);
    assert(!free_list->next);
    nums = (int *) mem_alloc(128 * sizeof(int));
    nums_header = get_header(nums);
    assert(free_list == nums2_header);
    assert(free_list->next == nums_header);
    assert(free_list->next->next);
    assert(is_free(free_list->next->next));
    assert(!free_list->next->next->next);
    mem_free(nums2);
    assert(free_list == nums_header);
    assert(free_list->next && is_free(free_list->next));
    assert(!free_list->next->next);
    mem_free(nums);
    assert(!free_list);
    test = (char *) mem_alloc(5);
    test_header = get_header(test);
    assert(free_list == test_header);
    assert(free_list->next && is_free(free_list->next));
    assert(!test_header->previous);
    strcpy(test, "BC");
    assert(!strcmp(test, "BC"));
    mem_free(test);
    assert(!free_list);
    puts("All tests passed.");
    return EXIT_SUCCESS;
}
