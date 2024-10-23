# Author: Matthew Leopold - leoplmb@bc.edu

CC = gcc
FLAGS = -Wall -Werror -std=gnu99
APP = mem_alloc

all: mem_alloc test

mem_alloc: $(APP).c main.c
	$(CC) $(FLAGS) $^ -o $@

test: $(APP).c main.c
	$(CC) $(FLAGS) $^ -o $@

clean:
	rm -rf mem_alloc test
