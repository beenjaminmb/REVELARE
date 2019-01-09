#ifndef _AO_FUNCTIONS_H
#define _AO_FUNCTIONS_H 1

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

typedef struct ao_data{
    char* address;
    char* opcode;
    char* mnemonic;
    int prefix;
    int id;
    int bytes;
    int refptr;
    int size;
    int val;
    char* type;
    char* ptr;
    char* reg;
    char* esil;
    char* stack;
    char* family;
}ao_data_t;

void print_ao(ao_data_t * ao);
ao_data_t parse_ao(char * ao_string);
void free_ao_members(ao_data_t *ao);
char* skip_and_copy_string(ao_data_t *ao_struct, char *src, void **dst, int skip_bytes);
char* skip_and_copy_int(ao_data_t *ao_struct, char *src, int *dst, int skip_bytes, int base);

#endif /*_AO_FUNCTIONS_H*/
