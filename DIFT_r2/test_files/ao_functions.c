#include "ao_functions.h"

/*
 *Not sure I need this right now, but I probably will later
 * */
void print_ao(ao_data_t * ao)
{
    if(ao->address != NULL){
        printf("address -> %s\n", ao->address);
    }
    if(ao->opcode != NULL){
        printf("opcode -> %s\n", ao->opcode);
    }
    if(ao->mnemonic != NULL){
        printf("mnemonic -> %s\n", ao->mnemonic);
    }
    printf("prefix -> %d\n", ao->prefix);
    printf("id -> %d\n", ao->id);
    printf("bytes -> %d\n", ao->bytes);
    printf("val -> %d\n", ao->val);
    printf("refptr -> %d\n", ao->refptr);
    printf("size -> %d\n", ao->size);
    if(ao->type != NULL){
        printf("type -> %s\n", ao->type);
    }
    if(ao->esil != NULL){
        printf("esil -> %s\n", ao->esil);
    }
    if(ao->stack != NULL){
        printf("stack -> %s\n", ao->stack);
    }
    if(ao->ptr != NULL){
        printf("stack -> %s\n", ao->ptr);
    }
    if(ao->family != NULL){
        printf("family -> %s\n\n", ao->family);
    }
}

ao_data_t parse_ao(char * ao_string)
{
    ao_data_t ao_st;

    ao_st.address = NULL;
    ao_st.opcode = NULL;
    ao_st.mnemonic = NULL;
    ao_st.type = NULL;
    ao_st.esil = NULL;
    ao_st.stack = NULL;
    ao_st.family = NULL;
    ao_st.ptr = NULL;
    ao_st.reg = NULL;
    ao_st.refptr = 0;
    ao_st.prefix = 0;
    ao_st.id = 0;
    ao_st.bytes = 0;
    ao_st.size = 0;
    ao_st.val = 0;
    int loop_on = 1;

    while (loop_on == 1) {
        switch(ao_string[0]){
            case 'a':
                //address
                ao_string = skip_and_copy_string(&ao_st, ao_string, (void*)&ao_st.address, 9);
                break;
            case 'o':
                //opcode
                ao_string = skip_and_copy_string(&ao_st, ao_string, (void*)&ao_st.opcode, 8);
                break;
            case 'm':
                //mnemonic
                ao_string = skip_and_copy_string(&ao_st, ao_string, (void*)&ao_st.mnemonic, 10);
                break;
            case 'p':
                //prefix or ptr
                if (ao_string[1] == 'r'){
                    ao_string = skip_and_copy_int(&ao_st, ao_string, (void*)&ao_st.prefix, 8, 10);
                }
                else {
                    ao_string = skip_and_copy_string(&ao_st, ao_string, (void*)&ao_st.ptr, 5);
                }
                break;
            case 'i':
                //id
                ao_string = skip_and_copy_int(&ao_st, ao_string, (void*)&ao_st.id, 4, 10);
                break;
            case 'b':
                //bytes
                ao_string = skip_and_copy_int(&ao_st, ao_string, (void*)&ao_st.bytes, 7, 16);
                break;
            case 's':
                //size or stack
                if (ao_string[1] == 'i'){
                    ao_string = skip_and_copy_int(&ao_st, ao_string, (void*)&ao_st.size, 6, 10);
                }
                else {
                    ao_string = skip_and_copy_string(&ao_st, ao_string, (void*)&ao_st.stack, 7);
                }
                break;
            case 't':
                //type
                ao_string = skip_and_copy_string(&ao_st, ao_string, (void*)&ao_st.type, 6);
                break;
            case 'r':
                //reg or refptr
                if (ao_string[2] == 'f'){
                    ao_string = skip_and_copy_int(&ao_st, ao_string, (void*)&ao_st.refptr, 8, 10);
                }
                else {
                ao_string = skip_and_copy_string(&ao_st, ao_string, (void*)&ao_st.reg, 5);
                }
                break;
            case 'e':
                //esil
                ao_string = skip_and_copy_string(&ao_st, ao_string, (void*)&ao_st.esil, 6);
                break;
            case 'f':
                //family
                ao_string = skip_and_copy_string(&ao_st, ao_string, (void*)&ao_st.family, 8);
                loop_on = 0;
                break;
            case 'v':
                ao_string = skip_and_copy_int(&ao_st, ao_string, (void*)&ao_st.val, 5, 16);
                break;
            default:
                loop_on = 0;
        }
    }
    return ao_st;
}

void free_ao_members(ao_data_t *ao)
{
    if (ao->address != NULL) {
        free(ao->address);
    }
    if (ao->opcode != NULL) {
        free(ao->opcode);
    }
    if (ao->mnemonic != NULL) {
        free(ao->mnemonic);
    }
    if (ao->type != NULL) {
        free(ao->type);
    }
    if (ao->esil != NULL) {
        free(ao->esil);
    }
    if (ao->stack != NULL) {
        free(ao->stack);
    }
    if (ao->family != NULL) {
        free(ao->family);
    }
    if (ao->ptr != NULL) {
        free(ao->ptr);
    }
    if (ao->reg != NULL) {
        free(ao->reg);
    }
}

/*
 * skips 'skip_bytes' in 'src' and writes bytes from there to newline in 'dst'
 * returns current position in src
 * */
char* skip_and_copy_string(ao_data_t *ao_struct, char *src, void **dst, int skip_bytes)
{
    //skip past the key in the string so we can get the value
    src += skip_bytes;
    //go till you hit a newline
    int i = 0;
    while (src[0] != '\n'){
        src++;
        i += 1;
    }
    //allocate string size plus 1 for the null byte
    char *copy_loc = (char *) malloc(sizeof(char) * i + 1);
    memcpy (copy_loc, src - i,i);
    copy_loc[i] = '\0';
    //move past newline
    src += 1;
    //set struct member
    *dst = copy_loc;
    return src;
}

/*
 * skips 'skip_bytes' in 'src' and writes bytes from there to newline in 'dst'
 * returns current position in src
 * */
char* skip_and_copy_int(ao_data_t *ao_struct, char *src, int *dst, int skip_bytes, int base)
{
    //skip past the key in the string so we can get the value
    //data is of the form "key: value"
    src += skip_bytes;
    int i = 0;
    //go till you hit a newline
    while (src[0] != '\n'){
        src++;
        i += 1;
    }
    //allocate string size plus 1 for the null byte
    char *copy_loc = (char *) malloc(sizeof(char) * i + 1);
    memcpy (copy_loc, src - i,i);
    copy_loc[i] = '\0';
    //move past newline
    src += 1;
    //set struct member
    *dst = (int) strtol(copy_loc, (char **)NULL, base);
    //free the mallocs!
    free(copy_loc);
    return src;
}
