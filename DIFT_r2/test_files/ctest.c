#include <stdio.h>
#include <stdlib.h>
#include <r_socket.h>
#include "ao_functions.h"

static void r2cmd(R2Pipe *r2, const char *cmd) {
    char *msg = r2p_cmd (r2, cmd);
    if (msg) {
        printf ("%s\n", msg);
        free (msg);
    }
}

//perform the action don't print
static void r2cmd_quiet(R2Pipe *r2, const char *cmd) {
    char *msg = r2p_cmd (r2, cmd);
    if (msg) {
        free (msg);
    }
}
//return the string for analysis
char *r2cmd_r(R2Pipe *r2, const char *cmd) {
    char *msg = r2p_cmd (r2, cmd);
    if (msg) {
        return(msg);
    }
    return NULL;
}

int arg_len(char *arg)
{
    for (int i = 1; i < 0xffff; i++) {
        if(arg[i] == '\0') {
            return i;
        }
        i += 1;
    }
    return 0;
}
int find_end(R2Pipe *r2)
{
    char *ao = r2cmd_r(r2, "ao");
    char cmd_str [100];
    //must free all returns from r2cmd_r
    int loc = 1;
    ao_data_t ao_st;

    while(true){
        ao_st = parse_ao(ao);
        free(ao);
        loc += ao_st.size;
        if (strcmp(ao_st.opcode, "ret") == 0) {
            long int ret = (long int) strtol(ao_st.address, (char**)NULL, 16);
            free_ao_members(&ao_st);
            return ret;
        }
        free_ao_members(&ao_st);
        sprintf(cmd_str, "s `dr? rip` + %d",loc);
        r2cmd_quiet(r2, cmd_str);
        ao = r2cmd_r(r2, "ao");
        if (ao == NULL)
           printf("Error.62");
    }
    return 0;
}

void dump_esil_to_end(R2Pipe *r2, long int end)
{
    ao_data_t ao_struct;
    char end_address[32];
    sprintf(end_address, "0x%x",end);

    char cmd_str [100];
    r2cmd_quiet(r2, "s `dr? rip`");

    char *ao = r2cmd_r(r2, "ao");
    ao_struct = parse_ao(ao);
    free(ao);

    while(strcmp(end_address, ao_struct.address) != 0) {
    /*
     * print opcode: stuff
             esil: stuff
     step instruction
     seek to new eip
     repete
     */
        printf("address: %s\n", ao_struct.address);
        printf("opcode: %s\n", ao_struct.opcode);
        printf("esil: %s\n", ao_struct.esil);
        free_ao_members(&ao_struct);
        r2cmd_quiet(r2, "ds;s `dr? rip`");
        ao = r2cmd_r(r2, "ao");
        ao_struct = parse_ao(ao);
        free(ao);
    }
    free_ao_members(&ao_struct);

}

int main(int argc, char *argv[])
{
    char *open_str = (char *)calloc(arg_len(argv[1]), sizeof(char));
    sprintf(open_str, "r2 -q0 %s", argv[1]);
    R2Pipe *r2 = r2p_open (open_str);
    free(open_str);
    //make sure it opened up right
    if (!r2) {
        perror("ERROR");
        return 1;
    }

    r2cmd(r2, "ood");
    r2cmd(r2, "db main");
    r2cmd(r2, "dc");
    //r2cmd(r2, "pd");
    long int end = find_end(r2);
    printf("0x%x\n",end);
    dump_esil_to_end(r2, end);
    r2p_close(r2);
    return 0;
}
