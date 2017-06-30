#include <stdio.h> 
#include <stdlib.h> 
#include <sys/types.h> 
#include <unistd.h> 
#include<string.h>

char* implode(char** pstr, size_t count, char* dst, size_t dst_size) {
    uid_t i = 0, j = 0; 
    char* p = dst;

    for(i = 0; i < count; i++) {
        size_t ln = strlen(pstr[i]);

        for(j = 0; j < ln; j++) {
            if (p - dst >= dst_size) {
                break;
            }

            *p++ = pstr[i][j];
        }

        *p++ = ' ';
    }

     *p = 0;

     return p;
}

int main(int argc, char* argv[], char *envp[]) { 
    uid_t uid = 0, euid = 0; 
#define BUFFER_SIZE 40 * 1024
    char buffer[BUFFER_SIZE] = {0};

    uid = getuid() ; 
    euid = geteuid(); 

    if(setreuid(euid, uid)) {
        printf("Warning: %d => %d error", uid, euid);
        return 0;
    }

    implode(argv + 1, argc - 1, buffer, BUFFER_SIZE);

    if (buffer[0] == 0) {
        return 0;
    }

#define FOR_TEST 0
#if !FOR_TEST
    system(buffer);
#else
    // path
    {
        int i = 0;
        while(envp[i]) {
            printf("%d: %s\n", i, envp[i]), i++;
        }
    }

    // popen
    {
        FILE *ls = popen(buffer, "r");
        char buf[256];
        int i = 0;
        while (fgets(buf, sizeof(buf), ls) != 0) {
            printf("> %s", buf);
            i++;
        }
        pclose(ls);

        printf("*** (%d) ****", i);
    }
#endif
    return 0; 
}