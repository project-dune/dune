
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>

#define EXECPGSIZE 4096

extern char **environ;
const char *sandbox_path = "./sandbox";
const char *ld_path = "/lib64/ld-linux-x86-64.so.2";

int
getlen(char *const arr[])
{
    int i;

    for (i = 0; arr[i] != NULL; i++)
        ;

    return i;
}

int
exec_execev(const char *filename, char *const argv[], char *const envp[])
{
    int fd;
    int len;
    char page[EXECPGSIZE];

    fd = open(filename, O_RDONLY);
    if (fd < 0) {
        return -errno;
    }

    len = read(fd, page, EXECPGSIZE);
    if (len < 2) {
        return -ENOEXEC;
    }

    close(fd);

    if (len < EXECPGSIZE)
        page[len] = 0;

    if (page[0] == 0x7f && page[1] == 'E' && page[2] == 'L'&& page[3] == 'F') {
        int i;
        int arglen = getlen(argv);
        const char **new_argv = (const char **)malloc(sizeof(char *)*(arglen+4));

        //printf("ELF!\n");

        new_argv[0] = sandbox_path;
        new_argv[1] = ld_path;
        for (i = 0; i <= arglen; i++)
            new_argv[i + 2] = argv[i];
        new_argv[arglen + 3] = NULL;

        /*for (i = 0; new_argv[i] != NULL; i++)
            printf("'%s' ", new_argv[i]);
        printf("\n");*/

        int status = fork();
        if (status < 0)
            return status;
        else if (status > 0)
            exit(0);

        execve(sandbox_path, (char* const*)new_argv, envp);
        // We can't handle this case currently...
        assert(false);

        return -errno;
    }

    if (page[0] == '#' || page[1] == '!') {
        bool no_args;
        int i;
        int arglen = getlen(argv);
        const char **new_argv = (const char **)malloc(sizeof(char *)*(arglen+7));

        //printf("SHELL!\n");

        // Parse interpreter and arguments.  According to FreeBSD's historical 
        // note in sys/kern/imgact_shell.c the most compatible behavoir is to 
        // parse all interpreter arguements as a single argv into the 
        // application.  If there are no arguements the first arguement will be 
        // the script itself.  Parsing excess whitespace from the beginning and 
        // end is optional and most systems do not do that.

        // Call sandbox with the following arguements:
        // /lib64/ld... <interp> <argstring> <script> <arg1> ... <argn>

        for (i = 2; i < EXECPGSIZE; i++) {
            if (page[i] != ' ' && page[i] != '\t')
                break;
        }
        int interp_begin = i;
        for (; i < EXECPGSIZE; i++) {
            if (page[i] == ' ' || page[i] == '\t' ||
                page[i] == '\n' || page[i] == '\0')
                break;
        }
        int interp_end = i;
        if (interp_begin == interp_end || page[interp_begin] == '\0') {
            return -ENOEXEC;
        }

        int arg_begin, arg_end;
        if (page[interp_end] == '\n') {
            no_args = true;
        } else {
            no_args = false;
            for (; i < EXECPGSIZE; i++) {
                if (page[i] == '\n' || page[i] == '\0')
                    break;
            }

            arg_begin = interp_end + 1;
            arg_end = i;
            page[i] = '\0';
        }
        page[interp_end] = '\0';

        new_argv[0] = sandbox_path;
        new_argv[1] = ld_path;
        new_argv[2] = page + interp_begin;
        if (no_args) {
            new_argv[3] = filename;
            for (i = 0; i <= arglen; i++)
                new_argv[i + 4] = argv[i];
            new_argv[arglen + 5] = NULL;
        } else {
            new_argv[3] = page + arg_begin;
            new_argv[4] = filename;
            for (i = 0; i <= arglen; i++)
                new_argv[i + 5] = argv[i];
            new_argv[arglen + 6] = NULL;
        }

        /*for (i = 0; new_argv[i] != NULL; i++)
            printf("'%s' ", new_argv[i]);
        printf("\n");*/

        int status = fork();
        if (status < 0)
            return status;
        else if (status > 0)
            exit(0);

        execve(sandbox_path, (char* const*)new_argv, envp);
        // We can't handle this case currently...
        assert(false);

        return -errno;
    }

    return -ENOEXEC;
}

#ifdef TEST_EXEC

int main(int argc, char *argv[])
{
    char *const args[] = { NULL };

    //exec_execev("/bin/ls", args, environ);
    //exec_execev("test.sh", args, environ);

    return 0;
}

#endif /* TEST_EXEC */

