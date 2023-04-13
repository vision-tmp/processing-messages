#include <stdio.h>
#include <stdlib.h>
#include <libgen.h>
#include <limits.h>
#include <string.h>
#include <unistd.h>
#include "process_messages.h"

int main (int argc, char **argv)
{
    int result;

    char *path_of_executable = dirname(argv[0]);
    if (NULL == path_of_executable) {
        fprintf(stderr, "%s", "Error with getting input file name\n");
        return 1;
    }
    DEBUG_STRING(path_of_executable);

    char in_file_name[PATH_MAX +1];
    char out_file_name[PATH_MAX +1];

    int length_of_slash = 1;
    if (strlen(path_of_executable) + length_of_slash + strlen(IN_FILE_NAME) > PATH_MAX) {
        fprintf(stderr, "%s", "Error with getting input file name\n");
        return 1;
    }
    strcpy(in_file_name, path_of_executable);
    strcat(in_file_name, "/");
    strcat(in_file_name, IN_FILE_NAME);
    DEBUG_STRING(in_file_name);

    if (strlen(path_of_executable) + length_of_slash + strlen(OUT_FILE_NAME) > PATH_MAX) {
        fprintf(stderr, "%s", "Error with getting output file name\n");
        return 1;
    }
    strcpy(out_file_name, path_of_executable);
    strcat(out_file_name, "/");
    strcat(out_file_name, OUT_FILE_NAME);
    DEBUG_STRING(out_file_name);

    options_t options;
    options.formatted_output = 0;

    int c;
    while ((c = getopt(argc, argv, "fh")) != -1) {
        switch (c) {
        case 'f':
            options.formatted_output = 1;
            break;
        case 'h':
            printf("Usage: %s [-f] [-h]\n", argv[0]);
            printf("\n'-f' is for writing to the output file in structured [f]ormat\n");
            return 0;
        default:
            abort();
        }
    }

    for (int i = optind; i < argc; i++) {
        fprintf(stderr, "Non-optional argument '%s'\n", argv[i]);
    }
    if (optind < argc)
        return 1;

    if ((result = process_all_messages(in_file_name, out_file_name, &options)) < 0) {
        fprintf(stderr, "%s\n", get_error_message(result));
        return result;
    }

    printf("The input file has been processed\n");
    return 0;
}
