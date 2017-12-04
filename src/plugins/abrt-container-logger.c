/*
 * Copyright (C) 2018  ABRT team
 * Copyright (C) 2018  RedHat Inc
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <stdio.h>

#define INIT_PROC_STDERR_FD_PATH "/proc/1/fd/2"

int main(int argc, char *argv[])
{
    const char *program_usage_string =
        "Usage: abrt-container-logger STR"
        "\n"
        "\nThe tool opens "INIT_PROC_STDERR_FD_PATH" and writes a STR to it.";

    /* the tool expects one parameter STR */
    if (argc != 2)
    {
        fprintf(stderr, "%s\n", program_usage_string);
        return 1;
    }

    /* if any parameter passed, print usage */
    if (argv[1][0] == '-')
    {
        fprintf(stderr, "%s\n", program_usage_string);
        return 1;
    }

    FILE *f = fopen(INIT_PROC_STDERR_FD_PATH, "w");
    if (f == NULL)
    {
        fprintf(stderr, "Failed to open %s\n", INIT_PROC_STDERR_FD_PATH);
        return 1;
    }
    fprintf(f, "%s\n", argv[1]);
    fclose(f);

    return 0;
}
