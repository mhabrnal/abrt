/*
 * Copyright (C) 2014  ABRT team
 * Copyright (C) 2014  RedHat Inc
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
#include "libabrt.h"
#include "abrt-journal.h"

#define ABRT_JOURNAL_WATCH_STATE_FILE VAR_STATE"/abrt-dump-journal-core.state"

typedef struct
{
    const char *awc_dump_location;
    int awc_throttle;
}
abrt_watch_core_conf_t;

static int
abrt_journal_get_last_occurrence(const char *executable)
{
    return 0;
}

static void
abrt_journal_update_occurrence(const char *executable, int ts)
{
    return;
}

static int
abrt_journal_core_to_problem(abrt_journal_t *journal, problem_data_t **pd)
{
    // verify journal data
    //   don not dump abrt related executables in order to avoid recursion
    //   skip signals
    //   check required fields (executable, proc_pid_status)
    //
    // generate reason ...
    //
    // for each journald message field - problem_data_add

    return 0;
}

static int
abrt_journal_problem_add_metadata(problem_data_t *pd)
{
    problem_data_add_text_noteditable(pd, FILENAME_ANALYZER, "CCpp");
    problem_data_add_text_noteditable(pd, FILENAME_TYPE, "CCpp");
    problem_data_add_text_noteditable(pd, FILENAME_ABRT_VERSION, VERSION);

    // parse fsuid from proc_pid_status ...

    return 0;
}

static int
abrt_journal_problem_submit(problem_data_t *pd, const char *dump_location)
{
    // save problem data with fsuid

    return 0;
}

static int
abrt_journal_dump_core(abrt_journal_t *journal, const char *dump_location)
{
    problem_data_t *pd;
    if (abrt_journal_core_to_problem(journal, &pd))
    {
        return -1;
    }

    return 0;
}

static void
abrt_journal_watch_cores(abrt_journal_watch_t *watch, void *user_data)
{
    const abrt_watch_core_conf_t *conf = (const abrt_watch_core_conf_t *)user_data;

    problem_data_t *pd = NULL;
    if (abrt_journal_core_to_problem(abrt_journal_watch_get_journal(watch), &pd))
    {
        error_msg(_("Failed to obtain all required information from journald"));
        return;
    }

    const char *exe = problem_data_get_content_or_die(pd, FILENAME_EXECUTABLE);
    if (exe == NULL)
    {
        error_msg("BUG: a valid problem data misses '"FILENAME_EXECUTABLE"'");
        goto watch_cleanup;
    }

    // do not dump too often
    //   ignore crashes of a single executable appearing in THROTTLE s (keep last 10 executable)
    //const int current = get_current_stamp();
    const int current = INT_MAX;
    const int last = abrt_journal_get_last_occurrence(exe);
    const int sub = current - last;
    if (sub < conf->awc_throttle)
    {
        /* We don't want to update the counter here. */
        error_msg(_("Not saving repeating crash after %ds (limit is %ds)"), sub, conf->awc_throttle);
        goto watch_cleanup;
    }

    if (abrt_journal_problem_add_metadata(pd))
    {
        error_msg(_("Failed to obtain information about system required by ABRT"));
        goto watch_cleanup;
    }

    if (abrt_journal_problem_submit(pd, conf->awc_dump_location))
    {
        error_msg(_("Failed to save detect problem data in abrt database"));
        goto watch_cleanup;
    }

    abrt_journal_update_occurrence(exe, current);

watch_cleanup:
    problem_data_free(pd);
    return;
}

static void
watch_journald(abrt_journal_t *journal, abrt_watch_core_conf_t *conf)
{
    abrt_journal_watch_t *watch = NULL;
    if (abrt_journal_watch_new(&watch, journal, abrt_journal_watch_cores, (void *)conf) < 0)
        error_msg_and_die(_("Failed to initialize systemd-journal watch"));

    abrt_journal_watch_run_sync(watch);
    abrt_journal_watch_free(watch);
}

int
main(int argc, char *argv[])
{
    /* I18n */
    setlocale(LC_ALL, "");
#if ENABLE_NLS
    bindtextdomain(PACKAGE, LOCALEDIR);
    textdomain(PACKAGE);
#endif

    abrt_init(argv);

    /* Can't keep these strings/structs static: _() doesn't support that */
    const char *program_usage_string = _(
        "& [-vsf] [-e]/[-c CURSOR] [-t INT]/[-T] [-d DIR]/[-D]\n"
        "\n"
        "Extract coredumps from systemd-journal\n"
        "\n"
        "-c and -e options conflicts because both specifies the first read message.\n"
        "\n"
        "-e is useful only for -f because the following of journal starts by reading \n"
        "the entire journal if the last seen possition is not available.\n"
        "\n"
        "The last seen position is saved in "ABRT_JOURNAL_WATCH_STATE_FILE"\n"
    );
    enum {
        OPT_v = 1 << 0,
        OPT_s = 1 << 1,
        OPT_d = 1 << 2,
        OPT_D = 1 << 3,
        OPT_c = 1 << 4,
        OPT_e = 1 << 5,
        OPT_t = 1 << 6,
        OPT_T = 1 << 7,
        OPT_f = 1 << 8,
    };

    char *cursor = NULL;
    char *dump_location = NULL;
    int throttle = 0;

    /* Keep enum above and order of options below in sync! */
    struct options program_options[] = {
        OPT__VERBOSE(&g_verbose),
        OPT_BOOL(  's', NULL, NULL, _("Log to syslog")),
        OPT_STRING('d', NULL, &dump_location, "DIR", _("Create new problem directory in DIR for every coredump")),
        OPT_BOOL(  'D', NULL, NULL, _("Same as -d DumpLocation, DumpLocation is specified in abrt.conf")),
        OPT_STRING('c', NULL, &cursor, "CURSOR", _("Start reading systemd-journal from the CURSOR position")),
        OPT_BOOL(  'e', NULL, NULL, _("Start reading systemd-journal from the end")),
        OPT_INTEGER('t', NULL, &throttle, _("Throttle problem directory creation to 1 per INT second")),
        OPT_BOOL(  'T', NULL, NULL, _("Same as -t INT, INT is specified in plugins/CCpp.conf")),
        OPT_BOOL(  'f', NULL, NULL, _("Follow systemd-journal from the last seen position (if available)")),
        OPT_END()
    };
    unsigned opts = parse_opts(argc, argv, program_options, program_usage_string);

    export_abrt_envvars(0);

    msg_prefix = g_progname;
    if ((opts & OPT_s) || getenv("ABRT_SYSLOG"))
        logmode = LOGMODE_JOURNAL;

    if ((opts & OPT_c) && (opts & OPT_e))
        error_msg_and_die(_("You need to specify either -c CURSOR or -e"));

    if (opts & OPT_D)
    {
        if (opts & OPT_d)
            show_usage_and_die(program_usage_string, program_options);
        load_abrt_conf();
        dump_location = g_settings_dump_location;
        g_settings_dump_location = NULL;
        free_abrt_conf_data();
    }

    const char *const env_journal_filter = getenv("ABRT_DUMP_JOURNAL_CORE_DEBUG_FILTER");
    static const char *coredump_journal_filter[2] = { 0 };
    coredump_journal_filter[0] = (env_journal_filter ? env_journal_filter : "SYSLOG_IDENTIFIER=systemd-coredump");
    log_debug("Using journal match: '%s'", coredump_journal_filter[0]);

    abrt_journal_t *journal = NULL;
    if (abrt_journal_new(&journal))
        error_msg_and_die(_("Cannot open systemd-journal"));

    if (abrt_journal_set_journal_filter(journal, coredump_journal_filter) < 0)
        error_msg_and_die(_("Cannot filter systemd-journal to systemd-coredump data only"));

    if ((opts & OPT_e) && abrt_journal_seek_tail(journal) < 0)
        error_msg_and_die(_("Cannot seek to the end of journal"));

    if ((opts & OPT_f))
    {
        if (!cursor)
            abrt_journal_restore_position(journal, ABRT_JOURNAL_WATCH_STATE_FILE);
        else if(abrt_journal_set_cursor(journal, cursor))
            error_msg_and_die(_("Failed to start watch from cursor '%s'"), cursor);

        abrt_watch_core_conf_t conf = {
            .awc_dump_location = dump_location,
            .awc_throttle = throttle,
        };

        watch_journald(journal, &conf);

        abrt_journal_save_current_position(journal, ABRT_JOURNAL_WATCH_STATE_FILE);
    }
    else
    {
        /* Beware: seeking to cursor here */
        if (cursor && abrt_journal_set_cursor(journal, cursor))
            error_msg_and_die(_("Failed to set systemd-journal cursor '%s'"), cursor);

        /* Compatibility hack, a watch's callback gets the journal already moved
         * to a next message.*/
        abrt_journal_next(journal);

        abrt_journal_dump_core(journal, dump_location);

        return 0;
    }

    abrt_journal_free(journal);

    return EXIT_SUCCESS;
}
