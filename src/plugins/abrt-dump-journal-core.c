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

struct field_mapping {
    const char *name;
    const char *file;
} fields [] = {
    { .name = "COREDUMP_EXE",         .file = FILENAME_EXECUTABLE, },
    { .name = "COREDUMP_CMDLINE",     .file = FILENAME_CMDLINE, },
    { .name = "COREDUMP_PROC_STATUS", .file = FILENAME_PROC_PID_STATUS, },
    { .name = "COREDUMP_PROC_MAPS",   .file = FILENAME_MAPS, },
    { .name = "COREDUMP_PROC_LIMITS", .file = FILENAME_LIMITS, },
    { .name = "COREDUMP_PROC_CGROUP", .file = FILENAME_CGROUP, },
    { .name = "COREDUMP_ENVIRON",     .file = FILENAME_ENVIRON, },
    { .name = "COREDUMP_CWD",         .file = FILENAME_PWD, },
    { .name = "COREDUMP_ROOT",        .file = FILENAME_ROOTDIR, },
    { .name = "COREDUMP_OPEN_FDS",    .file = FILENAME_OPEN_FDS, },
    { .name = "COREDUMP_UID",         .file = FILENAME_UID, },
    //{ .name = "COREDUMP_GID",         .file = FILENAME_GID, },
    { .name = "COREDUMP_PID",         .file = FILENAME_PID, },
};

struct crash_info
{
    abrt_journal_t *journal;
    int signal_no;
    const char *signal_name;
    char *executable_path;
    const char *executable_name;
    uid_t uid;
    struct field_mapping *mapping;
    size_t mapping_items;
};

typedef struct
{
    const char *awc_dump_location;
    int awc_throttle;
}
abrt_watch_core_conf_t;


struct occurrence_queue
{
    int head;
    unsigned size;

    struct last_occurence
    {
        unsigned stamp;
        char *executable;
    } occurrences[8];

} s_queue = {
    .head = -1,
    .size = 8,
};

static unsigned
abrt_journal_get_last_occurrence(const char *executable)
{
    if (s_queue.head < 0)
        return 0;

    unsigned index = s_queue.head == 0 ? s_queue.size - 1 : s_queue.head - 1;
    for (unsigned i = 0; i < s_queue.size; ++i)
    {
        if (s_queue.occurrences[index].executable == NULL)
            break;

        if (strcmp(executable, s_queue.occurrences[index].executable) == 0)
            return s_queue.occurrences[index].stamp;

        if (index-- == 0)
            index = s_queue.size - 1;
    }

    return 0;
}

static void
abrt_journal_update_occurrence(const char *executable, unsigned ts)
{
    if (s_queue.head < 0)
        s_queue.head = 0;
    else
    {
        unsigned index = s_queue.head == 0 ? s_queue.size - 1 : s_queue.head - 1;
        for (unsigned i = 0; i < s_queue.size; ++i)
        {
            if (s_queue.occurrences[index].executable == NULL)
                break;

            if (strcmp(executable, s_queue.occurrences[index].executable) == 0)
            {
                /* Enhancemenet: move this entry right behind head */
                s_queue.occurrences[index].stamp = ts;
                return;
            }

            if (index-- == 0)
                index = s_queue.size - 1;
        }
    }

    s_queue.occurrences[s_queue.head].stamp = ts;
    free(s_queue.occurrences[s_queue.head].executable);
    s_queue.occurrences[s_queue.head].executable = xstrdup(executable);

    if (++s_queue.head >= s_queue.size)
        s_queue.head = 0;

    return;
}

static int
abrt_journal_core_to_problem(abrt_journal_t *journal, struct crash_info *info)
{
    // verify journal data
    //   don not dump abrt related executables in order to avoid recursion
    //   skip signals
    //   check required fields (executable, proc_pid_status)
    //
    if (abrt_journal_get_int_field(journal, "COREDUMP_SIGNAL", &(info->signal_no)) != 0)
    {
        log_info("Failed to get signal number from journal message");
        return -EINVAL;
    }

    if (!signal_is_fatal(info->signal_no, &(info->signal_name)))
    {
        log_info("Signal '%d' is not fatal: ignoring crash", info->signal_no);
        return 1;
    }

    info->executable_path = abrt_journal_get_string_field(journal, "COREDUMP_EXE", NULL);
    if (info->executable_path == NULL)
    {
        log_notice("Could not get crashed 'executable'.");
        return -ENOENT;
    }

    info->executable_name = strrchr(info->executable_path, '/');
    if (info->executable_name == NULL)
    {
        info->executable_name = info->executable_path;
    }
    else if(strncmp(++(info->executable_name), "abrt", 4) == 0)
    {
        error_msg("Ignoring crash of ABRT executable '%s'", info->executable_path);
        return 1;
    }

    if (abrt_journal_get_unsigned_field(journal, "COREDUMP_UID", &(info->uid)))
    {
        log_info("Failed to get UID from journal message");
        return -EINVAL;
    }

    char *proc_status = abrt_journal_get_string_field(journal, "COREDUMP_PROC_STATUS", NULL);
    if (proc_status == NULL)
    {
        log_info("Failed to get /proc/[pid]/status from journal message");
        return -ENOENT;
    }

    uid_t tmp_fsuid = get_fsuid(proc_status);
    if (tmp_fsuid < 0)
        return -EINVAL;

    /* atoi() is unsafe but I refuse to use xatoi() wich exits on errors nor
     * introduce a new function!!
     */
    if (tmp_fsuid != info->uid)
    {
        /* use root for suided apps unless it's explicitly set to UNSAFE */
        info->uid = (dump_suid_policy() != DUMP_SUID_UNSAFE) ? 0 : tmp_fsuid;
    }

    return 0;
}

static int
save_systemd_coredump_in_dump_directory(struct dump_dir *dd, struct crash_info *info)
{
    char coredump_path[PATH_MAX + 1];
    if (coredump_path != abrt_journal_get_string_field(info->journal, "COREDUMP_FILENAME", coredump_path))
    {
        log_info("Ignoring coredumpctl entry becuase it misses coredump file");
        return -1;
    }

    if (dd_copy_file(dd, FILENAME_COREDUMP, coredump_path))
        return -1;

    dd_save_text(dd, FILENAME_ABRT_VERSION, VERSION);
    dd_save_text(dd, FILENAME_TYPE, "CCpp");
    dd_save_text(dd, FILENAME_ANALYZER, "systemd-coredump");

    char *reason;
    if (info->signal_name != NULL)
        reason = xasprintf("%s killed by signal %d", info->executable_name, info->signal_no);
    else
        reason = xasprintf("%s killed by SIG%s", info->executable_name, info->signal_name);

    dd_save_text(dd, FILENAME_REASON, reason);
    free(reason);

    char *cursor = NULL;
    if (abrt_journal_get_cursor(info->journal, &cursor) == 0)
        dd_save_text(dd, "journald_cursor", cursor);
    free(cursor);

    for (size_t i = 0; i < info->mapping_items; ++i)
    {
        const char *data;
        size_t data_len;
        struct field_mapping *f = info->mapping + i;

        if (abrt_journal_get_field(info->journal, f->name, (const void **)&data, &data_len))
        {
            log_info("systemd-coredump journald message misses field: '%s'", f->name);
            continue;
        }

        dd_save_binary(dd, f->file, data, data_len);
    }

    return 0;
}

static int
abrt_journal_problem_submit(struct crash_info *info, const char *dump_location)
{
    struct dump_dir *dd = create_dump_dir(dump_location, "ccpp", info->uid,
            (save_data_call_back)save_systemd_coredump_in_dump_directory, info);

    if (dd != NULL)
    {
        char *path = xstrdup(dd->dd_dirname);
        dd_close(dd);
        notify_new_path(path);
        free(path);
    }

    return dd == NULL;
}

static int
abrt_journal_dump_core(abrt_journal_t *journal, const char *dump_location)
{
    struct crash_info info = { 0 };
    info.journal = journal;
    info.mapping = fields;
    info.mapping_items = sizeof(fields)/sizeof(*fields);

    int r = abrt_journal_core_to_problem(journal, &info);
    if (r != 0)
        goto dump_cleanup;

    r = abrt_journal_problem_submit(&info, dump_location);

dump_cleanup:
    if (info.executable_path != NULL)
        free(info.executable_path);

    return r;
}

static void
abrt_journal_watch_cores(abrt_journal_watch_t *watch, void *user_data)
{
    const abrt_watch_core_conf_t *conf = (const abrt_watch_core_conf_t *)user_data;

    struct crash_info info = { 0 };
    info.journal = abrt_journal_watch_get_journal(watch);
    info.mapping = fields;
    info.mapping_items = sizeof(fields)/sizeof(*fields);

    int r = abrt_journal_core_to_problem(abrt_journal_watch_get_journal(watch), &info);
    if (r)
    {
        if (r < 0)
            error_msg(_("Failed to obtain all required information from journald"));

        goto watch_cleanup;
    }

    // do not dump too often
    //   ignore crashes of a single executable appearing in THROTTLE s (keep last 10 executable)
    const unsigned current = time(NULL);
    const unsigned last = abrt_journal_get_last_occurrence(info.executable_path);

    if (current < last)
    {
        error_msg("BUG: current time stamp lower than an old one");

        if (g_verbose > 2)
            abort();

        goto watch_cleanup;
    }

    const unsigned sub = current - last;
    if (sub < conf->awc_throttle)
    {
        /* We don't want to update the counter here. */
        error_msg(_("Not saving repeating crash after %ds (limit is %ds)"), sub, conf->awc_throttle);
        goto watch_cleanup;
    }

    if (abrt_journal_problem_submit(&info, conf->awc_dump_location))
    {
        error_msg(_("Failed to save detect problem data in abrt database"));
        goto watch_cleanup;
    }

    abrt_journal_update_occurrence(info.executable_path, current);

watch_cleanup:
    abrt_journal_save_current_position(info.journal, ABRT_JOURNAL_WATCH_STATE_FILE);

    if (info.executable_path != NULL)
        free(info.executable_path);

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
        {
            abrt_journal_restore_position(journal, ABRT_JOURNAL_WATCH_STATE_FILE);
            abrt_journal_next(journal);
        }
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
