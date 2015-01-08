/*
    Copyright (C) 2009  Jiri Moskovcak (jmoskovc@redhat.com)
    Copyright (C) 2009  RedHat inc.

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/
#if HAVE_LOCALE_H
# include <locale.h>
#endif
#include <X11/Xlib.h>
#include <X11/SM/SMlib.h>

#define GDK_DISABLE_DEPRECATION_WARNINGS
/* https://bugzilla.gnome.org/show_bug.cgi?id=734826 */
#include <gtk/gtk.h>

#include <libnotify/notify.h>
#include <dbus/dbus-shared.h>
#include <dbus/dbus-glib.h>
#include <dbus/dbus-glib-lowlevel.h>
#include <glib.h>

#include <libreport/internal_abrt_dbus.h>
#include <libreport/event_config.h>
#include <libreport/internal_libreport_gtk.h>
#include "libabrt.h"
#include "problem_api.h"

/* NetworkManager DBus configuration */
#define NM_DBUS_SERVICE "org.freedesktop.NetworkManager"
#define NM_DBUS_PATH  "/org/freedesktop/NetworkManager"
#define NM_DBUS_INTERFACE "org.freedesktop.NetworkManager"
#define NM_STATE_CONNECTED_LOCAL 50
#define NM_STATE_CONNECTED_SITE 60
#define NM_STATE_CONNECTED_GLOBAL 70

/* libnotify action keys */
#define A_KNOWN_OPEN_GUI "OPEN"
#define A_REPORT_REPORT "REPORT"
#define A_REPORT_AUTOREPORT "AUTOREPORT"

#define GUI_EXECUTABLE "gnome-abrt"

enum
{
    /*
     * with this flag show_problem_notification() shows only the old ABRT icon
     */
    SHOW_ICON_ONLY = 1 << 0,

    /*
     * show autoreport button on notification
     */
    JUST_DETECTED_PROBLEM = 1 << 1,
};


static GDBusConnection *g_system_bus;
static char **s_dirs;
static GtkApplication *g_application;
static GIOChannel *g_channel_id_signal;
static GList *g_notified_problems;
static GList *g_deferred_crash_queue;
static guint g_deferred_timeout;
static int g_signal_pipe[2];
static ignored_problems_t *g_ignore_set;
/* Used only for selection of the last notified problem if a user clicks on the systray icon */
static char *g_last_notified_problem_id;
static guint g_crash_signal_ret;
static guint g_nm_signal_ret;

static bool get_configured_bool_or_default(const char *opt_name, bool def)
{
    /* User config always takes precedence */
    load_user_settings("abrt-applet");
    const char *configured = get_user_setting(opt_name);
    if (configured)
        return string_to_bool(configured);

    return def;
}

static bool is_autoreporting_enabled(void)
{
    return get_configured_bool_or_default("AutoreportingEnabled", g_settings_autoreporting);
}

static bool is_ureport_auth_enabled(void)
{
    bool success, auth_enabled;
    map_string_t *settings = new_map_string();
    char *ureport_conf_path = concat_path_file(LIBREPORT_PLUGINS_CONF_DIR, "ureport.conf");

    success = load_conf_file(ureport_conf_path, settings, /*skipKeysWithoutValue*/false);
    if (success)
    {
        const char *value = get_map_string_item_or_NULL(settings, "SSLClientAuth");
        auth_enabled = (value && value[0] != '\0');
    }
    else
        auth_enabled = true; /* assume it is, do not claim the reporting is anonymous */

    free(ureport_conf_path);
    free_map_string(settings);

    return auth_enabled;
}

static const char *get_autoreport_event_name(void)
{
    load_user_settings("abrt-applet");
    const char *configured = get_user_setting("AutoreportingEvent");
    return configured ? configured : g_settings_autoreporting_event;
}

static void ask_start_autoreporting()
{
    struct strbuf *question = strbuf_new();
    question = strbuf_append_str(question,
         _("The report which will be sent does not contain any security sensitive data. "
           "Therefore it is not necessary to bother you next time and require any further action by you. \n"));

    if (is_ureport_auth_enabled())
    {
        question = strbuf_append_str(question,
            _("Do you want to enable automatically submitted crash reports?"));
    }
    else
    {
        question = strbuf_append_str(question,
            _("Do you want to enable automatically submitted anonymous crash reports?"));
    }

    /* The "Yes" response will be saved even if user don't check the
     * "Don't ask me again" box.
     */
    const int ret = run_ask_yes_no_save_result_dialog("AutoreportingEnabled", question->buf,
       /*parent wnd */ NULL);
    strbuf_free(question);

    load_user_settings("abrt-applet");

    /* Don't forget:
     *
     * The "Yes" response will be saved even if user don't check the
     * "Don't ask me again" box.
     */
    if (ret != 0)
        set_user_setting("AutoreportingEnabled", "yes");

    /* must be called immediately, otherwise the data could be lost in case of crash */
    save_user_settings();
}

static bool is_shortened_reporting_enabled()
{
    return get_configured_bool_or_default("ShortenedReporting", g_settings_shortenedreporting);
}

static bool is_silent_shortened_reporting_enabled(void)
{
    return get_configured_bool_or_default("SilentShortenedReporting", 0);
}

static bool is_notification_of_incomplete_problems_enabled(void)
{
    return get_configured_bool_or_default("NotifyIncompleteProblems", 0);
}

/*
 * Converts a NM state value stored in GVariant to boolean.
 *
 * Returns true if a state means connected.
 *
 * Sinks the args variant.
 */
static bool nm_state_is_connected(GVariant *args)
{
    GVariant *value = g_variant_get_child_value(args, 0);

    if (g_variant_is_of_type(value, G_VARIANT_TYPE_VARIANT))
    {
        GVariant *tmp = g_variant_get_child_value(value, 0);
        g_variant_unref(value);
        value = tmp;
    }

    int state = g_variant_get_uint32 (value);

    g_variant_unref(value);
    g_variant_unref(args);

    return state == NM_STATE_CONNECTED_GLOBAL
           || state == NM_STATE_CONNECTED_LOCAL
           || state == NM_STATE_CONNECTED_SITE;
}

/*
 * The function tries to get network state from NetworkManager over DBus
 * call. If NetworkManager DBus service is not available the function returns
 * true which means that network is enabled and up.
 *
 * Function must return true on any error, otherwise user won't be notified
 * about new problems. Because if network is not enabled, new problems are
 * pushed to the deferred queue. The deferred queue is processed immediately
 * after network becomes enabled. In case where NetworkManager is broken or not
 * available, notification about network state doesn't work thus the deferred
 * queue won't be ever processed.
 */
static bool is_networking_enabled(void)
{
    GError *error = NULL;

    /* Create a D-Bus proxy to get the object properties from the NM Manager
     * object.
     */
    const int flags = G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES
                      | G_DBUS_PROXY_FLAGS_DO_NOT_CONNECT_SIGNALS;

    GDBusProxy *props_proxy = g_dbus_proxy_new_sync(g_system_bus,
                                flags,
                                NULL /* GDBusInterfaceInfo */,
                                NM_DBUS_SERVICE,
                                NM_DBUS_PATH,
                                DBUS_INTERFACE_PROPERTIES,
                                NULL /* GCancellable */,
                                &error);

    if (!props_proxy)
    {
        /* The NetworkManager DBus service is not available. */
        error_msg (_("Can't connect to NetworkManager over DBus: %s"), error->message);
        g_error_free (error);

        /* Consider network state as connected. */
        return true;
    }

    /* Get the State property from the NM Manager object */
    GVariant *const value = g_dbus_proxy_call_sync (props_proxy,
                                "Get",
                                 g_variant_new("(ss)", NM_DBUS_INTERFACE, "State"),
                                 G_DBUS_PROXY_FLAGS_NONE,
                                 -1   /* timeout: use proxy default */,
                                 NULL /* GCancellable */,
                                 &error);

    /* Consider network state as connected if any error occurs */
    bool ret = true;

    if (!error)
        /* Convert the state value and sink the variable */
        ret = nm_state_is_connected(value);
    else
    {
        error_msg (_("Can't determine network status via NetworkManager: %s"), error->message);
        g_error_free (error);
    }

    g_object_unref(props_proxy);

    return ret;
}

static void show_problem_list_notification(GtkApplication* application, GList *problems, int flags);

static gboolean process_deferred_queue_timeout_fn(GList *queue)
{
    g_deferred_timeout = 0;
    show_problem_list_notification(g_application, queue, /* process these crashes as new crashes */ 0);

    /* Remove this timeout fn from the main loop*/
    return FALSE;
}

static void on_nm_state_changed(GDBusConnection *connection, const gchar *sender_name,
                                const gchar *object_path, const gchar *interface_name,
                                const gchar *signal_name, GVariant *parameters,
                                gpointer user_data)
{
    g_variant_ref(parameters);

    if (nm_state_is_connected(parameters))
    {
        if (g_deferred_timeout)
            g_source_remove(g_deferred_timeout);

        g_deferred_timeout = g_timeout_add(30 * 1000 /* give NM 30s to configure network */,
                                           (GSourceFunc)process_deferred_queue_timeout_fn,
                                           g_deferred_crash_queue);
    }
}

typedef struct problem_info {
    problem_data_t *problem_data;
    bool foreign;
    bool known;
    bool incomplete;
    bool reported;
    bool was_announced;
    bool is_writable;
} problem_info_t;

static void push_to_deferred_queue(problem_info_t *pi)
{
    g_deferred_crash_queue = g_list_append(g_deferred_crash_queue, pi);
}
static const char *problem_info_get_dir(problem_info_t *pi)
{
    return problem_data_get_content_or_NULL(pi->problem_data, CD_DUMPDIR);
}

static void problem_info_set_dir(problem_info_t *pi, const char *dir)
{
    problem_data_add_text_noteditable(pi->problem_data, CD_DUMPDIR, dir);
}

static bool problem_info_ensure_writable(problem_info_t *pi)
{
    if (pi->is_writable)
        return true;

    /* chown the directory in any case, because kernel oopses are not foreign */
    /* but their dump directories are not writable without chowning them or */
    /* stealing them. The stealing is deprecated as it breaks the local */
    /* duplicate search and root cannot see them */
    const int res = chown_dir_over_dbus(problem_info_get_dir(pi));
    if (pi->foreign && res != 0)
    {
        error_msg(_("Can't take ownership of '%s'"), problem_info_get_dir(pi));
        return false;
    }
    pi->foreign = false;

    struct dump_dir *dd = open_directory_for_writing(problem_info_get_dir(pi), /* don't ask */ NULL);
    if (!dd)
    {
        error_msg(_("Can't open directory for writing '%s'"), problem_info_get_dir(pi));
        return false;
    }

    problem_info_set_dir(pi, dd->dd_dirname);
    pi->is_writable = true;
    dd_close(dd);
    return true;
}

static problem_info_t *problem_info_new(const char *dir)
{
    problem_info_t *pi = xzalloc(sizeof(*pi));
    pi->problem_data = problem_data_new();
    problem_info_set_dir(pi, dir);
    return pi;
}

static void problem_info_free(problem_info_t *pi)
{
    if (pi == NULL)
        return;

    problem_data_free(pi->problem_data);
    free(pi);
}

static void add_to_notified_list(problem_info_t *pi)
{
    g_notified_problems = g_list_prepend(g_notified_problems, pi);
}

static problem_info_t *remove_from_notified_list(const char *problem_dir)
{
    problem_info_t *result = NULL;
    GList *iter = g_notified_problems;

    while (iter != NULL)
    {
        problem_info_t *pi = (problem_info_t *)iter->data;

        /* All have '/var/tmp/abr/' prefix ... :( */
        if (strcmp(problem_dir, problem_info_get_dir(pi)) == 0)
        {
            if (result == NULL)
                result = pi;
            else
                problem_info_free(pi);

            GList *removed = iter;
            iter = g_list_next(iter);

            g_notified_problems = g_list_remove_link(g_notified_problems, removed);
        }
        else
            iter = g_list_next(iter);
    }

    return result;
}

static void run_event_async(GtkApplication *application, problem_info_t *pi, const char *event_name, int flags);

enum {
    REPORT_UNKNOWN_PROBLEM_IMMEDIATELY = 1 << 0,
};

struct event_processing_state
{
    pid_t child_pid;
    int   child_stdout_fd;
    struct strbuf *cmd_output;

    problem_info_t *pi;
    GtkApplication *app;
    int flags;
};

static struct event_processing_state *new_event_processing_state(void)
{
    struct event_processing_state *p = xzalloc(sizeof(*p));
    p->child_pid = -1;
    p->child_stdout_fd = -1;
    p->cmd_output = strbuf_new();
    return p;
}

static void free_event_processing_state(struct event_processing_state *p)
{
    if (!p)
        return;

    strbuf_free(p->cmd_output);
    free(p);
}

static char *build_message(problem_info_t *pi)
{
    char *package_name = problem_data_get_content_or_NULL(pi->problem_data, FILENAME_COMPONENT);

    char *msg = NULL;
    if (package_name == NULL || package_name[0] == '\0')
        msg = xasprintf(_("A problem has been detected"));
    else
        msg = xasprintf(_("A problem in the %s package has been detected"), package_name);

    if (pi->incomplete)
    {
        const char *not_reportable = problem_data_get_content_or_NULL(pi->problem_data, FILENAME_NOT_REPORTABLE);
        log_notice("%s", not_reportable);
        if (not_reportable)
            msg = xasprintf("%s\n\n%s", msg, not_reportable);
    }
    else if (pi->reported)
        msg = xasprintf(_("%s and the diagnostic data has been submitted"), msg);

    return msg;
}

static GList *add_dirs_to_dirlist(GList *dirlist, const char *dirname)
{
    DIR *dir = opendir(dirname);
    if (!dir)
        return dirlist;

    struct dirent *dent;
    while ((dent = readdir(dir)) != NULL)
    {
        if (dot_or_dotdot(dent->d_name))
            continue;
        char *full_name = concat_path_file(dirname, dent->d_name);
        struct stat statbuf;
        if (lstat(full_name, &statbuf) == 0 && S_ISDIR(statbuf.st_mode))
            dirlist = g_list_prepend(dirlist, full_name);
        else
            free(full_name);
    }
    closedir(dir);

    return g_list_reverse(dirlist);
}

/* Compares the problem directories to list saved in
 * $XDG_CACHE_HOME/abrt/applet_dirlist and updates the applet_dirlist
 * with updated list.
 *
 * @param new_dirs The list where new directories are stored if caller
 * wishes it. Can be NULL.
 */
static void new_dir_exists(GList **new_dirs)
{
    GList *dirlist = NULL;
    char **pp = s_dirs;
    while (*pp)
    {
        dirlist = add_dirs_to_dirlist(dirlist, *pp);
        pp++;
    }

    const char *cachedir = g_get_user_cache_dir();
    char *dirlist_name = concat_path_file(cachedir, "abrt");
    g_mkdir_with_parents(dirlist_name, 0777);
    free(dirlist_name);
    dirlist_name = concat_path_file(cachedir, "abrt/applet_dirlist");
    FILE *fp = fopen(dirlist_name, "r+");
    if (!fp)
        fp = fopen(dirlist_name, "w+");
    free(dirlist_name);
    if (fp)
    {
        GList *old_dirlist = NULL;
        char *line;
        while ((line = xmalloc_fgetline(fp)) != NULL)
            old_dirlist = g_list_prepend(old_dirlist, line);

        old_dirlist = g_list_reverse(old_dirlist);
        /* We will sort and compare current dir list with last known one.
         * Possible combinations:
         * DIR1 DIR1 - Both lists have the same element, advance both ptrs.
         * DIR2      - Current dir list has new element. IOW: new dir exists!
         *             Advance only current dirlist ptr.
         *      DIR3 - Only old list has element. Advance only old ptr.
         * DIR4 ==== - Old list ended, cuurent one didn't. New dir exists!
         * ====
         */
        GList *l1 = dirlist = g_list_sort(dirlist, (GCompareFunc)strcmp);
        GList *l2 = old_dirlist = g_list_sort(old_dirlist, (GCompareFunc)strcmp);
        int different = 0;
        while (l1 && l2)
        {
            int diff = strcmp(l1->data, l2->data);
            different |= diff;
            if (diff < 0)
            {
                if (new_dirs)
                {
                    *new_dirs = g_list_prepend(*new_dirs, xstrdup(l1->data));
                    log_notice("New dir detected: %s", (char *)l1->data);
                }
                l1 = g_list_next(l1);
                continue;
            }
            l2 = g_list_next(l2);
            if (diff == 0)
                l1 = g_list_next(l1);
        }

        different |= (l1 != NULL);
        if (different && new_dirs)
        {
            while (l1)
            {
                *new_dirs = g_list_prepend(*new_dirs, xstrdup(l1->data));
                log_notice("New dir detected: %s", (char *)l1->data);
                l1 = g_list_next(l1);
            }
        }

        if (different || l2)
        {
            rewind(fp);
            if (ftruncate(fileno(fp), 0)) /* shut up gcc */;
            l1 = dirlist;
            while (l1)
            {
                fprintf(fp, "%s\n", (char*) l1->data);
                l1 = g_list_next(l1);
            }
        }
        fclose(fp);
        list_free_with_free(old_dirlist);
    }
    list_free_with_free(dirlist);
}

static void fork_exec_gui(const char *problem_id)
{
    fflush(NULL); /* paranoia */
    pid_t pid = fork();
    if (pid < 0)
    {
        perror_msg("fork");
        goto record_dirs;
    }

    if (pid == 0)
    {
        /* child */
        /* double fork to avoid GUI zombies */
        pid_t grand_child = fork();
        if (grand_child != 0)
        {
            /* child */
            if (grand_child < 0)
                perror_msg("fork");
            _exit(0);
        }

        // pass s_[] as DIR param(s) to 'gui executable'
        char *gui_args[4];
        char **pp = gui_args;
        *pp++ = (char *)GUI_EXECUTABLE;
        if (problem_id != NULL)
        {
            *pp++ = (char *)"-p";
            *pp++ = (char *)problem_id;
        }
        *pp = NULL;

        /* grandchild */
        execv(BIN_DIR"/"GUI_EXECUTABLE, gui_args);
        /* Did not find 'gui executable' in installation directory. Oh well */
        /* Trying to find it in PATH */
        execvp(GUI_EXECUTABLE, gui_args);
        perror_msg_and_die(_("Can't execute '%s'"), GUI_EXECUTABLE);
    }

    /* parent */
    safe_waitpid(pid, /* status */ NULL, /* options */ 0);

 record_dirs:
    /* Scan dirs and save new $XDG_CACHE_HOME/abrt/applet_dirlist.
     * (Oterwise, after a crash, next time applet is started,
     * it will show alert icon even if we did click on it
     * "in previous life"). We ignore function return value.
     */
    new_dir_exists(/* new dirs list */ NULL);
}

static pid_t spawn_event_handler_child(const char *dump_dir_name, const char *event_name, int *fdp)
{
    char *args[7];
    args[0] = (char *) LIBEXEC_DIR"/abrt-handle-event";
    args[1] = (char *) "-i"; /* Interactive? - Sure, applet is like a user */
    args[2] = (char *) "-e";
    args[3] = (char *) event_name;
    args[4] = (char *) "--";
    args[5] = (char *) dump_dir_name;
    args[6] = NULL;

    int pipeout[2];
    int flags = EXECFLG_INPUT_NUL | EXECFLG_OUTPUT | EXECFLG_QUIET | EXECFLG_ERR2OUT;
    VERB1 flags &= ~EXECFLG_QUIET;

    char *env_vec[2];

    /* WTF? We use 'abrt-handle-event -i' but here we export REPORT_CLIENT_NONINTERACTIVE */
    /* - Exactly, REPORT_CLIENT_NONINTERACTIVE causes that abrt-handle-event in */
    /* interactive mode replies with empty responses to all event's questions. */
    env_vec[0] = xstrdup("REPORT_CLIENT_NONINTERACTIVE=1");
    env_vec[1] = NULL;

    pid_t child = fork_execv_on_steroids(flags, args, fdp ? pipeout : NULL,
            env_vec, /*dir:*/ NULL, /*uid(unused):*/ 0);

    if (fdp)
        *fdp = pipeout[0];

    free(env_vec[0]);

    return child;
}

static void run_report_from_applet(problem_info_t *pi)
{
    if (!problem_info_ensure_writable(pi))
        return;

    const char *dirname = problem_info_get_dir(pi);

    fflush(NULL); /* paranoia */
    pid_t pid = fork();
    if (pid < 0)
    {
        perror_msg("fork");
        return;
    }
    if (pid == 0)
    {
        /* child */
        /* prevent zombies - another fork inside: */
        spawn_event_handler_child(dirname, "report-gui", NULL);
        _exit(0);
    }
    safe_waitpid(pid, /* status */ NULL, /* options */ 0);
}

//this action should open the reporter dialog directly, without showing the main window
static void action_full_report(GSimpleAction *action, GVariant *param, gpointer user_data)
{
    log_debug("Reporting a problem!");

    problem_info_t *pi = (problem_info_t *)user_data;
    if (problem_info_get_dir(pi))
        run_report_from_applet(pi);

    problem_info_free(pi);
}

//this action should open the reporter dialog directly, without showing the main window
static void action_micro_report(GSimpleAction *action, GVariant *param, gpointer user_data)
{
    log_debug("Micro-Reporting a problem!");

    const char *dir_name;
    g_variant_get(param, "&s", &dir_name);
    problem_info_t *pi = remove_from_notified_list(dir_name);

    if (problem_info_get_dir(pi))
    {
        if (pi->foreign == false)
            ask_start_autoreporting();

        /* if shortened reporting is configured don't start reporting process
         * when problem is unknown (just show notification) */
        run_event_async(g_application, pi, get_autoreport_event_name(),
            is_shortened_reporting_enabled() ? 0 : REPORT_UNKNOWN_PROBLEM_IMMEDIATELY);
    }
    else
        problem_info_free(pi);
}

static void action_ignore(GSimpleAction *action, GVariant *param, gpointer user_data)
{
    const char *dir_name;
    g_variant_get(param, "&s", &dir_name);
    problem_info_t *pi = remove_from_notified_list(dir_name);

    const char *const message = _(
            "You are going to mute notifications of a particular problem. " \
            "You will never see a notification bubble for this problem again, " \
            "however, ABRT will be detecting it and you will be able " \
            "to report it from ABRT GUI." \
            "\n\n" \
            "Do you want to continue?");

    if (run_ask_yes_no_yesforever_dialog("AskIgnoreForever", message, NULL))
    {
        log_debug("Ignoring problem '%s'", problem_info_get_dir(pi));
        ignored_problems_add_problem_data(g_ignore_set, pi->problem_data);
    }

    problem_info_free(pi);
}

static void action_open_problem(GSimpleAction *action, GVariant *param, gpointer user_data)
{
    const char *dir_name;
    g_variant_get(param, "&s", &dir_name);
    problem_info_t *pi = remove_from_notified_list(dir_name);

    fork_exec_gui(problem_info_get_dir(pi));

    problem_info_free(pi);
}

static void action_close(GSimpleAction *action, GVariant *param, gpointer user_data)
{
    log_debug("Notify closed!");

    const char *dir_name;
    g_variant_get(param, "&s", &dir_name);
    problem_info_t *pi = remove_from_notified_list(dir_name);
    problem_info_free(pi);

    /* Scan dirs and save new $XDG_CACHE_HOME/abrt/applet_dirlist.
     * (Oterwise, after a crash, next time applet is started,
     * it will show alert icon even if we did click on it
     * "in previous life"). We ignore finction return value.
     */
    new_dir_exists(/* new dirs list */ NULL);
}

static GNotification *new_warn_notification(problem_info_t *pi)
{
    GNotification *notification;
    GIcon *icon;

    notification = g_notification_new(_("Warning"));
    icon = g_themed_icon_new_with_default_fallbacks("abrt");
    g_notification_set_icon(notification, icon);
    g_object_unref(icon);

    g_notification_set_default_action_and_target(notification, "app.close-notification",
                                                 "s", problem_info_get_dir(pi));

    // As of now, all notifications are persisntent
    //notify_notification_set_timeout(notification, persistence ? NOTIFY_EXPIRES_NEVER
    //                                                          : NOTIFY_EXPIRES_DEFAULT);
    //
    // TODO: This should handle GtkApplication ??
    //notify_notification_set_hint(notification, "desktop-entry", g_variant_new_string("abrt-applet"));

    return notification;
}

#if 0
static void on_about_cb(GtkMenuItem *menuitem, gpointer dialog)
{
    if (dialog)
    {
        gtk_dialog_run(GTK_DIALOG(dialog));
        gtk_widget_hide(GTK_WIDGET(dialog));
    }
}

static GtkWidget *create_about_dialog(void)
{
    const char *copyright_str = "Copyright © 2009 Red Hat, Inc\nCopyright © 2010 Red Hat, Inc";
    const char *license_str = "This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version."
                         "\n\nThis program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details."
                         "\n\nYou should have received a copy of the GNU General Public License along with this program.  If not, see <http://www.gnu.org/licenses/>.";

    const char *website_url = "https://fedorahosted.org/abrt/";
    const char *authors[] = {"Anton Arapov <aarapov@redhat.com>",
                     "Karel Klic <kklic@redhat.com>",
                     "Jiri Moskovcak <jmoskovc@redhat.com>",
                     "Nikola Pajkovsky <npajkovs@redhat.com>",
                     "Zdenek Prikryl <zprikryl@redhat.com>",
                     "Denys Vlasenko <dvlasenk@redhat.com>",
                     NULL};

    const char *artists[] = {"Patrick Connelly <pcon@fedoraproject.org>",
                             "Lapo Calamandrei",
                             "Jakub Steinar <jsteiner@redhat.com>",
                                NULL};

    const char *comments = _("Notification area applet that notifies users about "
                               "issues detected by ABRT");
    GtkWidget *about_d = gtk_about_dialog_new();
    if (about_d)
    {
        gtk_window_set_default_icon_name("abrt");
        gtk_about_dialog_set_version(GTK_ABOUT_DIALOG(about_d), VERSION);
        gtk_about_dialog_set_logo_icon_name(GTK_ABOUT_DIALOG(about_d), "abrt");
        gtk_about_dialog_set_comments(GTK_ABOUT_DIALOG(about_d), comments);
        gtk_about_dialog_set_program_name(GTK_ABOUT_DIALOG(about_d), "ABRT");
        gtk_about_dialog_set_copyright(GTK_ABOUT_DIALOG(about_d), copyright_str);
        gtk_about_dialog_set_license(GTK_ABOUT_DIALOG(about_d), license_str);
        gtk_about_dialog_set_wrap_license(GTK_ABOUT_DIALOG(about_d),true);
        gtk_about_dialog_set_website(GTK_ABOUT_DIALOG(about_d), website_url);
        gtk_about_dialog_set_authors(GTK_ABOUT_DIALOG(about_d), authors);
        gtk_about_dialog_set_artists(GTK_ABOUT_DIALOG(about_d), artists);
        gtk_about_dialog_set_translator_credits(GTK_ABOUT_DIALOG(about_d), _("translator-credits"));
    }
    return about_d;
}
#endif

static void notify_problem_list(GtkApplication *application, GList *problems, int flags)
{
    GList *last_item = g_list_last(problems);
    if (last_item == NULL)
    {
        log_debug("Not showing any notification bubble because the list of problems is empty.");
        return;
    }

    problem_info_t *last_problem = (problem_info_t *)last_item->data;
    free(g_last_notified_problem_id);
    g_last_notified_problem_id = xstrdup(problem_info_get_dir(last_problem));

    char *notify_body = NULL;
    for (GList *iter = problems; iter; iter = g_list_next(iter))
    {
        problem_info_t *pi = iter->data;
        if (ignored_problems_contains_problem_data(g_ignore_set, pi->problem_data))
        {   /* In case of shortened reporting, show the problem notification only once. */
            problem_info_free(pi);
            continue;
        }

        GNotification *notification = new_warn_notification(pi);
        g_notification_add_button_with_target(notification,
                _("Ignore forever"), "app.ignore-problem-forever", "s", problem_info_get_dir(pi));

        notify_body = build_message(pi);
        g_notification_set_body(notification, notify_body);

        pi->was_announced = true;

        if (pi->known)
        {   /* Problem has been 'autoreported' and is considered as KNOWN
             */
            g_notification_add_button_with_target(notification,
                    _("Open"), "app.open-problem", "s", problem_info_get_dir(pi));

            if (pi->was_announced)
                g_notification_set_title(notification, _("The Problem has already been Reported"));
            else
                g_notification_set_title(notification, _("A Known Problem has Occurred"));
        }
        else
        {
            if (flags & JUST_DETECTED_PROBLEM)
            {   /* Problem cannot be 'autoreported' because its data are incomplete
                 */
                if (pi->incomplete)
                {
                    g_notification_add_button_with_target(notification,
                            _("Open"), "app.open-problem", "s", problem_info_get_dir(pi));
                }
                else
                {
                   /* Problem has not yet been 'autoreported' and can be
                    * 'autoreported' on user request.
                    */
                    g_notification_add_button_with_target(notification,
                            _("Report"), "app.send-micro-report", "s", problem_info_get_dir(pi));
                }

                g_notification_set_title(notification, _("A Problem has Occurred"));
            }
            else
            {   /* Problem has been 'autoreported' and is considered as UNKNOWN
                 *
                 * In case of shortened reporting don't scare (confuse, bother)
                 * user with the 'Report' button and simply announce that some
                 * problem has been reported.
                 *
                 * Otherwise let user decide if he wants to start the standard
                 * reporting process of a new problem by clicking on the
                 * 'Report' button.
                 */
                if (is_shortened_reporting_enabled())
                {
                    /* Users dislike "useless" notification of reported
                     * problems allowing only to disable future notifications
                     * of the same problem.
                     */
                    if (is_silent_shortened_reporting_enabled())
                    {
                        problem_info_free(pi);
                        g_object_unref(notification);
                        goto next_problem_to_notify;
                    }

                    g_notification_set_title(notification, _("A Problem has been Reported"));
                }
                else
                {
                    g_notification_add_button_with_target(notification,
                            _("Report"), "app.send-full-report", "s", problem_info_get_dir(pi));

                    g_notification_set_title(notification, _("A New Problem has Occurred"));
                }
            }
        }

        log_debug("Showing a notification");

        add_to_notified_list(pi);
        g_application_send_notification(G_APPLICATION(application),
                                        problem_info_get_dir(pi), notification);

next_problem_to_notify:
        free(notify_body);
        notify_body = NULL;
    }

    g_list_free(problems);
}

static void notify_problem(GtkApplication *application, problem_info_t *pi)
{
    GList *problems = g_list_append(NULL, pi);
    notify_problem_list(application, problems, /* show icon and notify, don't show autoreport and don't use anon report*/ 0);
}

/* Event-processing child output handler */
static gboolean handle_event_output_cb(GIOChannel *gio, GIOCondition condition, gpointer ptr)
{
    struct event_processing_state *state = ptr;
    problem_info_t *pi = state->pi;

    /* Read streamed data and split lines */
    for (;;)
    {
        char buf[250]; /* usually we get one line, no need to have big buf */
        errno = 0;
        gsize r = 0;
        GError *error = NULL;
        GIOStatus stat = g_io_channel_read_chars(gio, buf, sizeof(buf) - 1, &r, &error);
        if (stat == G_IO_STATUS_ERROR)
        {   /* TODO: Terminate child's process? */
            error_msg(_("Can't read from gio channel: '%s'"), error ? error->message : "");
            g_error_free(error);
            break;
        }
        if (stat == G_IO_STATUS_AGAIN)
        {   /* We got all buffered data, but fd is still open. Done for now */
            return TRUE; /* "glib, please don't remove this event (yet)" */
        }
        if (stat == G_IO_STATUS_EOF)
            break;

        buf[r] = '\0';

        /* split lines in the current buffer */
        char *raw = buf;
        char *newline;
        while ((newline = strchr(raw, '\n')) != NULL)
        {
            *newline = '\0';
            strbuf_append_str(state->cmd_output, raw);
            char *msg = state->cmd_output->buf;

            log_debug("%s", msg);

            strbuf_clear(state->cmd_output);
            /* jump to next line */
            raw = newline + 1;
        }

        /* beginning of next line. the line continues by next read */
        strbuf_append_str(state->cmd_output, raw);
    }

    /* EOF/error */

    /* Wait for child to actually exit, collect status */
    int status = 1;
    if (safe_waitpid(state->child_pid, &status, 0) <= 0)
        perror_msg("waitpid(%d)", (int)state->child_pid);

    if (WIFEXITED(status) && WEXITSTATUS(status) == EXIT_STOP_EVENT_RUN)
    {
        pi->known = 1;
        status = 0;
    }

    if (status == 0)
    {
        pi->reported = 1;

        log_debug("fast report finished successfully");
        if (pi->known || !(state->flags & REPORT_UNKNOWN_PROBLEM_IMMEDIATELY))
            notify_problem(state->app, pi);
        else
            run_report_from_applet(pi);
    }
    else
    {
        log_debug("fast report failed");
        if (is_networking_enabled())
            notify_problem(state->app, pi);
        else
            push_to_deferred_queue(pi);
    }

    free_event_processing_state(state);

    /* We stop using this channel */
    g_io_channel_unref(gio);

    return FALSE;
}

static GIOChannel *my_io_channel_unix_new(int fd)
{
    GIOChannel *ch = g_io_channel_unix_new(fd);

    /* Need to set the encoding otherwise we get:
     * "Invalid byte sequence in conversion input".
     * According to manual "NULL" is safe for binary data.
     */
    GError *error = NULL;
    g_io_channel_set_encoding(ch, NULL, &error);
    if (error)
        perror_msg_and_die(_("Can't set encoding on gio channel: %s"), error->message);

    g_io_channel_set_flags(ch, G_IO_FLAG_NONBLOCK, &error);
    if (error)
        perror_msg_and_die(_("Can't turn on nonblocking mode for gio channel: %s"), error->message);

    g_io_channel_set_close_on_unref(ch, TRUE);

    return ch;
}

static void export_event_configuration(const char *event_name)
{
    static bool exported = false;
    if (exported)
        return;

    exported = true;

    event_config_t *event_config = get_event_config(event_name);

    /* load event config data only for the event */
    if (event_config != NULL)
        load_single_event_config_data_from_user_storage(event_config);

    GList *ex_env = export_event_config(event_name);
    g_list_free(ex_env);
}

static void run_event_async(GtkApplication *application, problem_info_t *pi, const char *event_name, int flags)
{
    if (!problem_info_ensure_writable(pi))
    {
        problem_info_free(pi);
        return;
    }

    export_event_configuration(event_name);

    struct event_processing_state *state = new_event_processing_state();
    state->pi = pi;
    state->app = application;
    state->flags = flags;

    state->child_pid = spawn_event_handler_child(problem_info_get_dir(state->pi), event_name, &state->child_stdout_fd);

    GIOChannel *channel_event_output = my_io_channel_unix_new(state->child_stdout_fd);
    g_io_add_watch(channel_event_output, G_IO_IN | G_IO_PRI | G_IO_HUP,
                   handle_event_output_cb, state);
}

static void show_problem_list_notification(GtkApplication *application, GList *problems, int flags)
{
    if (is_autoreporting_enabled())
    {
        /* Automatically report only own problems */
        /* and skip foreign problems */
        for (GList *iter = problems; iter;)
        {
            problem_info_t *data = (problem_info_t *)iter->data;
            GList *next = g_list_next(iter);

            if (!data->foreign && !data->incomplete)
            {
                run_event_async(application, (problem_info_t *)iter->data, get_autoreport_event_name(), /* don't automatically report */ 0);
                problems = g_list_delete_link(problems, iter);
            }

            iter = next;
        }

    }

    /* report the rest:
     *  - only foreign if autoreporting is enabled
     *  - the whole list otherwise
     */
    if (problems)
        notify_problem_list(application, problems, flags | JUST_DETECTED_PROBLEM);
}

static void show_problem_notification(GtkApplication *application, problem_info_t *pi, int flags)
{
    GList *problems = g_list_append(NULL, pi);
    show_problem_list_notification(application, problems, flags);
}

static void Crash(GDBusConnection *connection, const gchar *sender_name,
                    const gchar *object_path, const gchar *interface_name,
                    const gchar *signal_name, GVariant *parameters,
                    gpointer user_data)
{
    log_debug("Crash recorded");

    if (g_variant_check_format_string(parameters, "(&s&s&s&s&s)", FALSE) == FALSE)
    {
        error_msg("dbus signal Crash: parameter type is invalid: %s",
                    g_variant_get_type_string(parameters));
        return;
    }

    const char *package_name;
    const char *dir;
    const char *uid_str;
    const char *uuid;
    const char *duphash;

    g_variant_get(parameters, "(&s&s&s&s&s)",
            &package_name, &dir, &uid_str, &uuid, &duphash);

    bool foreign_problem = false;
    if (uid_str[0] != '\0')
    {
        char *end;
        errno = 0;
        unsigned long uid_num = strtoul(uid_str, &end, 10);
        if (errno || *end != '\0' || uid_num != getuid())
        {
            foreign_problem = true;
            log_notice("foreign problem %i", foreign_problem);
        }
    }

    /*
     * Can't append dir to the seen list because of directory stealing
     *
     * append_dirlist(dir);
     *
     */

    /* If this problem seems to be repeating, do not annoy user with popup dialog.
     * (The icon in the tray is not suppressed)
     */
    static time_t last_time = 0;
    static char* last_package_name = NULL;
    static char *last_problem_dir = NULL;
    time_t cur_time = time(NULL);
    int flags = 0;
    if (last_package_name && strcmp(last_package_name, package_name) == 0
     && last_problem_dir && strcmp(last_problem_dir, dir) == 0
     && (unsigned)(cur_time - last_time) < 2 * 60 * 60
    ) {
        /* log_msg doesn't show in .xsession_errors */
        error_msg("repeated problem in %s, not showing the notification", package_name);
        flags |= SHOW_ICON_ONLY;
    }
    else
    {
        last_time = cur_time;
        free(last_package_name);
        last_package_name = xstrdup(package_name);
        free(last_problem_dir);
        last_problem_dir = xstrdup(dir);
    }

    problem_info_t *pi = problem_info_new(dir);
    if (uuid != NULL && uuid[0] != '\0')
        problem_data_add_text_noteditable(pi->problem_data, FILENAME_UUID, uuid);
    if (duphash != NULL && duphash[0] != '\0')
        problem_data_add_text_noteditable(pi->problem_data, FILENAME_DUPHASH, duphash);
    if (package_name != NULL && package_name[0] != '\0')
        problem_data_add_text_noteditable(pi->problem_data, FILENAME_COMPONENT, package_name);

    pi->foreign = foreign_problem;

    show_problem_notification(GTK_APPLICATION(user_data), pi, flags);
}

static void handle_signal(int signo)
{
    int save_errno = errno;

    // Enable for debugging only, malloc/printf are unsafe in signal handlers
    //log_debug("Got signal %d", signo);

    uint8_t sig_caught = signo;
    if (write(g_signal_pipe[1], &sig_caught, 1))
        /* we ignore result, if () shuts up stupid compiler */;

    errno = save_errno;
}

static gboolean handle_sigterm_pipe(GIOChannel *gio, GIOCondition condition, gpointer ptr_unused)
{
    /* It can be only SIGTERM.
     * We are going to quit.
     * Therefore No read from the channel is necessary.
     */

    /* Next received SIGTERM will kill the applet. */
    signal(SIGTERM, SIG_DFL);

    gtk_main_quit();

    return FALSE; /* Pointless (loop is done and signal handler was reset); "please remove this event" */
}

/*
 * XSMP client
 */
static void
cb_smc_save_yourself(SmcConn smc_conn, SmPointer client_data, gint save_type,
                          gboolean shutdown, gint interact_style, gboolean fast)
{
    /* http://lesstif.sourceforge.net/doc/super-ux/g1ae04e/chap12.html#12.4.1.1 */
    /* Since we do not save any state, we can declare that we succeeded (True) */
    SmcSaveYourselfDone(smc_conn, True);
}

static void
cb_smc_die(SmcConn smc_conn, SmPointer client_data)
{
    /* The session manager sends a Die message to a client when it wants it to
     * die. The client should respond by calling SmcCloseConnection.
     *
     * http://lesstif.sourceforge.net/doc/super-ux/g1ae04e/chap12.html#12.4.1.2
     *
     * The reasons will most likely be NULL if resignation is expected by the
     * client.
     *
     * http://lesstif.sourceforge.net/doc/super-ux/g1ae04e/chap12.html#12.4.2
     */
    SmcCloseConnection(smc_conn, 0 /* The number of reason messages */,
                       NULL /* The reasons for closing the connection */);

    gtk_main_quit();
}

static void
cb_smc_save_complete(SmcConn smc_conn, SmPointer client_data)
{
    /* No action needed */
}

static void
cb_smc_shutdown_cancelled(SmcConn smc_conn, SmPointer client_data)
{
    /* Since we do not save any state, we can declare that we succeeded (True) */
    SmcSaveYourselfDone(smc_conn, True);
}

static gboolean
cb_ice_process_messages(GIOChannel *gio, GIOCondition condition, gpointer user_data)
{
    /* May return an error but we don't care, it isn't our problem */
    IceConn ice_conn = (IceConn)user_data;
    IceProcessMessages(ice_conn, NULL /* Indicates if a reply is being waited for */,
                       NULL /* If set to True on return, a reply is ready */);

    return TRUE; /* do not remove this source */
}

/*
 * We do not need to save any special state, we just want to be notified about
 * session death.
 */
static void
xsmp_client_connect(void)
{
    SmcCallbacks callbacks;
    memset(&callbacks, 0, sizeof(callbacks));
    callbacks.die.callback = cb_smc_die;
    callbacks.save_yourself.callback = cb_smc_save_yourself;
    callbacks.save_complete.callback = cb_smc_save_complete;
    callbacks.shutdown_cancelled.callback = cb_smc_shutdown_cancelled;
    char error_buf[256];
    char *client_id;

    SmcConn conn = SmcOpenConnection(NULL /* SESSION_MANAGER env variable */,
            NULL /* share ICE connection */, SmProtoMajor, SmProtoMinor,
            SmcSaveYourselfProcMask | SmcDieProcMask |
            SmcSaveCompleteProcMask | SmcShutdownCancelledProcMask,
            &callbacks, NULL /* previous client id */,
            &client_id, sizeof(error_buf), error_buf);

    if (!conn)
    {
        log(_("Failed to open connection to session manager: '%s', "
              "notification may reappear on the next login"), error_buf);
        return;
    }

    free(client_id);

    /* These 4 properties are required, however we do not need a special
     * handling neither for restart nor for clone, because we just need to
     * update seen problems list at exit.
     *
     * http://www.x.org/releases/X11R7.7/doc/libSM/xsmp.html#Predefined_Properties
     */
    SmProp prop_program, prop_user, prop_restart_cmd, prop_clone_cmd;
    SmProp *prop_list[4];
    SmPropValue val_program, val_user;
    prop_program.name = (char *)SmProgram;
    prop_program.type = (char *)SmARRAY8;
    val_program.value = (char *)"abrt-applet";
    val_program.length = (int)strlen(val_program.value);
    prop_program.num_vals = 1;
    prop_program.vals = &val_program;
    prop_list[0] = &prop_program;

    prop_user.name = (char *)SmUserID;
    prop_user.type = (char *)SmARRAY8;

    char userid_string[256];
    uid_t uid = getuid();
    struct passwd * pwd;
    if ((pwd = getpwuid(uid)) != NULL)
        snprintf(userid_string, sizeof(userid_string), "%s", pwd->pw_name);
    else
        snprintf(userid_string, sizeof(userid_string), "%d", uid);

    val_user.value = (char *)userid_string;
    val_user.length = (int) strlen(val_user.value);
    prop_user.num_vals = 1;
    prop_user.vals = &val_user;
    prop_list[1] = &prop_user;

    prop_restart_cmd.name = (char *)SmRestartCommand;
    prop_restart_cmd.type = (char *)SmARRAY8;
    prop_restart_cmd.num_vals = 1;
    /* Use Program property */
    prop_restart_cmd.vals = &val_program;
    prop_list[2] = &prop_restart_cmd;

    prop_clone_cmd.name = (char *)SmCloneCommand;
    prop_clone_cmd.type = (char *)SmARRAY8;
    prop_clone_cmd.num_vals = 1;
    /* Use Program property */
    prop_clone_cmd.vals = &val_program;
    prop_list[3] = &prop_clone_cmd;

    SmcSetProperties(conn, 4 /* number of properties */, prop_list);

    /* The X Session Management Protocol is layered on top of the Inter-Client
     * Exchange (ICE) Protocol.
     *
     * http://lesstif.sourceforge.net/doc/super-ux/g1ae04e/chap12.html#12.2
     */
    IceConn ice_conn = SmcGetIceConnection(conn);
    gint fd = IceConnectionNumber(ice_conn);

    /* Make sure we don't pass on these file descriptors to an
     * exec'd child process.
     */
    const int fd_flags = fcntl(fd, F_GETFD, 0);
    if (fd_flags < 0)
        perror_msg_and_die("fcntl(IceConnectionNumber, F_GETFD, 0)");
    else if (fcntl(fd, F_SETFD, fd_flags | FD_CLOEXEC) < 0)
        perror_msg_and_die("fcntl(IceConnectionNumber, + FD_CLOEXEC, 0)");

    /* When a client detects that there is data to read on an ICE connection,
     * it should call the IceProcessMessages function.
     *
     * http://lesstif.sourceforge.net/doc/super-ux/g1ae04e/chap12.html#12.2
     */
    GIOChannel *channel = g_io_channel_unix_new(fd);
    g_io_add_watch(channel, G_IO_ERR | G_IO_HUP | G_IO_IN,
                   cb_ice_process_messages, (gpointer)ice_conn);
    g_io_channel_unref(channel);
}
/*
 * XSMP client finito
 */

static void startup(GApplication *application, gpointer user_data)
{
    /* Initialize our (dbus_abrt) machinery: hook _system_ dbus to glib main loop.
     * (session bus is left to be handled by libnotify, see below) */
    g_crash_signal_ret = g_dbus_connection_signal_subscribe(g_system_bus,
                                                        NULL, //"org.freedesktop.problems",
                                                        NULL, //"org.freedesktop.problems",
                                                        "Crash",
                                                        "/org/freedesktop/problems",
                                                        /* arg0 */ NULL,
                                                        G_DBUS_SIGNAL_FLAGS_NONE,
                                                        Crash,
                                                        /* user_data */ application,
                                                        /* user_dta_free_func */ NULL);

    g_nm_signal_ret = g_dbus_connection_signal_subscribe(g_system_bus,
                                                        NM_DBUS_SERVICE,
                                                        NM_DBUS_INTERFACE,
                                                        "StateChanged",
                                                        NM_DBUS_PATH,
                                                        /* arg0 */ NULL,
                                                        G_DBUS_SIGNAL_FLAGS_NONE,
                                                        on_nm_state_changed,
                                                        /* user_data */ NULL,
                                                        /* user_data_free_func */ NULL);

        /* If some new dirs appeared since our last run, let user know it */
    GList *new_dirs = NULL;
    GList *notify_list = NULL;
    new_dir_exists(&new_dirs);

#define time_before_ndays(n) (time(NULL) - (n)*24*60*60)

    /* Age limit = now - 3 days */
    const unsigned long min_born_time = (unsigned long)(time_before_ndays(3));

    const bool notify_incomplete = is_notification_of_incomplete_problems_enabled();

    while (new_dirs)
    {
        struct dump_dir *dd = dd_opendir((char *)new_dirs->data, DD_OPEN_READONLY);
        if (dd == NULL)
        {
            log_notice("'%s' is not a dump dir - ignoring\n", (char *)new_dirs->data);
            new_dirs = g_list_next(new_dirs);
            continue;
        }

        if (dd->dd_time < min_born_time)
        {
            log_notice("Ignoring outdated problem '%s'", (char *)new_dirs->data);
            goto next;
        }

        const bool incomplete = !problem_dump_dir_is_complete(dd);
        if (!notify_incomplete && incomplete)
        {
            log_notice("Ignoring incomplete problem '%s'", (char *)new_dirs->data);
            goto next;
        }

        if (!dd_exist(dd, FILENAME_REPORTED_TO))
        {
            problem_info_t *pi = problem_info_new(new_dirs->data);
            const char *elements[] = {FILENAME_UUID, FILENAME_DUPHASH, FILENAME_COMPONENT, FILENAME_NOT_REPORTABLE};

            for (size_t i = 0; i < sizeof(elements)/sizeof(*elements); ++i)
            {
                char * const value = dd_load_text_ext(dd, elements[i],
                        DD_FAIL_QUIETLY_ENOENT | DD_LOAD_TEXT_RETURN_NULL_ON_FAILURE);
                if (value)
                    problem_data_add_text_noteditable(pi->problem_data, elements[i], value);
                free(value);
            }

            pi->incomplete = incomplete;

            /* Can't be foreign because if the problem is foreign then the
             * dd_opendir() call failed few lines above and the problem is ignored.
             * */
            pi->foreign = false;

            notify_list = g_list_prepend(notify_list, pi);
        }
        else
        {
            log_notice("Ignoring already reported problem '%s'", (char *)new_dirs->data);
        }

next:
        dd_close(dd);

        new_dirs = g_list_next(new_dirs);
    }

    g_ignore_set = ignored_problems_new(concat_path_file(g_get_user_cache_dir(), "abrt/ignored_problems"));

    if (notify_list)
        show_problem_list_notification(GTK_APPLICATION(application), notify_list, /* show icon and notify */ 0);

    list_free_with_free(new_dirs);

    /*
     * We want to update "seen directories" list on SIGTERM.
     * Updating it after each notification doesn't account for stealing directories:
     * if directory is stolen after seen list is updated,
     * on next startup applet will notify user about stolen directory. WRONG.
     *
     * SIGTERM handler simply stops GTK main loop and the applet saves user
     * settings, releases notify resources, releases dbus resources and updates
     * the seen list.
     */

    /* Set up signal pipe */
    xpipe(g_signal_pipe);
    close_on_exec_on(g_signal_pipe[0]);
    close_on_exec_on(g_signal_pipe[1]);
    ndelay_on(g_signal_pipe[0]);
    ndelay_on(g_signal_pipe[1]);
    signal(SIGTERM, handle_signal);
    g_channel_id_signal = my_io_channel_unix_new(g_signal_pipe[0]);
    g_io_add_watch(g_channel_id_signal,
                G_IO_IN | G_IO_PRI | G_IO_ERR | G_IO_HUP | G_IO_NVAL,
                handle_sigterm_pipe,
                NULL);

    /* Register a handler quiting from gtk main loop on X Session death.
     */
    xsmp_client_connect();
}

static void activate(GApplication *application, gpointer user_data)
{
    g_application_hold(application);
}

static GActionEntry actions[] = {
    { "close-notification",     action_close,        "t", NULL, NULL },
    { "send-full-report",       action_full_report,  "t", NULL, NULL },
    { "send-micro-report",      action_micro_report, "t", NULL, NULL },
    { "open-problem",           action_open_problem, "t", NULL, NULL },
    { "ignore-problem-forever", action_ignore,       "t", NULL, NULL },
};

int main(int argc, char** argv)
{
    /* I18n */
    setlocale(LC_ALL, "");
#if ENABLE_NLS
    bindtextdomain(PACKAGE, LOCALEDIR);
    textdomain(PACKAGE);
#endif

    abrt_init(argv);
    /* Glib 2.31:
     * Major changes to threading and synchronisation
     * - threading is now always enabled in GLib
     * - support for custom thread implementations (including our own internal
     * - support for errorcheck mutexes) has been removed
     */
#if (GLIB_MAJOR_VERSION == 2 && GLIB_MINOR_VERSION < 31)
    //can't use log(), because g_verbose is not set yet
    /* Need to be thread safe */
    g_thread_init(NULL);
    gdk_threads_init();
    gdk_threads_enter();
#endif

    glib_init();

    /* Monitor 'StateChanged' signal on 'org.freedesktop.NetworkManager' interface */
    GError *error = NULL;
    g_system_bus = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &error);

    if (g_system_bus == NULL)
    {
        error_msg("Error creating D-Bus proxy: %s\n", error->message);
        g_error_free(error);
        return -1;
    }

    g_set_prgname("abrt");

    /* Can't keep these strings/structs static: _() doesn't support that */
    const char *program_usage_string = _(
        "& [-v] [DIR]...\n"
        "\n"
        "Applet which notifies user when new problems are detected by ABRT\n"
    );
    enum {
        OPT_v = 1 << 0,
    };
    /* Keep enum above and order of options below in sync! */
    struct options program_options[] = {
        OPT__VERBOSE(&g_verbose),
        OPT_END()
    };
    /*unsigned opts =*/ parse_opts(argc, argv, program_options, program_usage_string);

    migrate_to_xdg_dirs();

    export_abrt_envvars(0);
    msg_prefix = g_progname;

    load_abrt_conf();
    load_event_config_data();
    load_user_settings("abrt-applet");

    const char *default_dirs[] = {
        g_settings_dump_location,
        NULL,
        NULL,
    };
    argv += optind;
    if (!argv[0])
    {
        default_dirs[1] = concat_path_file(g_get_user_cache_dir(), "abrt/spool");
        argv = (char**)default_dirs;
    }
    s_dirs = argv;

    GtkApplication *application = gtk_application_new("org.freedesktop.abrt.applet",
                                                      G_APPLICATION_FLAGS_NONE);

    g_signal_connect(application, "startup", G_CALLBACK(startup), NULL);
    g_signal_connect(application, "activate", G_CALLBACK(activate), NULL);

    g_action_map_add_action_entries(G_ACTION_MAP(application),
                                    actions, G_N_ELEMENTS(actions),
                                    application);

    /* Enter main loop
     *
     * Returns on SIGTERM signal, on menu button Quit click or on X Session
     * death.
     */
    g_application_run(G_APPLICATION(application), 1, argv);

    g_io_channel_unref(g_channel_id_signal);

    g_object_unref(application);

    ignored_problems_free(g_ignore_set);

#if (GLIB_MAJOR_VERSION == 2 && GLIB_MINOR_VERSION < 31)
    gdk_threads_leave();
#endif

    /* new_dir_exists() is called for each notification and if user clicks on
     * the abrt icon. Those calls cover 99.97% of detected crashes
     *
     * The rest of detected crashes:
     *
     * 0.01%
     * applet doesn't append a repeated crash to the seen list if the crash was
     * the last caught crash before exit (notification is not shown in case of
     * repeated crash)
     *
     * 0.01%
     * applet doesn't append a stolen directory to the seen list if
     * notification was closed before the notified directory had been stolen
     *
     * 0.1%
     * crashes of abrt-applet
     */
    new_dir_exists(/* new dirs list */ NULL);

    /* It does not make much sense to save settings at exit and after
     * introduction of system-config-abrt it is wrong to do that. abrt-applet
     * is long-running application and user can modify the configuration files
     * while abrt-applet run. Thus, saving configuration at desktop session
     * exit would make someone's life really hard.
     *
     * abrt-applet saves configuration immediately after user input.
     *
     * save_user_settings();
     */

    g_dbus_connection_signal_unsubscribe(g_system_bus, g_crash_signal_ret);
    g_dbus_connection_signal_unsubscribe(g_system_bus, g_nm_signal_ret);
    g_object_unref(g_system_bus);

    free(g_last_notified_problem_id);

    return 0;
}
