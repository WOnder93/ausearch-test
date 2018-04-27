/*
 * ausearch-test.c - ausearch testing utility
 * version: 0.5
 * Copyright 2014 Red Hat Inc., Durham, North Carolina.
 * All Rights Reserved.
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
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Authors:
 *     Steve Grubb <sgrubb@redhat.com>
 */

#include <stdio.h>
#include <locale.h>
#include <libaudit.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <auparse.h>

static char *AUSEARCH = NULL;
static char *LOG = NULL;
static int continue_on_error = 0;

struct nv_pair {
	const char *field;
	const char *option;
};

static struct nv_pair options[] =
{
 {"comm", "-c" },
 {"exit", "-e" },
 {"name", "-f" },
 {"cwd", "-f" }, // INFO: old ausearch will fail this, comment out accordingly
 {"path", "-f" },
 {"saddr", "-f" },  // if unix socket
 {"gid", "--gid" },
 {"egid", "-ge" },
 {"hostname", "-hn" },
 {"addr", "-hn" },
 {"saddr", "-hn" },
 {"key", "-k" },
 {"type", "-m" },
 {"node", "-n" },
 {"pid", "-p" },
 {"ppid", "-pp" },
 {"obj", "-o" },
 {"syscall", "-sc" },
 {"tcontext", "-se" },
 {"scontext", "-se" },
 {"subj", "-su" },
 {"ses", "--session" },
 {"subj", "--subject" },
 {"scontext", "--subject" },
 {"res", "--success" },
 {"result", "--success" },
 {"success", "--success" },
 {"tty", "-tm" },
 {"terminal", "-tm" },
 {"uid", "-ui" },
 {"euid", "-ue" },
 {"auid", "-ul" },
 {"loginuid", "-ul" },
 {"uuid", "--uuid" },
 {"vm", "--vm-name" },
 {"exe", "-x" },
 { NULL, NULL}
};

const char *opt_lookup(const char *f)
{
	unsigned int i = 0;
	while (options[i].field != NULL) {
		if (strcasecmp(f, options[i].field) == 0)
			break;
		i++;
	}
	return options[i].option;
}

int run_ausearch(auparse_state_t *au, char *line, const char *opt, 
		const char *val, const char *cmd)
{
	int rc = system(line);
	if (rc) {
		printf("\n");
		printf("Failed to locate a record\n");
		printf("Current test option: %s %s\n",
				opt, val);
		printf("Command used: %s\n", cmd);
		printf("Full record being tested: %s\n",
			auparse_get_record_text(au));
		if (!continue_on_error) {
			free(line);
			exit(1);
		} else
			return 1;
	}
	return 0;
}

/*
 * This tests one complete record
 */
int do_record_test(auparse_state_t *au)
{
	char cmd[8192], *ptr;
	int hn = 0, li = 0, ses = 0, first = 0;
	auparse_first_field(au);
	ptr = cmd;
	ptr = stpcpy(ptr, AUSEARCH);
	ptr = stpcpy(ptr, " -if ");
	ptr = stpcpy(ptr, LOG);

	do {
		char *line;
		if (first == 0) {
			char buf[64];
			unsigned long serial = auparse_get_serial(au);

			snprintf(buf, sizeof(buf), "%lu", serial);
			ptr = stpcpy(ptr, " -a ");
			ptr = stpcpy(ptr, buf);
			asprintf(&line, "%s  >/dev/null 2>&1", cmd);
			if (run_ausearch(au, line, "-a", buf, cmd)) {
				free(line);
				return 1;
			}
			free(line);
			first = 1;
		}
		const char *field = auparse_get_field_name(au);
		if (field) {
			const char *opt = opt_lookup(field);
			if (opt) {
				char buf[4096];
				int type = auparse_get_type(au);
				const char *val = auparse_get_field_str(au);
				if (val == NULL) {
					printf("can't get value for %s in %s\n",
						field,
						auparse_get_record_text(au));
					exit(1);
				}
				if (strcmp(val, "?") == 0)
					// skip the unknowns
					continue;
				if (strcmp(opt, "--success") == 0) {
					// Correct the value
					if (val[0] == 's')
						val = "yes";
					else if (val[0] == 'y')
						val = "yes";
					else if (val[0] == '1')
						val = "yes";
					else
						val = "no";
				}
				if (strcmp(field, "key") == 0) {
					// skip (none)
					if (val[0] == '(')
						continue;
				}
				if (strcmp(opt, "-tm") == 0) {
					// Skip (null)
					if (val[0] == '(')
						continue;
				}
				if (strcmp(opt, "-hn") == 0) {
					// some records have both addr and 
					// hostname filled in - only use the
					// first one
					if (hn) continue;
					hn = 1;
				}
				if (strcmp(field, "saddr") == 0) {
					if (type == AUDIT_SOCKADDR) {
						// If unix socket skip the
						// the identifier for its type
						val = auparse_interpret_field(au);
						if (strncmp(val, "local",
								5) == 0)
							val += 6;
						else if (strncmp(val, "netlink",
							7) == 0)
						// skip netlink - not a real
						// address
							continue;
					}
				}
				if (strcmp(field, "name") == 0) {
					if (strcmp(val, "(null)") == 0)
					// Some files temporarily have
					// no name - skip them
						continue;
				}
				if (type == AUDIT_USER_AVC)
					// USER AVCs are a mess - skip
					continue;
				if (type == AUDIT_LOGIN) {
					// On login records, only second auid
					// is searchable
					if (strcmp(field, "auid") == 0 &&
						li == 0) {
						li = 1;
						continue;
					}
					// On login records, only second ses
					// is searchable
					if (strcmp(field, "ses") == 0 &&
						ses == 0) {
						ses = 1;
						continue;
					}
				}
				if (type == AUDIT_USER_LOGIN) {
					// On user login records, only second
					// uid is searchable
					if (strcmp(field, "uid") == 0 &&
						li == 0) {
						li = 1;
						continue;
					}
				}
				if (type == AUDIT_USER_LOGOUT) {
					// On user login records, only second
					// uid is searchable
					if (strcmp(field, "uid") == 0 &&
						li == 0) {
						li = 1;
						continue;
					}
				}

				if (auparse_get_field_type(au) ==
						AUPARSE_TYPE_ESCAPED &&
						val[0] != '"') {
					snprintf(buf, sizeof(buf), "\'%s\'",
					auparse_interpret_field(au));
					val = buf;
				}

				ptr = stpcpy(ptr, " ");
				ptr = stpcpy(ptr, opt);
				ptr = stpcpy(ptr, " ");
				ptr = stpcpy(ptr, val);
				asprintf(&line, "%s  >/dev/null 2>&1", cmd);
				if (run_ausearch(au, line, opt, val, cmd)) {
					free(line);
					return 1;
				}
				free(line);
			}
		}
	} while (auparse_next_field(au));
	return 0;
}

int main(int argc, char *argv[])
{
	auparse_state_t *au;
	int opt = 1, problems = 0;

	setlocale (LC_ALL, "");
	while (argc > opt) {
		if (strcmp(argv[opt], "--help") == 0) {
			printf("ausearch-test [path to different ausearch|log] [--continue]\n");
			return 0;
		}
//printf("opt=%d, argv[opt]=%s\n", opt, argv[opt]);
		if (strcmp(argv[opt], "--continue") == 0)
			continue_on_error = 1;
		else if (access(argv[opt], X_OK) == 0)
			AUSEARCH = strdup(argv[opt]);
		else if (access(argv[opt], R_OK) == 0) {
			LOG = strdup(argv[opt]);
		} else {
			printf("Can't find replacement for ausearch: %s\n", argv[opt]);
			return 1;
		}
		opt++;
	}
	if (AUSEARCH == NULL)
		AUSEARCH = strdup("ausearch");
	if (LOG == NULL)
		LOG = strdup("./audit.log");

	au = auparse_init(AUSOURCE_FILE, LOG);
	if (au == NULL) {
		printf("Error initializing\n");
		return 1;
	}

	printf("Starting the test\n");
	do {
		auparse_first_record(au);
		do {	// Do the test on the record
			if (do_record_test(au)) {
				problems++;
				break; // --continue given, do next event
			}
		} while (auparse_next_record(au) > 0);
	} while (auparse_next_event(au) > 0);

	auparse_destroy(au);
	if (problems)
		printf("Done - %d problems detected\n", problems);
	else
		printf("Done - no problems detected\n");

	return 0;
}

