To use the ausearch test suite run make. This will compile the
ausearch-test program. The next thing is you will want to have some
logs to test.

ausearch --start today --raw > test.log

The program will default to testing audit.log in the current directory.
But you can also pass it a log name to test:

./ausearch-test test.log

It should complete saying "no problems detected". If it does not, then
you have run across a problem. When the test fails, it will output two
pieces of information. The first is the ausearch command that was being
run. The second piece of information is the event record that is being
tested. If this is a well established event and you are using the system
provided ausearch utility, then you should coordinate your finding with
the linux-audit mail list.

If you are creating a new event and it fails, then this will tell you
that ausearch may need updating or that perhaps you have used a field
name that has special meaning to the search tools. Either way, you should
coordinate your finding on the linux-audit mail list.

The default behavior is for it to stop on the first failure. You may
also pass --continue as a command line option and it will examine all
events in the log.

The ausearch test suite also comes with a couple of scripts to help
curate a collection of events.

* gather-logs
This program will try to gather one event for each type of record that
ausearch supports from the system audit logs. By default it places the
events in audit.log in the current directory.

* aucoverage LOG | --dump
This program will process the log file passed and enumerate the records
that are known to ausearch but are missing in the log file. You can also
pass the --dump option which will cause ausearch to output the record types
that it knows about.

* aumerge LOG1 LOG2
This program will extract events from LOG1 that are missing in LOG2 and
write them to LOG2. This allows you to build up a collection of events
in one file from several.

Report any problems to: linux-audit@redhat.com

