import select
import re
from collections import defaultdict
import os
from termcolor import colored, cprint
import datetime
import sys

print "Welcome to Plumber, a grep friendly execve/fork monitor for Linux!"
print "Written by Amit Serper, Cybereason | Contact: @0xAmit"
#     Copyright (C) 2017, Cybereason
#
#     This program is free software: you can redistribute it and/or modify
#     it under the terms of the GNU Affero General Public License as
#     published by the Free Software Foundation, either version 3 of the
#     License, or (at your option) any later version.
#
#     This program is distributed in the hope that it will be useful,
#     but WITHOUT ANY WARRANTY; without even the implied warranty of
#     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#     GNU Affero General Public License for more details.
#
#     You should have received a copy of the GNU Affero General Public License
#     along with this program.  If not, see <http://www.gnu.org/licenses/>.


#TODO: divide this into different classes and tidy up the code



# Bail if not root/sudo
if not os.geteuid() == 0:
    sys.exit("Error: You need to be root to run this")

# Change dir to the tracer directory
os.chdir("/sys/kernel/debug/tracing/")

#We're creating a custom krpboe and calling  it "plumber_sys_execve"
CR_EXECVE = "plumber_sys_execve"

#This function removes the tracer (DOH!) It's called on exit for cleanliness
def disableTrace():
    open("events/sched/sched_process_fork/enable", 'w').write("0")
    open("events/sched/sched_process_exec/enable", 'w').write("0")
    open("events/sched/sched_process_exit/enable", 'w').write("0")
    open("events/kprobes/%s/enable" % CR_EXECVE, 'w').write('0')
    open("kprobe_events", 'a+').write("-:"+CR_EXECVE)
    open("trace", 'w').write('')

# Disabling trace in case we didn't exit cleanly the last time
try:
    disableTrace()
except IOError:
    pass

# Enable all tracers
def enableTrace():
    open("events/sched/sched_process_fork/enable", 'w').write("1")
    open("events/sched/sched_process_exec/enable", 'w').write("1")
    open("events/sched/sched_process_exit/enable", 'w').write("1")


    # Create the custom execve kprobe consumer
    with open("kprobe_events", "w") as f:
        f.write("p:kprobes/%s sys_execve" % CR_EXECVE)

        #Command line args will be in %si, we're asking ftrace to give them to us
        for i in range(1, 16):
            f.write(" arg%d=+0(+%d(%%si)):string" % (i, i*8))

    open("events/kprobes/%s/enable" % CR_EXECVE, 'w').write('1')

# Disable all tracers
def disableTrace():
    open("events/sched/sched_process_fork/enable", 'w').write("0")
    open("events/sched/sched_process_exec/enable", 'w').write("0")
    open("events/sched/sched_process_exit/enable", 'w').write("0")
    open("events/kprobes/%s/enable" % CR_EXECVE, 'w').write('0')
    open("kprobe_events", 'a+').write("-:"+CR_EXECVE)
    open("trace", 'w').write('')

#This prints in green
def print_green(txt):
    cprint(txt, 'green')

#This prints in red
def print_red(txt):
     cprint(txt, 'red')

#Let's go!
def trace():
    # Open the trace pipe
    f = open("/sys/kernel/debug/tracing/trace_pipe")

    piddict = defaultdict(dict)

    try:
        while True:
            r, w, e = select.select([f], [], [], 0)
            if f not in r:
                continue
            line = f.readline()

            m = re.search(r'sched_process_(.*?):', line)
            # Parsing output from the trace pipe
            if m is not None:
                if m.group(1) == 'fork':
                    mm = re.search(r'\scomm=(.+?)\s+pid=(\d+)\s+child_comm=(.+?)\s+child_pid=(\d+)', line)

                    command, pid, child_command, child_pid = mm.groups()
                    pid = int(pid)
                    child_pid = int(child_pid)

                    piddict[pid]['command'] = command

                    piddict[child_pid] = {'parent': pid,
                                          'command': child_command}

                    print_green("%s: Process %s (pid=%d) forked from parent %s (pid=%d)" % \
                          (datetime.datetime.now().time(), child_command, child_pid, command, pid))

                elif m.group(1) == 'exec':
                    filename = re.search(r'filename=(.*?)\s+pid=', line).group(1)
                    pid = int(re.search(r'\spid=(\d+)', line).group(1))

                    piddict[pid]['fname'] = filename

                    outstr = "New process (pid=%d): %s" % (pid, piddict[pid]['fname'])

                    if 'args' in piddict[pid]:
                        outstr += ' ' + piddict[pid]['args']

                    if 'parent' in piddict[pid]:
                        parent_pid = piddict[pid]['parent']
                        outstr += "; parent is %s (pid=%d)" % (piddict[parent_pid].get('command', '<empty>'), parent_pid)

                    print_green(str(datetime.datetime.now().time()) + ": "+outstr)


                elif m.group(1) == 'exit':
                    mm = re.search(r'\scomm=(.*?)\s+pid=(\d+)', line)

                    command = mm.group(1)
                    pid = int(mm.group(2))

                    #Print time from using datetime.
                    #TODO: Get time from frtrace (laziness prevails)
                    print_red("%s: Process %s (pid=%d) ended." % (datetime.datetime.now().time(), command, pid))

                    if pid in piddict:
                        del piddict[pid]

            # Find message from our probe and parse it
            if CR_EXECVE in line:
                m = re.search(r'^.*?\-(\d+)\s*\[', line)

                if m is None:
                    print "ERROR: unknown format: ", line

                pid = int(m.group(1))
                #"walk" over every argument field, 'fault' is our terminator. If we see it it means that there are
                # more cmdline args.
                if '(fault)' in line:
                    line = line[:line.find('(fault)')]

                args = ' '.join(re.findall(r'arg\d+="(.*?)"', line))

                piddict[pid]['args'] = args


    # When CTRL-C is hit we don't want to leave tracers open
    except KeyboardInterrupt:
        print_green("Quitting gracefully")
        disableTrace()


if __name__ == "__main__":
    enableTrace()
    trace()
