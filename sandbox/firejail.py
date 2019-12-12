# coding: utf-8

import os
import signal
import subprocess
from tempfile import TemporaryDirectory
from threading import Thread
from typing import List, Set

from dataset.syscalls import Syscall, ExecutionFlow, SyscallParsingException


class ProgramCrashedException(Exception):
    pass


class HelpNotFoundException(Exception):
    pass


def _parse_strace_output(path):

    with open(path, "r") as file:
        syscalls = []  # type: List[Syscall]

        line_being_built = None

        for line in file.read().split("\n"):
            if line:
                if "(core dump)" in line:
                    raise ProgramCrashedException

                if line.startswith("---") or line.startswith("+++"):  # Skip non syscall lines
                    continue

                if line_being_built:
                    line = line_being_built + line
                    line_being_built = None

                try:
                    syscalls.append(Syscall(line))

                # For an unknown reason, strace sometimes writes syscalls on multiple lines
                except SyscallParsingException:
                    line_being_built = line

        return syscalls


def _exec_using_firejail(command_line):

    with TemporaryDirectory() as tmpdirname:
        output_filename = tmpdirname + "/trace"

        process = subprocess.Popen(["firejail", "--x11=xvfb", "--allow-debuggers", "--overlay-tmpfs",
                                    "strace", "-o", output_filename, "-ff", "-xx", "-qq", "-s", "1000"]
                                   + command_line, stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=os.setsid)

        try:
            out, errs = process.communicate(timeout=5, input=b"Y\nY\nY\nY\nY\nY\nY\nY\nY\nY\nY\nY\nY\nY\nY\nY\n")
            # print("stdout:", out)
            # print("stderr:", errs)

            if b"invalid" in errs and b"command line option" in errs:
                print(errs.decode()[:-1])
                print("Unsupported argument detected ! You're probably running an old version of firejail which "
                      "doesn't like a parameter.\nCompile it manually using the latest version to fix the issue.")
                exit(1)

        except subprocess.TimeoutExpired:
            print(command_line, "timed out")
            os.killpg(os.getpgid(process.pid), signal.SIGTERM)
            process.poll()
            out, errs = None, None

        traces_files = [f"{tmpdirname}/{file}" for file in os.listdir(tmpdirname)]

        flows = []  # type: List[ExecutionFlow]

        for file in traces_files:
            _, pid = file.split(".")

            try:
                flow = ExecutionFlow(" ".join(command_line), pid, _parse_strace_output(file))
                # print(command_line, f"(pid {flow.pid}) produced", len(flow), "syscalls")
                flows.append(flow)
            except ProgramCrashedException:
                print(command_line, "crashed")

        print(command_line, "produced a total of", sum(len(flow) for flow in flows), "syscalls")
        return flows, out, process.returncode


def generate_command_lines_from_binary(filename, help_output):
    command_lines = [[filename]]

    for line in help_output.split("\n"):
        lowered_line = line.lower()

        if "usage:" in lowered_line:
            if "file" in lowered_line:
                command_lines.append([filename, "/etc/passwd"])
            elif "path" in lowered_line or "dir" in lowered_line or "folder" in lowered_line:
                command_lines.append([filename, "/etc"])

        splitted_line = line.split()

        if splitted_line and splitted_line[0].startswith("-"):
            detected_parameter = splitted_line[0].replace(",", "")

            # We skip --param=values kinds, too hard to process
            if "=" in detected_parameter:
                continue

            # We skip non alpha parameters to reduce false positives
            if not detected_parameter.replace("-", "").isalnum():
                continue

            command_lines.append([filename, detected_parameter])

    return command_lines


def analyse(binary_path) -> Set[ExecutionFlow]:

    if not os.path.isfile(binary_path):
        raise Exception(f"{binary_path} does not exist")

    total_flows_count = 0
    unique_inlined_flows = set()  # type: Set[ExecutionFlow]
    execution_flows, help_output, returncode = _exec_using_firejail([binary_path, "--help"])

    if returncode != 0:
        execution_flows, help_output, returncode = _exec_using_firejail([binary_path, "-h"])

        if returncode != 0:
            print(f"{binary_path} --help does not seem to work")
            help_output = b""

    total_flows_count += len(execution_flows)
    unique_inlined_flows.update(execution_flows)
    potentially_working_command_lines = generate_command_lines_from_binary(binary_path, help_output.decode())

    threads = []
    threads_results = []

    def thread_wrapper(*args):
        threads_results.append(_exec_using_firejail(*args))

    for command_line in potentially_working_command_lines:
        thread = Thread(target=thread_wrapper, args=(command_line,))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    for execution_flows, program_output, returncode in threads_results:
        total_flows_count += len(execution_flows)
        unique_inlined_flows.update(execution_flows)
        # print(f"Total flows: {total_flows_count} -- Unique flows: {len(unique_inlined_flows)}")

    return unique_inlined_flows
