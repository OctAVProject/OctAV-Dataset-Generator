# coding: utf-8

import subprocess
import requests
import os
import time

LISA_SANDBOX_URL = "http://localhost:4242"


class SandBoxException(Exception):
    pass


def _send_file_to_lisa(filename):
    resp = requests.post(
        LISA_SANDBOX_URL + "/api/tasks/create/file",
        files={"file": (os.path.basename(filename), open(filename, "rb"))},
        data={"exec_time": "10"}
    )

    if resp.status_code != 200:
        raise SandBoxException("the sandbox returned HTTP code " + str(resp.status_code))

    task_id = resp.json()["task_id"]
    print("Task ID:", task_id)

    while True:

        resp = requests.get(LISA_SANDBOX_URL + "/api/report/" + task_id)

        if resp.status_code == 200:
            break

        if resp.status_code != 404:
            raise SandBoxException(f"the sandbox returned HTTP code {resp.status_code} during report waiting")

        print("Waiting for the report...")
        time.sleep(2)

    print(resp.json())
    print("\nGOT THE REPORT !!!")


def _exec_using_firejail(command_line):
    process = subprocess.run(["firejail", "--allow-debuggers", "--blacklist=/home",
                              "strace", "-f", "-qq", "-xx", "-s", "1000", "bash", "-c", " ".join(command_line) + " 2>&1"],
                             capture_output=True, timeout=10, input=b"Y\nY\nY\nY\nY\nY\nY\nY\nY\nY\nY\nY\nY\nY\nY\nY\n")

    return process.stdout, process.stderr.decode(), process.returncode  # strace prints syscalls on stderr


def _process_syscall_traces(traces):
    syscalls = []
    lines = traces.split("\n")

    for line in lines:

        # If the line doesn't start with that, it means those are bash syscalls (the parent)
        if not line.startswith("[pid"):
            continue

        # It could either mean the program is waiting for some stdin input or its running too fast for strace
        if "<unfinished ...>" in line:
            continue

        # Program crashed
        if "(core dumped)" in line:
            continue

        end_pid = line.find("]")
        pid = int(line[4:end_pid])

        begin_syscall_name = end_pid + 2
        end_syscall_name = line.find("(", end_pid)

        if end_syscall_name == -1:  # Skip debug output lines
            continue

        begin_return_value = line.rfind("=")

        if begin_return_value == -1:
            print(lines)
            print()
            print(line)
            raise Exception("return value of syscall not found")

        begin_return_value += 2
        end_return_value = line.find(" ", begin_return_value)

        begin_parameter = end_syscall_name + 1
        end_parameter = line.rfind(")", 0, begin_return_value)

        if end_parameter == -1:
            raise Exception("closing parenthesis of syscall not found")

        name = line[begin_syscall_name:end_syscall_name]
        parameters = line[begin_parameter:end_parameter].split(", ")  # FIXME: will not work with a string containing ", "

        if end_return_value == -1:
            return_value = line[begin_return_value:]
        else:
            return_value = line[begin_return_value:end_return_value]

        syscalls.append({
            "pid": pid,
            "name": name,
            "parameters": parameters,
            "return_value": return_value
        })

    return syscalls


def generate_command_lines_from_binary(filename, help_output):
    command_lines = [[filename]]

    for line in help_output.split("\n"):
        lowered_line = line.lower()

        if "usage:" in lowered_line:
            if "file" in lowered_line:
                command_lines   .append([filename, "/etc/passwd"])
            elif "path" in lowered_line or "dir" in lowered_line or "folder" in lowered_line:
                command_lines.append([filename, "/etc"])

        splitted_line = line.split()

        if splitted_line and splitted_line[0].startswith("-"):
            detected_parameter = splitted_line[0].replace(",", "")

            if "=" in detected_parameter:  # We skip --param=values kinds, too hard to process
                continue

            command_lines.append([filename, detected_parameter])

    return command_lines


def _does_syscall_sequence_already_exist(existing_syscalls_per_parameter, syscalls):

    for sequence in existing_syscalls_per_parameter:

        if len(sequence) != len(syscalls):
            continue

        for i in range(len(sequence)):
            if sequence[i]["name"] != syscalls[i]["name"]:
                continue

        return True

    return False


def analyse_malware(filename):

    if not os.path.isfile(filename):
        raise Exception(f"{filename} does not exist")

    _send_file_to_lisa(filename)


def analyse_legit_binary(filename):

    if not os.path.isfile(filename):
        raise Exception(f"{filename} does not exist")

    progam_output, strace_output, returncode = _exec_using_firejail([filename, "--help"])
    help_syscalls = _process_syscall_traces(strace_output)
    syscalls_per_parameter = [help_syscalls]

    if returncode != 0:
        print(f"'{filename} --help' does not seem to work")
        return

    potentially_working_command_lines = generate_command_lines_from_binary(filename, progam_output.decode())
    print(potentially_working_command_lines)

    timeouts_count = 0

    for command_line in potentially_working_command_lines:

        try:
            progam_output, strace_output, returncode = _exec_using_firejail(command_line)

            if returncode == 0:
                syscalls = _process_syscall_traces(strace_output)

                # Make sur we don't have this sequence already
                if not _does_syscall_sequence_already_exist(syscalls_per_parameter, syscalls):
                    print(command_line, "produced", len(syscalls), "syscalls")
                    syscalls_per_parameter.append(syscalls)

                # else:
                #     print(command_line, "syscalls sequence already exists")
            else:
                print(command_line, "didn't work as expected")

        except subprocess.TimeoutExpired:
            print(command_line, "timed out")
            timeouts_count += 1

            if timeouts_count > 3:
                print("This program times out too much, skipping...")
                break
