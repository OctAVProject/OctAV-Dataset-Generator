# coding: utf-8
import signal
import subprocess
from subprocess import PIPE
import requests
import os
import time
from tempfile import TemporaryDirectory

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


def _get_file_lines(path):
    with open(path, "r") as file:
        return file.read().split("\n")


def _exec_using_firejail(command_line):

    with TemporaryDirectory() as tmpdirname:
        output_filename = tmpdirname + "/trace"

        process = subprocess.Popen(["firejail", "--x11=xvfb", "--allow-debuggers", "--private",
                                    "strace", "-o", output_filename, "-ff", "-xx", "-s",
                                    "1000"] + command_line, stdout=PIPE, stderr=PIPE, preexec_fn=os.setsid)

        try:
            out, errs = process.communicate(timeout=5, input=b"Y\nY\nY\nY\nY\nY\nY\nY\nY\nY\nY\nY\nY\nY\nY\nY\n")
            # print("stdout:", out)
            # print("stderr:", errs)
        except subprocess.TimeoutExpired:
            print(command_line, "timed out")
            os.killpg(os.getpgid(process.pid), signal.SIGTERM)
            process.poll()
            out, errs = None, None

        traces_files = [f"{tmpdirname}/{file}" for file in os.listdir(tmpdirname)]

        processes = []

        for file in traces_files:
            _, pid = file.split(".")
            processes.append({
                "pid": pid,
                "syscalls": _get_file_lines(file)
            })

        return processes, out, process.returncode


def _parse_strace_output(processes):
    syscalls_per_pid = {}

    for process in processes:
        for syscall_line in process["syscalls"]:

            # It could either mean the program is waiting for some stdin input or its running too fast for strace
            if "<unfinished ...>" in syscall_line:
                continue

            # Program crashed
            if "(core dumped)" in syscall_line:
                break

            end_syscall_name = syscall_line.find("(")

            if end_syscall_name == -1:  # Skip debug output lines
                continue

            begin_return_value = syscall_line.rfind("=")

            # return value of syscall not found
            if begin_return_value == -1:
                continue

            begin_return_value += 2
            end_return_value = syscall_line.find(" ", begin_return_value)

            begin_parameter = end_syscall_name + 1
            end_parameter = syscall_line.rfind(")", 0, begin_return_value)

            if end_parameter == -1:
                continue

            name = syscall_line[:end_syscall_name]

            # FIXME: will not work with a string containing ", "
            parameters = syscall_line[begin_parameter:end_parameter].split(", ")

            if end_return_value == -1:
                return_value = syscall_line[begin_return_value:]
            else:
                return_value = syscall_line[begin_return_value:end_return_value]

            if process["pid"] not in syscalls_per_pid:
                syscalls_per_pid[process["pid"]] = []

            syscalls_per_pid[process["pid"]].append({
                "name": name,
                "parameters": parameters,
                "return_value": return_value
            })

    return syscalls_per_pid


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

            if "=" in detected_parameter:  # We skip --param=values kinds, too hard to process
                continue

            command_lines.append([filename, detected_parameter])

    return command_lines


def _does_syscall_sequence_already_exist(existing_syscalls_per_pid, syscalls):

    for sequence in existing_syscalls_per_pid:

        if len(sequence) != len(syscalls):
            continue

        for i in range(len(sequence)):
            if sequence[i]["name"] != syscalls[i]["name"]:
                continue

        return True

    return False


def analyse_malware(binary_path):

    if not os.path.isfile(binary_path):
        raise Exception(f"{binary_path} does not exist")

    _send_file_to_lisa(binary_path)


def analyse_legit_binary(binary_path):

    if not os.path.isfile(binary_path):
        raise Exception(f"{binary_path} does not exist")

    processes, help_output, returncode = _exec_using_firejail([binary_path, "--help"])

    if returncode != 0:
        processes, help_output, returncode = _exec_using_firejail([binary_path, "-h"])

        if returncode != 0:
            print(f"Help of {binary_path} not found\n")
            return

    help_syscalls = _parse_strace_output(processes)
    syscalls_sequences = list(help_syscalls.values())

    potentially_working_command_lines = generate_command_lines_from_binary(binary_path, help_output.decode())
    print("Potentially working command lines:", potentially_working_command_lines)

    for command_line in potentially_working_command_lines:

        processes, program_output, returncode = _exec_using_firejail(command_line)

        for pid, syscalls_sequence in _parse_strace_output(processes).items():
            # Make sur we don't have this sequence already
            if not _does_syscall_sequence_already_exist(syscalls_sequences, syscalls_sequence):
                print(command_line, f"(pid {pid}) produced", len(syscalls_sequence), "syscalls")
                syscalls_sequences.append(syscalls_sequence)

            else:
                print(command_line, "syscalls sequence already exists")
