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


def _exec_using_firejail(filename):
    process = subprocess.run(["firejail", "--noprofile", "strace", "-f", "-qq", "-s", "1000", filename], capture_output=True)
    return process.stderr.decode(), process.returncode  # strace prints syscalls on stderr


def _process_syscall_traces(traces):
    syscalls = []
    lines = traces.split("\n")

    for line in lines:
        end_syscall_name = line.find("(")

        if end_syscall_name == -1:  # Skip debug output lines
            continue

        begin_return_value = line.rfind("=")

        if begin_return_value == -1:
            raise Exception("return value of syscall not found")

        begin_return_value += 2
        end_return_value = line.find(" ", begin_return_value)

        begin_parameter = end_syscall_name + 1
        end_parameter = line.rfind(")", 0, begin_return_value)

        if end_parameter == -1:
            raise Exception("closing parenthesis of syscall not found")

        # TODO : get PID too
        name = line[:end_syscall_name]
        parameters = line[begin_parameter:end_parameter].split(", ")  # FIXME: will not work with a string containing ", "

        if end_return_value == -1:
            return_value = line[begin_return_value:]
        else:
            return_value = line[begin_return_value:end_return_value]

        syscalls.append({
            "name": name,
            "parameters": parameters,
            "return_value": return_value
        })

    return syscalls


def analyse_malware(filename):
    _send_file_to_lisa(filename)


def analyse_legit_binary(filename):
    strace_output, returncode = _exec_using_firejail(filename)

    if returncode == 0:
        syscalls = _process_syscall_traces(strace_output)
        print(filename, "produced", len(syscalls), "syscalls")
    else:
        print(f"{filename} didn't work as expected")

