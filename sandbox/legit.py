# coding: utf-8

import os
import signal
import subprocess
import time
from tempfile import TemporaryDirectory
from threading import Thread
from typing import List

import psutil

from dataset.core import Syscall, Flow, SyscallParsingException, Execution


FIREJAIL_COMMAND = ["firejail", "--x11=xvfb", "--allow-debuggers", "--overlay-tmpfs",
                       "--nodbus", "--nosound", "--nodvd", "--nonewprivs"]


class ProgramCrashedException(Exception):
    pass


class HelpNotFoundException(Exception):
    pass


def check_requirements():
    try:
        out = subprocess.check_output(["strace", "--version"], stderr=subprocess.STDOUT)
        strace_version = out.split(b"\n")[0].split(b" ")[3].decode()
        print("Detected strace version :", strace_version)
    except FileNotFoundError:
        print("Missing requirement : please install strace")
        return False

    try:
        out = subprocess.check_output(["firejail", "--version"], stderr=subprocess.STDOUT)
        firejail_version = out.split(b"\n")[0].split(b" ")[2].decode()
        print("Detected firejail version :", firejail_version)
    except FileNotFoundError:
        print("Missing requirement : please install firejail")
        return False

    try:
        subprocess.check_output(FIREJAIL_COMMAND + ["test"], stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as cpe:

        if b"invalid" in cpe.stderr and b"command line option" in cpe.stderr \
                or b"Xvfb program was not found" in cpe.stderr:
            print(cpe.stderr.decode()[:-1])
            print("Unsupported argument detected ! You're probably running an old version of firejail which "
                  "doesn't like a parameter.\nCompile it manually using the latest version to fix the issue.")

        else:
            print(cpe.stderr.decode())
            print("Firejail error detected !")

        return False

    return True


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


def _kill_strace_debugee(ppid):
    try:
        p = psutil.Process(pid=ppid)
        children = p.children()

        if p.name() == "strace":
            for child in children:
                os.kill(child.pid, signal.SIGKILL)  # Kill strace's children

            for process in p.parent().children():
                if process.name() != "strace":
                    os.kill(process.pid, signal.SIGKILL)  # Kill processes at the same level than strace
        else:
            for child in children:
                _kill_strace_debugee(child.pid)

    except psutil.NoSuchProcess:
        pass

    except AttributeError:
        pass


def _exec_using_firejail(command_line, debug=False):

    """
    command_line: the command to run within firejail
    debug: whether to use strace or not
    """

    with TemporaryDirectory() as tmpdirname:
        output_filename = tmpdirname + "/trace"
        stdout = open(tmpdirname + "/stdout", "wb+")
        stderr = open(tmpdirname + "/stderr", "wb+")

        command = FIREJAIL_COMMAND.copy()

        if debug:
            command += ["strace", "-o", output_filename, "-ff", "-xx", "-qq", "-s", "1000"]

        command += command_line

        process = subprocess.Popen(command, stdout=stdout, stderr=stderr, start_new_session=True)

        try:

            if debug:
                # Sometimes there's a "bug" which causes the program not to output any syscall.
                # This is because the CPU is overloaded and doesn't exec anything withing the 5 seconds timeout
                # In order to solve that issue, this is a bit hack-ish but we wait for strace to create at least a file
                while not os.listdir(tmpdirname):
                    time.sleep(0.1)

            process.communicate(timeout=5, input=b"Y\nY\nY\nY\nY\nY\nY\nY\nY\nY\nY\nY\nY\nY\nY\nY\n")

        except subprocess.TimeoutExpired:

            # Kill all subprocesses, let firejail clean itself

            try:
                parent = psutil.Process(process.pid)

                for child in parent.children(recursive=True):
                    if child.name() != "firejail" and child.name() != "Xvfb":
                        child.send_signal(signal.SIGKILL)
            except psutil.NoSuchProcess:
                pass

            process.wait()

        stdout.seek(0)
        stderr.seek(0)
        out = stdout.read()
        errs = stderr.read()
        stdout.close()
        stderr.close()

        if debug:
            traces_files = [f"{tmpdirname}/{file}" for file in os.listdir(tmpdirname)
                            if file != "stdout" and file != "stderr"]

            flows = []  # type: List[Flow]

            for file in traces_files:
                _, pid = file.split(".")

                try:
                    flow = Flow(" ".join(command_line), int(pid), _parse_strace_output(file))
                    flows.append(flow)
                except ProgramCrashedException:
                    print(command_line, "crashed")
                except UnicodeDecodeError:
                    print("strace output of '", command_line, "' contains binary data, ignoring")

            return flows, out, errs, process.returncode

        else:
            return out, errs, process.returncode


def get_help_manual(binary_path):
    stdout, stderr, returncode = _exec_using_firejail([binary_path, "--help"])

    if returncode != 0:
        stdout, stderr, _ = _exec_using_firejail([binary_path, "-h"])

        if returncode != 0:
            return None

    try:
        help_output = stdout + stderr
        return help_output.decode()
    except UnicodeDecodeError:
        return None


def generate_command_lines_from_binary(binary_path) -> List[List[str]]:
    command_lines = set()
    command_lines.add((binary_path,))

    help_output = get_help_manual(binary_path)

    if not help_output:
        print(binary_path, "help not found")
        return [[binary_path]]

    for line in help_output.split("\n"):
        lowered_line = line.lower()

        if "usage:" in lowered_line:
            if "file" in lowered_line:
                command_lines.add((binary_path, "/etc/passwd",))
            elif "path" in lowered_line or "dir" in lowered_line or "folder" in lowered_line:
                command_lines.add((binary_path, "/etc",))

        splitted_line = line.split()

        if splitted_line and splitted_line[0].startswith("-"):
            detected_parameters = splitted_line[0].split(",")

            for param in detected_parameters:
                param = param.strip()

                # We skip --param=values kinds, too hard to process
                if "=" in param:
                    continue

                # We skip non alpha parameters to reduce false positives
                if not param.replace("-", "").isalnum():
                    continue

                command_lines.add((binary_path, param,))

    return [[*line] for line in command_lines]  # Convert tuples into lists


def analyse(command_line) -> Execution:
    flows, _, _, _ = _exec_using_firejail(command_line, debug=True)
    return Execution(command_line, flows, is_malware=False)
