# coding: utf-8
import os
import time
from multiprocessing import Pool
from typing import Set

from sandbox.firejail import analyse as analyse_legit_binary
from sandbox.lisa import analyse as analyse_malware
from sandbox.manager import is_sandbox_ready, start
from sandbox.syscalls import ExecutionFlow

LEGIT_BINARIES_LOCATIONS = [
    "/bin",
    "/sbin",
    "/usr/bin"
]


# TODO
def export_dataset(syscalls_sequences: Set[ExecutionFlow]):
    pass


def generate_legit_binaries_dataset():
    print("Generating legit binaries dataset...")

    begin_analysis = time.time()

    binaries = set()
    for bin_dir in LEGIT_BINARIES_LOCATIONS:
        for file in os.listdir(bin_dir):
            full_path = os.path.realpath(bin_dir + "/" + file)
            if os.path.isfile(full_path):
                binaries.add(full_path)

    unique_syscalls_sequences_of_all_binaries = set()  # type: Set[ExecutionFlow]

    with Pool() as pool:
        syscall_sequences = pool.map(analyse_legit_binary, binaries)

        for sequence in syscall_sequences:
            unique_syscalls_sequences_of_all_binaries.update(sequence)

    print()
    print("-" * 50)
    print("Job done in", int(time.time() - begin_analysis), "seconds")
    print("Executed binaries count:", len(binaries))
    print("Unique syscall sequences count:", len(unique_syscalls_sequences_of_all_binaries))

    export_dataset(unique_syscalls_sequences_of_all_binaries)


def generate_malwares_dataset():
    print("Generating malwares dataset...")

    # TODO : Iterate through the malwares to send to the sandbox
    # with multiprocessing.Pool(processes=4) as pool:  ??
    analyse_malware("/bin/ls")


if __name__ == "__main__":

    generate_legit_binaries_dataset()

    # if not is_sandbox_ready():
    #    start()

    # generate_malwares_dataset()
