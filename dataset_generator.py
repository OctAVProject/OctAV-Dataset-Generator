# coding: utf-8
import os
import subprocess

from sandbox.api import analyse_malware, analyse_legit_binary
from sandbox.manager import is_sandbox_ready, start

LEGIT_BINARIES_LOCATIONS = [
    "/bin",
    "/sbin",
    "/usr/bin"
]


def generate_legit_binaries_dataset():
    print("Generating legit binaries dataset...")

    # TODO with multiprocessing.Pool(processes=4) as pool:  ??

    # analyse_legit_binary("/bin/ls")
    # analyse_legit_binary("/bin/gzip")

    for bin_dir in LEGIT_BINARIES_LOCATIONS:
        files = os.listdir(bin_dir)

        for file in files:
            full_path = bin_dir + "/" + file
            if os.path.isfile(full_path):
                analyse_legit_binary(full_path)


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
