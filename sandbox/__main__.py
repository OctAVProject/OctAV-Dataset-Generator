# coding: utf-8

import os
import sys

from sandbox.manager import start
from sandbox.lisa import analyse as analyse_malware


if __name__ == "__main__":

    if len(sys.argv) < 2:
        print("Please specify 'start' or 'submit'")
        exit(1)

    if sys.argv[1] == "start":
        start()

    elif sys.argv[1] == "submit":

        if len(sys.argv) != 3:
            print(f"Usage: {sys.argv[0]} {sys.argv[1]} [FILEPATH]")
            exit(1)

        filepath = sys.argv[2]

        if os.path.isfile(filepath):
            analyse_malware(filepath)
        else:
            print(f"File '{filepath}' does not exist")
            exit(1)

    else:
        print(f"Unknown '{sys.argv[1]}' operation")
        exit(1)

