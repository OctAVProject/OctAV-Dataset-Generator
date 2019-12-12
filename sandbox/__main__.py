# coding: utf-8

import sys
from argparse import ArgumentParser
from sandbox import lisa

if __name__ == "__main__":

    parser = ArgumentParser(prog="python -m sandbox", description='This is the sandbox manager.')
    parser.add_argument('--start', help='start LiSa docker containers', action='store_true')
    parser.add_argument('--submit', metavar="FILE", help='submit a file to the LiSa sandbox')

    args = parser.parse_args(None if sys.argv[1:] else ['--help'])

    if lisa.is_sandbox_ready():
        if args.start:
            print("You specified --start but the sandbox seems to be up already !")

    else:
        if args.submit:
            print("Sandbox is not ready !")

            if not args.start:
                exit(1)

        if args.start:
            lisa.start_sandbox()

    if args.submit:
        lisa.analyse(args.submit)
