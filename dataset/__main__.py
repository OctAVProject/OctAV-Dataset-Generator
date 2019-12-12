# coding: utf-8

import sys
from argparse import ArgumentParser
from dataset.builder import generate_legit_binaries_dataset, generate_malwares_dataset

if __name__ == "__main__":
    parser = ArgumentParser(prog="python -m dataset", description='This is the dataset builder.')
    parser.add_argument('--malware-dirs', metavar="DIRECTORY", nargs='+',
                        help='directories of malwares to process')
    parser.add_argument('--legit-dirs', metavar="DIRECTORY", nargs='+',
                        help='directories of legit binaries to process')

    args = parser.parse_args(None if sys.argv[1:] else ['--help'])
    legits = args.legit_dirs
    malwares = args.malware_dirs

    if legits:
        generate_legit_binaries_dataset(legits)

    if malwares:
        generate_malwares_dataset(malwares)
