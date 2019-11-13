# coding: utf-8

import os


class SandBoxException(Exception):
    pass


def start():
    print("Starting the sandbox...")

    if os.fork() == 0:
        pass
        #os.system("docker-compose up")  # TODO: improve that disgusting thing

