# coding: utf-8

import multiprocessing
import os
import subprocess
import time
import requests

from sandbox.lisa import LISA_SANDBOX_URL

scripts_path = os.path.dirname(os.path.realpath(__file__))


class SandBoxException(Exception):
    pass


def is_sandbox_available():
    return os.path.isdir(scripts_path + "/LiSa")


def is_sandbox_ready():
    try:
        resp = requests.get(LISA_SANDBOX_URL)
    except:
        return False

    return resp.status_code == 200


def clone_sandbox():
    print("[o] Cloning the sandbox...")
    process = subprocess.run(["git", "-C", scripts_path, "clone", "https://github.com/danieluhricek/LiSa.git"], capture_output=True)

    if process.returncode != 0:
        print(process.stderr.decode())
        print("[-] Error encountered while trying to clone LiSa")
        exit(1)

    print("[+] LiSa cloned successfully !")


def docker_compose_build():
    print("[o] Building docker containers...")
    process = subprocess.run(["docker-compose", "-f", scripts_path + "/LiSa/docker-compose.yml", "build"],
                             capture_output=True)

    if process.returncode != 0:
        print(process.stderr.decode())
        print("[-] docker-compose build failed !")
        exit(1)

    print("[+] Docker containers were built successfully !")


def docker_compose_up():
    process = subprocess.run(["docker-compose", "-f", scripts_path + "/LiSa/docker-compose.yml", "up"], capture_output=True)

    if process.returncode != 0:
        print(process.stderr.decode())
        print("[-] docker-compose up failed !")
        exit(1)


def start():

    if not is_sandbox_available():
        clone_sandbox()
        docker_compose_build()

    print("[o] Starting the sandbox...")

    p = multiprocessing.Process(target=docker_compose_up)
    p.start()

    while not is_sandbox_ready() and p.is_alive():
        time.sleep(2)

    if p.is_alive():
        print("[+] The sandbox started successfully !")
