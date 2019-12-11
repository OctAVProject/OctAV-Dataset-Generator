# coding: utf-8

import os
import threading
import time
import sqlite3
from multiprocessing import Pool
from typing import Set, IO, List

from sandbox.firejail import analyse as analyse_legit_binary
from sandbox.lisa import analyse as analyse_malware
from sandbox.manager import is_sandbox_ready, start
from sandbox.syscalls import ExecutionFlow

LEGIT_BINARIES_LOCATIONS = [
    "/bin",
    "/sbin",
    "/usr/bin"
]

DB_FILE = "dataset.db"

SQLITE_SCHEME = """CREATE TABLE IF NOT EXISTS execution_flows (
                        id integer PRIMARY KEY AUTOINCREMENT,
                        command_line TEXT
                        -- Maybe later we could add stuff like "opened_files"
                    );

                    CREATE TABLE IF NOT EXISTS syscalls (
                        id integer PRIMARY KEY AUTOINCREMENT,
                        flow_id INTEGER,
                        name TEXT,
                        parameters TEXT,
                        return_value TEXT,
                        FOREIGN KEY(flow_id) REFERENCES execution_flow(id)
                    );"""

# The higher this value is, the heavier it will be on RAM usage. It will increase speed however
EXPORT_BUFFERED_SYSCALLS_COUNT = 100000

db = sqlite3.connect(DB_FILE)

# We store a hash of each execution flow to be sure we don't have it already (lowers RAM usage to use hashes)
hash_of_known_syscalls_sequences = set()  # type: Set[hash(ExecutionFlow)]

# We use a list to buffer execution flows for performance, we know they're unique already
buffered_flows = []  # type: List[ExecutionFlow]
buffered_syscalls_count = 0

cleaning_lock = threading.Lock()
needs_cleaning_cond = threading.Condition(lock=cleaning_lock)


# TODO : try using postgresql instead of sqlite ? (or support both ?)
#  execute() and commit() take 2/3 of the whole exec time...
def _export_flows():
    global buffered_syscalls_count

    for buffered_flow in buffered_flows:
        cursor = db.execute("INSERT INTO execution_flows VALUES(NULL, ?);", (buffered_flow.command_line,))

        for syscall in buffered_flow:
            db.execute(f"INSERT INTO syscalls VALUES(NULL, ?, ?, ?, ?);",
                       (cursor.lastrowid, syscall.name, syscall.raw_parameters, syscall.return_value))

        db.commit()

    with needs_cleaning_cond:
        buffered_syscalls_count = 0
        buffered_flows.clear()
        needs_cleaning_cond.notify_all()


# This callback is called in the context of the main process
def _process_finished_callback(execution_flows: Set[ExecutionFlow]):
    global buffered_syscalls_count

    for flow in execution_flows:
        flow_hash = hash(flow)
        if flow_hash not in hash_of_known_syscalls_sequences:
            hash_of_known_syscalls_sequences.add(flow_hash)

            with needs_cleaning_cond:
                buffered_syscalls_count += len(flow)
                buffered_flows.append(flow)

                if buffered_syscalls_count > EXPORT_BUFFERED_SYSCALLS_COUNT:
                    needs_cleaning_cond.wait()


def generate_legit_binaries_dataset():
    print("Generating legit binaries dataset...")

    # Build tables if not existing already
    db.executescript(SQLITE_SCHEME)
    db.commit()

    begin_analysis = time.time()

    binaries = set()
    for bin_dir in LEGIT_BINARIES_LOCATIONS:
        for file in os.listdir(bin_dir):
            full_path = os.path.realpath(bin_dir + "/" + file)
            if os.path.isfile(full_path):
                binaries.add(full_path)

    binaries = sorted(list(binaries))  # Sort in order to see progress based on alphabetical names

    def error_callback(exc):
        raise exc

    with Pool() as pool:

        results = []

        for binary in binaries:
            result = pool.apply_async(analyse_legit_binary, args=(binary,),
                                      callback=_process_finished_callback,
                                      error_callback=error_callback)
            results.append(result)

        while results:
            results_indexes_to_remove = []

            for i in range(len(results)):
                if results[i].ready():
                    results_indexes_to_remove.append(i)

            for i, index_to_remove in enumerate(results_indexes_to_remove):
                del results[index_to_remove - i]

            if buffered_syscalls_count > EXPORT_BUFFERED_SYSCALLS_COUNT:
                _export_flows()

    _export_flows()  # Export remaining buffered flows

    print()
    print("-" * 50)
    print("Job done in", int(time.time() - begin_analysis), "seconds")
    print("Executed binaries count:", len(binaries))
    print("Unique syscall sequences count:", len(hash_of_known_syscalls_sequences))

    db.close()


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
