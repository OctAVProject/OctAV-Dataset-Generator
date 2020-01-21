# coding: utf-8
import multiprocessing
import os
import sqlite3
import threading
import time

from multiprocessing.pool import ThreadPool
from typing import List

from dataset.core import Execution
from sandbox import legit, malware
from sandbox.legit import get_help_manual

SQLITE_SCHEME = """
                CREATE TABLE IF NOT EXISTS executions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    command_line TEXT NOT NULL UNIQUE, -- The same binary can appear multiple times with different parameters
                    is_malware BOOL NOT NULL
                );

                CREATE TABLE IF NOT EXISTS flows (
                    id integer PRIMARY KEY AUTOINCREMENT,
                    execution_id INTEGER,
                    FOREIGN KEY(execution_id) REFERENCES executions(id)
                    -- Maybe later we could add stuff like "opened_files"
                );

                CREATE TABLE IF NOT EXISTS syscalls (
                    id integer PRIMARY KEY AUTOINCREMENT,
                    flow_id INTEGER,
                    name TEXT NOT NULL,
                    parameters TEXT,
                    return_value TEXT,
                    -- exec_timestamp INTEGER,
                    FOREIGN KEY(flow_id) REFERENCES flows(id)
                );
                """

# We use a list to buffered executions for performance
buffered_executions = []  # type: List[Execution]

# The higher this value is, the heavier it will be on RAM usage. It will increase speed however
MAX_CACHED_EXECUTIONS = 100

cleaning_lock = threading.Lock()
needs_cleaning_cond = threading.Condition(lock=cleaning_lock)


# TODO : compare sqlite vs postgresql performance
def _export_buffered_binaries(db: sqlite3.Connection):

    to_remove_from_cache = []

    for execution in buffered_executions:

        try:
            cursor = db.execute("INSERT INTO executions VALUES(NULL, ?, ?);",
                                (execution.command_line, execution.is_malware))

            binary_id = cursor.lastrowid

            execution_sorted_by_pid = sorted(execution, key=lambda f: f.pid)

            # data inserted follows the spawned processes order (thanks to pid sorting)
            for flow in execution_sorted_by_pid:
                cursor = db.execute("INSERT INTO flows VALUES(NULL, ?);", (binary_id,))

                flow_id = cursor.lastrowid

                for syscall in flow:
                    db.execute(f"INSERT INTO syscalls VALUES(NULL, ?, ?, ?, ?);",
                               (flow_id, syscall.name, syscall.raw_parameters, syscall.return_value))

            db.commit()
        except sqlite3.IntegrityError:
            db.rollback()

        to_remove_from_cache.append(execution)

    for execution in to_remove_from_cache:
        buffered_executions.remove(execution)


# This callback is called in the context of the main process
def _binary_analysis_finished_callback(execution: Execution):

    print("command '{}' started {} process(es) for a total of {} syscalls".format(
        execution.command_line,
        len(execution),
        sum(len(flow) for flow in execution))
    )

    buffered_executions.append(execution)


def _generate_command_lines_from_binary(binary_path):

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


def generate_legit_binaries_dataset(legit_directories: List[str], db: sqlite3.Connection):

    if not legit.check_requirements():
        print("Cannot continue legit binaries analysis")
        exit(1)

    binaries = set()
    for bin_dir in legit_directories:
        for file in os.listdir(bin_dir):
            full_path = os.path.realpath(bin_dir + "/" + file)
            if os.path.isfile(full_path):
                binaries.add(full_path)

    binaries = sorted(list(binaries))  # Sort in order to see progress based on alphabetical names

    # We dont want command line duplicates in the dataset
    cursor = db.execute("SELECT command_line FROM executions;")
    commands_already_in_dataset = set(item[0] for item in cursor.fetchall())

    analysis_pool_results = []

    def cleaning_work():

        results_to_remove = []

        for r in analysis_pool_results:
            if r.ready():
                results_to_remove.append(r)

        for r in results_to_remove:
            analysis_pool_results.remove(r)

        if len(buffered_executions) > MAX_CACHED_EXECUTIONS:
            _export_buffered_binaries(db)

    def error_callback(exc):
        raise exc

    with ThreadPool(processes=os.cpu_count() * 2) as pool:

        for binary in binaries:

            # Skip binaries we already have
            if binary in commands_already_in_dataset:
                continue

            # TODO : generate command lines depending on cpu_count() (multithreaded?) to speed things up (to keep the workers busy)
            generated_commands = _generate_command_lines_from_binary(binary)

            for cmd in generated_commands:
                result = pool.apply_async(legit.analyse, args=(cmd,),
                                          callback=_binary_analysis_finished_callback,
                                          error_callback=error_callback)
                analysis_pool_results.append(result)

            cleaning_work()

        commands_already_in_dataset.clear()  # free some memory

        while analysis_pool_results:
            cleaning_work()

            if analysis_pool_results:
                time.sleep(3)

    _export_buffered_binaries(db)  # Export remaining buffered flows


def generate_malwares_dataset(malware_directories: List[str], db: sqlite3.Connection):
    print("Generating malwares dataset...")

    # TODO : Iterate through the malwares to send to the sandbox
    # with multiprocessing.Pool(processes=4) as pool:  ??
    malware.analyse("/bin/ls")
