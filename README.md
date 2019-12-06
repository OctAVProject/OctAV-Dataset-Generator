# OctAV Dataset Generator

This repository's goal is to generate a dataset of binaries execution for machine learning purposes.

## Requirements

You need to have installed the following programs :

- git
- firejail
- docker-compose

## Installation

```
$ git clone https://github.com/OctAVProject/OctAV-Dataset-Generator.git
$ cd OctAV-Dataset-Generator/
$ python3 -m venv venv
$ . venv/bin/activate
$ pip install -r requirements.txt
```

## Usage

If you only want to start the LiSa sandbox, do :

```
$ python -m sandbox start
```

To submit a single file to the sandbox, do :

```
$ python -m sandbox submit [FILENAME]
```

To generate the dataset, do :

```
$ python dataset_generator.py
```