# Nessus Parser

This is a Nessus parser tool that can be used through a command line interface or a web application, that processes XML exports from the Nessus vulnerability scanner and generates an output in .docx or .txt format. The script filters Microsoft patches and third-party vulnerabilities, processes unquoted service path vulnerabilities, and explores Nessus files to collect relevant data.

## Features

 - Parses Microsoft patches and third-party vulnerabilities.
 - Processes unquoted service path vulnerabilities.
 - Outputs in .docx or .txt format.
 - Explores Nessus files to collect relevant data.

## Requirements
 - Python 3.x
 - python-docx library
 - Flask
 - An XML export file from Nessus

To install the python-docx library and Flask, run the following command:

```bash
pip install python-docx Flask
```

## Usage 
1. Clone the repository or download the `nessus_parser.py` script and the `styles.py` script.
2. Place the Nessus XML export file in the same directory as the scripts.
3. Run the script with the appropriate command line arguments.

```bash
python nessus_parser.py -f input.nessus -o output.docx
```

### Command Line Arguments

```bash 
-f, --file          The Nessus XML file to parse
-o, --output        The output file (either .docx or .txt)
-m, --microsoft     Include Microsoft patches in the output
-t, --third-party   Include third-party vulnerabilities in the output
-u, --unquoted      Include unquoted service path vulnerabilities in the output
```

## Web Application

The web application provides a user-friendly interface for parsing and analyzing `.nessus` files. It is built using Flask and can be run inside a Docker container. You can find the source code for the web application in `app.py`.

### Running the web application with Docker

To run the web application using Docker, follow these steps:

1. Install Docker on your system, if you haven't already.

2. Build the Docker image:

```bash
$ docker build -t nessus-parser .
```
3. Run the Docker container:
```bash 
$ docker run -d -p 8000:8000 --name nessus-parser-container nessus-parser
```

The web application will be accessible at `http://localhost:8000`.

### Web Application Features
The web application offers the following features:

 - Upload `.nessus` files.
 - View and manage uploaded files.
 - Parse and analyze `.nessus` files using various filters.
 - Export the results in different formats (e.g., CSV, JSON, etc.).
 - Explore and search `.nessus` files based on various criteria.
 
 Refer to the code in `app.py` for more details about the implementation of these features.

## Dockerfile
The `Dockerfile` is provided for building the Docker image of the web application. The Dockerfile sets up a Python 3.9 environment, installs the required packages from `requirements.txt`, copies the application files, and runs the application.