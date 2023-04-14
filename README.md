# NessusNibbler

NessusNibbler is a Python script for extracting missing Windows patches, third-party software vulnerabilities, and associated targets from Nessus (.nessus) files. It supports output in both Word Document (docx) and plain text (txt) formats.

## Features

- Extract missing Windows patches, third-party software vulnerabilities, and associated targets from Nessus files
- Generate output in Word Document (docx) or plain text (txt) format
- Easy to use via command-line interface (CLI) or Docker
- Customize output file name and format

## Prerequisites

To use the NessusNibbler tool, you need Python 3.x and the following packages installed:

- `Flask`
- `python-docx`

You can install the required packages using pip:

```bash
pip install Flask python-docx 
```

## Usage

NessusNibbler can be used via the command-line interface (CLI) or Docker.

### Command Line Interface (CLI)
To use the NessusNibbler tool, navigate to the directory containing the app.py file and run the following command:
```bash 
python app.py
```
Then, open your web browser and visit `http://localhost:8000` to access the application.

### Docker
To use the NessusNibbler tool with Docker, first build the Docker image:

```bash
docker build -t nessus-nibbler .
```

Then, run the Docker container:

```bash 
docker run -d -p 8000:8000 nessus-nibbler
```
Open your web browser and visit `http://localhost:8000` to access the application.

## License
NessusNibbler is released under the MIT License.