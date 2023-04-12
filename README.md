# Nessus Parser Tool

Nessus Parser is a Python script for extracting outdated software and associated targets from Nessus (.nessus) files. It supports output in both Word Document (docx) and Command Line Interface (CLI) formats.

## Features

- Extract outdated software and associated targets from Nessus files
- Filter extracted data based on Microsoft missing patches or third-party outdated software
- Generate output in Word Document (docx) or Command Line Interface (CLI) format
- Customize output file name and format

## Prerequisites

To use the Nessus Parser tool, you need Python 3.x and the following packages installed:

- `python-docx`

You can install the required package using pip:

```bash
pip install python-docx
```

## Usage
To use the Nessus Parser tool, navigate to the directory containing the `nessus-parser.py` file and run the following command:

```bash 
python nessus-parser.py -f <path_to_nessus_file> [options]
```

Options:

- `-f`, `--file` : (Required) Path to the Nessus (.nessus) file
- `-mp`, `--microsoft-patches` : (Optional) Only include findings related to Microsoft missing patches
- `-tp`, `--third-party` : (Optional) Only include findings related to third-party outdated software
- `-o`, `--output` : (Optional) Output file name (default: output.docx)
- `-fmt`, `--format` : (Optional) Output format: docx (Word document) or cli (command-line) (default: docx)

Example usage:
```bash 
python nessus-parser.py -f sample.nessus -mp -o sample_output.docx -fmt docx
```
This command will parse the `sample.nessus` file, filter findings related to Microsoft missing patches, and generate a Word document output with the file name `sample_output.docx`.


