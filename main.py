import xml.etree.ElementTree as ET
import sys
import os
import re
import argparse
import docx
from docx.shared import Cm
from docx.enum.style import WD_STYLE
from styles import create_styles
from utils.print import *
from utils.extract import *

def parse_and_extract_data_from_nessus_file(file_name, microsoft_patches, third_party, linux_patches, unquoted_service_path):
    root = parse_nessus_file(file_name)
    vulnerabilities = extract_data_from_nessus_file(root, microsoft_patches, third_party, linux_patches, unquoted_service_path)
    return vulnerabilities


def explore_nessus_file(file_name):
    root = parse_nessus_file(file_name)
    findings = extract_findings_from_nessus_file(root)
    return findings

def main():
    parser = argparse.ArgumentParser(description="Nessus parser for extracting outdated software and associated targets")
    parser.add_argument("-f", "--file", dest="file_name", required=True, help="Path to the Nessus (.nessus) file")
    parser.add_argument("-mp", "--microsoft-patches", action="store_true", help="Only include findings related to Microsoft missing patches")
    parser.add_argument("-tp", "--third-party", action="store_true", help="Only include findings related to third-party outdated software")
    parser.add_argument("-lp", "--linux-patches", action="store_true", help="Only include findings related to Linux patches")
    parser.add_argument("-o", "--output", dest="output_file", default="output.docx", help="Output file name (default: output.docx)")
    parser.add_argument("-fmt", "--format", dest="output_format", choices=["docx", "txt"], default="docx", help="Output format: docx (Word document) or txt (text file) (default: docx)")
    parser.add_argument("-u", "--unquoted-service-path", action="store_true", help="Only include findings related to unquoted service path vulnerabilities")

    args = parser.parse_args()

    if args.explore:
        hosts, vulnerabilities = explore_nessus_file(args.file_name)
        print_output(vulnerabilities, output_format=args.output_format, output_file=args.output_file)
    else:
        vulnerabilities = parse_and_extract_data_from_nessus_file(args.file_name, args.microsoft_patches, args.third_party, args.linux_patches, args.unquoted_service_path)
        print_output(vulnerabilities, output_format=args.output_format, output_file=args.output_file)


if __name__ == "__main__":
    main()