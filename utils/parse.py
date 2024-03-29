import re
import xml.etree.ElementTree as ET
import re
from docx.shared import Cm
from docx.enum.style import WD_STYLE
from styles import create_styles
from utils.patterns import *
import html

def parse_installed_software(software_text):
    decoded_text = html.unescape(software_text)
    software_list = [match.group(1) for match in re.finditer(SOFTWARE_REGEX_PATTERN, decoded_text)]
    additional_software = [match.group(1) for match in re.finditer(SOFTWARE_REGEX_PATTERN2, decoded_text)]
    software_list.extend(additional_software)
    return software_list


def parse_linux_patches(linux_patches_text):
    matches = [match.group(1) for match in re.finditer(LINUX_PATCHES_REGEX_PATTERN, linux_patches_text)]
    return matches

def clean_description_text(description_text):
    cleaned_text = re.sub(DESCRIPTION_CLEANUP_REGEX_PATTERN1, '', description_text)
    cleaned_text = re.sub(DESCRIPTION_CLEANUP_REGEX_PATTERN2, ' ', cleaned_text)
    return cleaned_text
