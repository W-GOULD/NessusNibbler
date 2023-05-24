import xml.etree.ElementTree as ET
import re
from docx.shared import Cm
from docx.enum.style import WD_STYLE
from styles import create_styles
from utils.parse import *
from utils.patterns import *

def process_vulnerabilities(vulnerabilities, finding_name, description, plugin_output, host, output_as_dict=False):
    if finding_name not in vulnerabilities:
        vulnerabilities[finding_name] = {
            'description': description,
            'plugin_output': {} if output_as_dict else plugin_output,
            'targets': []
        }
    if host not in vulnerabilities[finding_name]['targets']:
        vulnerabilities[finding_name]['targets'].append(host)
    if output_as_dict:
        vulnerabilities[finding_name]['plugin_output'][host] = plugin_output
