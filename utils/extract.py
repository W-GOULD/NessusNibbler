import xml.etree.ElementTree as ET
import re
import csv
from collections import defaultdict
from lxml import etree
from docx.shared import Cm
from docx.enum.style import WD_STYLE
from styles import create_styles
from utils.parse import *
from utils.vulnerabilities import *

def parse_nessus_file(file_name):
    # Parse the file and return the root XML element
    tree = ET.parse(file_name)
    root = tree.getroot()
    return root


def parse_for_cis(file_name):
    tree = etree.parse(file_name)
    namespaces = {'cm': 'http://www.nessus.org/cm'}

    all_data = defaultdict(list)
    
    # Identify all unique hosts
    hosts = tree.xpath('//ReportHost')

    for host in hosts:
        # Filter ReportItems for each host
        report_items = host.xpath('.//ReportItem[cm:compliance-result="FAILED"]', namespaces=namespaces)

        for item in report_items:
            agent = item.find('agent')
            if agent is not None:
                check_name_element = item.find('cm:compliance-check-name', namespaces=namespaces)
                compliance_info_element = item.find('cm:compliance-info', namespaces=namespaces)
                compliance_actual_value_element = item.find('cm:compliance-actual-value', namespaces=namespaces)
                compliance_solution_element = item.find('cm:compliance-solution', namespaces=namespaces)

                if check_name_element is not None and compliance_info_element is not None and compliance_actual_value_element is not None:
                    match = re.match(r"(\d+(\.\d+)*)(.*)", check_name_element.text)
                    if match:
                        item_no, benchmark = match.groups()[0:3:2]
                        rationale = compliance_info_element.text.split('Rationale:\n\n')[1].split('\n\nImpact:')[0]
                        recommendation = compliance_solution_element.text if compliance_solution_element is not None else 'N/A'
                        current_setting = compliance_actual_value_element.text

                        # Check for Unix/Linux file permission pattern only for unix hosts
                        if agent.text == 'unix' and re.search(r'-[r-][w-][x-][r-][w-][x-][r-][w-][x-].*', current_setting):
                            current_setting = "Check Permissions"
                            
                        # Key for dictionary
                        key = (item_no, benchmark, rationale, recommendation, current_setting)

                        # Add host to the list of affected hosts for this key
                        all_data[key].append(host.get("name"))

    return all_data


def extract_data_from_nessus_file(root, microsoft_patches, third_party, linux_patches, unquoted_service_path):
    installed_software = {}
    linux_patches_lt = {}
    vulnerabilities = {}
    ms_bulletins_and_kbs = set()

    for host in root.findall(".//ReportHost"):
        target = host.get("name")
        for item in host.findall('.//ReportItem[@pluginID="45590"]'):
            software_text = item.find('plugin_output').text.strip()
            installed_software[target] = parse_installed_software(software_text)
        
        if linux_patches:
            for item in host.findall('.//ReportItem[@pluginID="66334"]'):
                linux_patches_text = item.find('plugin_output').text.strip()
                linux_patches_lt[target] = parse_linux_patches(linux_patches_text)

        if microsoft_patches:
            for item in host.findall('.//ReportItem[@pluginID="38153"]'):
                plugin_output = item.find('plugin_output').text.strip()
                for line in plugin_output.split('\n'):
                    match = re.search(r'- (MS\d+-\d+|KB\d+)', line)
                    if match:
                        ms_bulletins_and_kbs.add(match.group(1))
            for finding in root.findall('.//ReportItem'):
                finding_name = finding.find('plugin_name').text
                if finding_name.startswith("Security Update for"):
                    ms_bulletins_and_kbs.add(finding_name)

        for finding in host.findall('.//ReportItem'):
            plugin_id = finding.get("pluginID")
            plugin_family = finding.get('pluginFamily')
            severity = int(finding.get("severity"))
            if severity >= 1:
                plugin_name_element = finding.find('plugin_name')
                if plugin_name_element is not None:
                    finding_name = plugin_name_element.text
                else:
                    finding_name = ''
                
                description_element = finding.find('description')
                if description_element is not None:
                    description = clean_description_text(description_element.text.strip())
                else:
                    description = ''
                
                plugin_output_element = finding.find('plugin_output')
                if plugin_output_element is not None:
                    plugin_output = plugin_output_element.text.strip()
                else:
                    plugin_output = 'N/A'
                    
                plugin_output = plugin_output_element.text.strip() if plugin_output_element is not None else 'N/A'

                if plugin_id == "63155" and unquoted_service_path:  # Microsoft Windows Unquoted Service Path Enumeration
                    process_vulnerabilities(vulnerabilities, finding_name, description, plugin_output, target, output_as_dict=True)
                else:
                    for host_key, software_list in installed_software.items():
                        combined_software_and_patches = software_list + list(ms_bulletins_and_kbs)
                        
                        for item in combined_software_and_patches:
                            if item in finding_name:
                                matched_bulletin_or_kb = any(bulletin_or_kb in finding_name for bulletin_or_kb in ms_bulletins_and_kbs)
                                
                                if microsoft_patches and matched_bulletin_or_kb:
                                    process_vulnerabilities(vulnerabilities, finding_name, description, plugin_output, host_key)
                                elif third_party and not matched_bulletin_or_kb and "Microsoft" not in item:
                                    process_vulnerabilities(vulnerabilities, finding_name, description, plugin_output, host_key)

                    # Separate loop for Linux patches
                    if linux_patches:
                        if plugin_family in linux_local_security_checks:
                            for host_key, patches_list in linux_patches_lt.items():
                                for patch in patches_list:
                                    if patch in finding_name:
                                        process_vulnerabilities(vulnerabilities, finding_name, description, plugin_output, host_key)

    return vulnerabilities





def extract_findings_from_nessus_file(root):
    findings = []

    for host in root.findall(".//ReportHost"):
        target = host.get("name")
        os_tag = host.find('./HostProperties/tag[@name="os"]')
        os = os_tag.text if os_tag is not None else "Unknown"
        hostname = host.find('./HostProperties/tag[@name="host-fqdn"]').text if host.find('./HostProperties/tag[@name="host-fqdn"]') is not None else 'N/A'

        for item in host.findall('.//ReportItem'):
            plugin_id = item.get("pluginID")
            plugin_name = item.find('plugin_name').text
            severity = int(item.get("severity"))
            port = item.get("port")
            service = item.get("svc_name")

            if severity >= 0:
                description = clean_description_text(item.find('description').text.strip())
                synopsis = item.find('synopsis').text.strip()
                solution = item.find('solution').text.strip()
                plugin_output_element = item.find('plugin_output')
                plugin_output = plugin_output_element.text.strip() if plugin_output_element is not None and plugin_output_element.text is not None else 'N/A'
                cve = item.find('cve').text.strip() if item.find('cve') is not None else 'N/A'
                cvss3_base_score = item.find('cvss3_base_score').text.strip() if item.find('cvss3_base_score') is not None else 'N/A'
                cvss3_vector = item.find('cvss3_vector').text.strip() if item.find('cvss3_vector') is not None else 'N/A'
                external_reference = item.find('see_also').text.strip() if item.find('see_also') is not None else 'N/A'

                finding = {
                    'id': plugin_id,
                    'plugin_name': plugin_name,
                    'host_ip': target,
                    'port': port,
                    'service': service,
                    'os': os,
                    'hostname': hostname,
                    'risk_rating': severity,
                    'external_reference': external_reference,
                    'cvssv3': cvss3_base_score,
                    'cvssv3_vector': cvss3_vector,
                    'description': description,
                    'synopsis': synopsis,
                    'solution': solution,
                    'plugin_output': plugin_output,
                    'cve': cve
                }

                findings.append(finding)

    return findings