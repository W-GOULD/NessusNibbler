SOFTWARE_REGEX_PATTERN = r'cpe:/.*->\s+(.*)'
LINUX_PATCHES_REGEX_PATTERN = r'\[ (.*?) \('
DESCRIPTION_CLEANUP_REGEX_PATTERN1 = r'<code>|</code>'
DESCRIPTION_CLEANUP_REGEX_PATTERN2 = r' {2,}'
MICROSOFT_PATCHES_REGEX_PATTERN = r'- (MS\d+-\d+|KB\d+)'

linux_local_security_checks = [
    'Alma Linux Local Security Checks',
    'Amazon Linux Local Security Checks',
    'CentOS Local Security Checks',
    'Fedora Local Security Checks',
    'Debian Local Security Checks',
    'Gentoo Local Security Checks',
    'Oracle Linux Local Security Checks',
    'Red Hat Local Security Checks',
    'Rocky Linux Local Security Checks',
    'Scientific Linux Local Security Checks',
    'SuSE Local Security Checks',
    'Ubuntu Local Security Checks'
]