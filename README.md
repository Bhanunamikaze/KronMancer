# KronMancer

A comprehensive privilege escalation vulnerability scanner for Unix/Linux cron jobs and scheduled tasks.

## Overview

KronMancer is a defensive security tool designed for red team assessments and security auditing. It identifies potential privilege escalation vulnerabilities in cron jobs by analyzing scheduled tasks, their dependencies, and execution contexts.

## Features

### Comprehensive Cron Discovery
- System-wide crontab (`/etc/crontab`)
- Individual cron directories (`/etc/cron.d/*`)
- Run-parts directories (`/etc/cron.hourly`, `/etc/cron.daily`, etc.)
- User crontabs for privileged accounts
- Systemd timers (modern cron alternative)

### Vulnerability Detection
- **PATH Injection Analysis**: Identifies commands using relative paths that could be hijacked
- **Write Access Analysis**: Detects writable script files and parent directories
- **Dependency Chain Analysis**: Recursively follows sourced scripts and configuration files
- **Missing File Exploitation**: Finds opportunities to create malicious files in writable locations
- **Binary Hijacking**: Identifies writable binaries in PATH directories

### Advanced Analysis
- Multi-language support (Shell scripts, Python)
- Recursive dependency following with loop prevention
- Symlink attack detection
- Command substitution analysis
- Shebang interpreter validation

## MITRE ATT&CK Mapping

This tool implements detection for:
- **T1053.003**: Scheduled Task/Job: Cron
- Command and argument discovery
- File and directory permissions modification
- PATH environment variable manipulation
- Scheduled task persistence mechanisms

## Installation & Running

```bash
git clone https://github.com/bhanunamikaze/kronmancer.git
cd kronmancer
chmod +x KronMancer.sh
./KronMancer.sh
```

## Output

The scanner provides clean output showing only security vulnerabilities:

```
KRONMANCER v2.0 - Cron Privilege Escalation Scanner
Target: hostname | User: username | 2025-08-22 23:30:11

[CRITICAL] Found relative path in cron job: cd
[CRITICAL] Found relative path in cron job: test
[CRITICAL] Found relative path in cron job: command

SCAN COMPLETE - Vulnerabilities found: 3
VULNERABILITIES DISCOVERED:
[!] PATH_INJECTION_1_test: CROND:/etc/cron.d/e2scrub_all:10 3 * * * root test -e /run/systemd/system
[!] PATH_INJECTION_1_cd: SYSTEM:/etc/crontab:17 * * * * root cd / && run-parts --report /etc/cron.hourly
[!] PATH_INJECTION_1_command: CROND:/etc/cron.d/sysstat:59 23 * * * root command -v debian-sa1
```

## Vulnerability Types

### PATH Injection
Commands using relative paths that could be hijacked by placing malicious binaries earlier in the PATH.

### Write Access Vulnerabilities
- Direct write access to cron scripts
- Writable parent directories (symlink attacks)
- Missing files in writable directories

### Dependency Vulnerabilities
- Missing sourced scripts that could be created
- Writable configuration files
- Recursive dependency chains

## Requirements

- Bash 4.0+
- Standard Unix utilities (grep, awk, find, etc.)
- Read access to cron directories (some features require elevated privileges)

## Security Considerations

This tool is designed for:
- Authorized security assessments
- System hardening and compliance checks
- Red team exercises on owned systems
- Defensive security auditing

**Do not use on systems you do not own or have explicit permission to test.**

## License

This project is provided for educational and authorized security testing purposes only.
