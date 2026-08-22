# Network Vulnerability Scanner

## Overview

A Bash-based network vulnerability scanner that uses Nmap to identify open ports, detect running services, and check for potential security vulnerabilities. The script also queries the National Vulnerability Database for known CVEs associated with detected services.

## Purpose

This project was developed for NTS370 to demonstrate network security assessment, Bash scripting, vulnerability analysis, API integration, and security best practices.

## Features

- Accepts a target IP address or hostname.
- Identifies open ports and running services using Nmap.
- Runs Nmap vulnerability detection scripts.
- Checks service versions against known vulnerabilities.
- Queries the National Vulnerability Database API for relevant CVEs.
- Extracts CVE descriptions and severity ratings using jq.
- Creates timestamped security reports.
- Validates required dependencies and handles errors.

## Requirements

The following tools must be installed:

- Bash
- Nmap
- curl
- jq

Install the required tools on Ubuntu or Debian:

## Usage

Make the script executable:


Run the scanner against an authorized target


You can also scan your local machine


The script creates a timestamped report:


## Authorized Use

Only use this tool against systems you own or have explicit permission to scan. Unauthorized scanning may violate applicable laws or organizational policies.

## NVD Disclaimer

This product uses data from the NVD API but is not endorsed or certified by the NVD.
