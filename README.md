# NetSentinel-CVE

A desktop security auditing tool designed for automated network port discovery, service banner analysis, and vulnerability lookup.

## Overview

NetSentinel-CVE scans targeted IP addresses for open TCP ports, captures service banners, and queries the CIRCL REST API to map detected services to known Common Vulnerabilities and Exposures (CVEs) and CVSS severity scores. All scan results and vulnerability findings are persisted in a local SQLite database and displayed via a multi-threaded desktop GUI.

## Key Features

* TCP port scanning using standard sockets
* Service banner grabbing for version detection
* Automated CVE and CVSS score retrieval via CIRCL API
* Persistent local storage using SQLite
* Asynchronous execution to prevent GUI freezing during network requests

## Tech Stack

* Python
* Sockets & Threading (Standard Library)
* Requests (REST API client)
* SQLite3 (Local persistence)
* Tkinter (Desktop GUI)