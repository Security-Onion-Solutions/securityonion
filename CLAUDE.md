# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

Security Onion is an open-source network security monitoring (NSM) platform that combines multiple security tools into a unified solution. It's designed for threat hunting, enterprise security monitoring, and log management. The platform integrates tools for intrusion detection, packet capture, log management, and security analytics in a comprehensive security monitoring solution.

## Architecture

Security Onion uses a microservice architecture with containerized components:

- **Deployment Models**:
  - Standalone: Single all-in-one instance
  - Distributed: Manager/sensor architecture with multiple node types
    - Manager: Central management server
    - Search Nodes: Data storage and search
    - Sensor Nodes: Network monitoring and data collection
    - Heavy Nodes: Combined sensor/search capabilities
    - IDH (Intrusion Deception Host): Honeypot services

- **Core Components**:
  - Data Collection: Zeek, Suricata, Steno (PCAP), Elastic Agents
  - Data Processing: Logstash, Kafka, Strelka (file analysis)
  - Data Storage: Elasticsearch, InfluxDB, Redis
  - User Interface: Kibana, SOC (custom Security Onion web UI), Kratos/Hydra (auth)
  - Management: Salt, Docker, Registry, Nginx

## Development Environment

### Prerequisites

- Linux environment (Oracle Linux or compatible)
- Git
- Docker and Docker Compose
- SaltStack

### Testing

Run validation tests:
```bash
cd tests
./validation.sh
```

Run Python tests (requires Python 3):
```bash
./pyci.sh salt/sensoroni/files/analyzers/urlhaus
```

### Key Files and Directories

- `/salt`: SaltStack states for all components
- `/setup`: Installation scripts and utilities
- `/pillar`: SaltStack pillar data (configuration)
- `/files`: Additional configuration files
- `/tests`: Test utilities and validation

## Common Tasks

### Testing Salt States

To test a specific Salt state without applying it:
```bash
salt-call state.show_sls <state_name>
```

To apply a Salt state in test mode:
```bash
salt-call state.apply <state_name> test=True
```

### Working with Docker Containers

View running containers:
```bash
so-status
```

Access container logs:
```bash
docker logs <container_name>
```

### Development Workflow

1. Make code changes
2. Run validation: `./tests/validation.sh`
3. Run Python tests if applicable: `./pyci.sh <directory>`

## Code Conventions

- All Bash scripts should pass ShellCheck analysis
- YAML (Salt states and pillars) should be properly formatted
- Python code should pass flake8 checks (configured in pytest.ini)
- Code should match the pre-existing style of Security Onion
- All commits must be signed with a valid key

## Important Notes

- Security Onion uses Salt for configuration management
- Most components run as Docker containers
- The project follows a distributed architecture with different node types
- Testing should cover both code functionality and deployment scenarios