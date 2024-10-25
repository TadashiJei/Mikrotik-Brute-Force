# MikrotikAPI Brute Force Tool

## Educational Purpose Only

This repository contains a Python-based tool demonstrating RouterOS API interactions and authentication mechanisms. This is intended for educational purposes to understand API security testing and network device interactions.

## Features

### Core Functionality
- Implements RouterOS API communication protocol
- Supports both modern and legacy API authentication methods
- Performs systematic credential validation
- Compatible with Python 3.x

### Connection Features
- Supports both SSL and non-SSL connections
- Configurable connection timeout (default: 5 seconds)
- Automatic socket recovery for timeout scenarios
- Custom port configuration (default: 8728 for non-SSL)
- Error handling for various connection scenarios

### Authentication Testing Capabilities
- Default credential validation
- Dictionary-based authentication testing
- Custom username support (default: admin)
- Configurable retry delay between attempts
- Progress tracking and statistics

### Advanced Features
- Auto-save functionality
  - Saves progress to JSON file
  - Supports resume from last position
  - Configurable save interval

- Verbose Logging
  - Detailed API conversation logging
  - Configurable log output (file/console)
  - Debug information for troubleshooting

- Performance Statistics
  - Real-time progress tracking
  - Elapsed time monitoring
  - Attempt counter
  - Success/failure reporting

### Command Line Interface
```bash
OPTIONS
    -t, --target       RouterOS target IP
    -p, --port         RouterOS port (default 8728)
    -u, --user         User name (default admin)
    -h, --help         Help information
    -d, --dictionary   Password dictionary path
    -s, --seconds      Delay between attempts (default 1)
    -q, --quiet        Quiet mode
    -a, --autosave     Auto-save progress file path
```

### Example Usage
```bash
python3 main.py -t 192.168.0.200 -u manager -p 1337 -d /tmp/passwords.txt -s 5
python3 main.py -t 192.168.0.1 -d /tmp/passwords.txt
python3 main.py -t 192.168.0.1 -d /tmp/passwords.txt -a /tmp/autosave.json
```

## Technical Implementation Details

### API Communication Protocol
- Custom implementation of RouterOS API protocol
- Handles word length encoding/decoding
- Supports sentence-based communication
- Implements proper connection lifecycle management

### Error Handling
- Socket connection errors
- Authentication failures
- Timeout scenarios
- API protocol errors
- Word length limitations

### Classes and Components
- `ApiRos`: Main API communication class
- `LoginError`: Custom exception for auth failures
- `WordTooLong`: Custom exception for protocol limits
- `CreateSocketError`: Custom exception for connection issues
- `RouterOSTrapError`: Custom exception for API errors

## Requirements
- Python 3.x
- Standard library modules:
  - binascii
  - getopt
  - hashlib
  - select
  - socket
  - ssl
  - json
  - codecs
  - time
  - signal

## Notes
- This tool implements proper socket timeout handling
- Includes automatic retry mechanisms for connection issues
- Supports UTF-8 dictionary files with error handling
- Provides detailed progress and status information

## Author
- Original Author: Tadashi Jei
- GitHub: https://github.com/TadashiJei/Mikrotik-Brute-Force

## Version
Tool Version: 1.0

## Disclaimer
This tool is provided for educational purposes only. Users are responsible for ensuring compliance with applicable laws and regulations when studying network security concepts.
