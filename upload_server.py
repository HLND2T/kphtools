#!/usr/bin/env python3
"""
File Upload Server for KPH Dynamic Data

HTTP server that handles file uploads, validates PE files and digital signatures,
and stores files in the symbol directory structure.

Upload format:
    application/octet-stream: Raw binary file upload

Optional features:
    - X-File-Compressed: gzip header to indicate gzip-compressed file

Usage:
    python upload_server.py -symboldir=C:/Symbols [-port=8000]

    Or:
    python upload_server.py -symboldir C:/Symbols -port 8000

    Upload example:
    curl -X POST -H "Content-Type: application/octet-stream" --data-binary "@ntoskrnl.exe" http://localhost:8000/upload

Requirements:
    Python packages:
        pip install pefile signify

    System dependencies (Ubuntu/Debian):
        sudo apt-get install -y libssl-dev

    System dependencies (CentOS/RHEL/Fedora):
        sudo yum install -y openssl-devel
        # or on newer versions:
        sudo dnf install -y openssl-devel
"""

import os
import sys
import argparse
import hashlib
import http.server
import json
import re
from io import BytesIO
from urllib.parse import urlparse, parse_qs
import gzip

try:
    import pefile
    from signify.authenticode.signed_file.pe import SignedPEFile
    from signify.authenticode.verification_result import VerificationError
except ImportError as e:
    error_name = getattr(e, 'name', str(e).split("'")[1] if "'" in str(e) else 'unknown')
    print(f"Error: Missing required dependency: {error_name}")
    print("Please install required packages: pip install pefile signify")
    sys.exit(1)
except Exception as e:
    # Handle oscrypto errors (missing OpenSSL libraries)
    error_str = str(e)
    error_type = type(e).__name__
    
    if 'libcrypto' in error_str or 'LibraryNotFoundError' in error_type:
        print("=" * 70)
        print("Error: OpenSSL library (libcrypto) detection failed.")
        print("=" * 70)
        print("")
    else:
        print(f"Error importing signify library: {e}")
        print(f"Error type: {error_type}")
        print("Please ensure all dependencies are correctly installed.")
    sys.exit(1)


MAX_FILE_SIZE = 20 * 1024 * 1024  # 20MB
UPLOAD_DIR = 'uploads'
ALLOW_FILENAME = ['ntoskrnl.exe', 'ntkrnlmp.exe', 'ntkrla57.exe']
ALLOW_FILEDESC = ['NT Kernel & System']
ALLOW_ARCH = ['x86', 'amd64', 'arm64']

# Threaded HTTP server to allow concurrent requests (e.g., uploads + health checks).
class ThreadedHTTPServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

# Regex pattern for file version: X.X.X.X where X is a ushort (0-65535)
FILEVERSION_PATTERN = re.compile(
    r'^(?:0|[1-9]\d{0,4}|[1-5]\d{4}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5])\.'
    r'(?:0|[1-9]\d{0,4}|[1-5]\d{4}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5])\.'
    r'(?:0|[1-9]\d{0,4}|[1-5]\d{4}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5])\.'
    r'(?:0|[1-9]\d{0,4}|[1-5]\d{4}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5])$'
)


def validate_exists_params(arch, filename, fileversion, sha256):
    """
    Validate parameters for /exists endpoint.

    Args:
        arch: Architecture string
        filename: Filename string
        fileversion: File version string
        sha256: SHA256 hash string (lowercase, 64 hex characters)

    Returns:
        Tuple of (is_valid: bool, error_message: str or None)
    """
    # Validate arch
    if arch not in ALLOW_ARCH:
        return (False, f"Invalid arch: must be one of {ALLOW_ARCH}")

    # Validate filename (case-insensitive)
    if filename.lower() not in [name.lower() for name in ALLOW_FILENAME]:
        return (False, f"Invalid filename: must be one of {ALLOW_FILENAME}")

    # Validate fileversion format: X.X.X.X where X is ushort (0-65535)
    if not FILEVERSION_PATTERN.match(fileversion):
        return (False, "Invalid fileversion: must be in format X.X.X.X where X is 0-65535")

    # Validate sha256 format: 64 lowercase hex characters
    if len(sha256) != 64 or not all(c in '0123456789abcdef' for c in sha256.lower()):
        return (False, "Invalid sha256: must be 64 lowercase hexadecimal characters")

    return (True, None)


def check_file_exists(symboldir, arch, filename, fileversion, sha256):
    """
    Check if a file exists in the symbol directory.

    Args:
        symboldir: Base symbol directory path
        arch: Architecture (x86/amd64/arm64)
        filename: Filename to check
        fileversion: File version string
        sha256: SHA256 hash of the file (lowercase)

    Returns:
        Dictionary with file existence information:
        {
            'filename': str,
            'arch': str,
            'fileversion': str,
            'sha256': str,
            'exists': bool,
            'path': str,
            'file_size': int (optional, only if file exists)
        }
    """
    # Build file path: {symboldir}/{arch}/{filename}.{fileversion}/{sha256}/{filename}
    target_dir = os.path.join(symboldir, arch, f"{filename}.{fileversion}", sha256)
    target_path = os.path.join(target_dir, filename)

    # Build relative path (relative to symboldir) for response
    # Format: {arch}/{filename}.{fileversion}/{sha256}/{filename}
    relative_path = os.path.join(arch, f"{filename}.{fileversion}", sha256, filename)
    # Normalize path separators to forward slashes for consistency
    relative_path = relative_path.replace(os.sep, '/')

    # Check if file exists
    file_exists = os.path.exists(target_path) and os.path.isfile(target_path)

    # Prepare response data
    result = {
        'filename': filename,
        'arch': arch,
        'fileversion': fileversion,
        'sha256': sha256,
        'exists': file_exists,
        'path': relative_path
    }

    if file_exists:
        # Get file size
        try:
            file_size = os.path.getsize(target_path)
            result['file_size'] = file_size
        except OSError:
            pass

    return result


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="HTTP server that handles file uploads, validates PE files and digital signatures"
    )
    parser.add_argument(
        "-symboldir",
        required=False,
        help="Directory to store uploaded files (can also be set via KPHTOOLS_SYMBOLDIR environment variable)"
    )
    parser.add_argument(
        "-port",
        type=int,
        default=8000,
        help="Port to listen on (default: 8000, can also be set via KPHTOOLS_SERVER_PORT environment variable)"
    )
    
    args = parser.parse_args()
    
    return args


def verify_pe_file(file_data):
    """
    Verify PE file and extract information.
    
    Args:
        file_data: Bytes data of the PE file
        
    Returns:
        Dictionary with file_name, file_version, arch, or None if validation fails
    """
    try:
        # Parse PE file from memory
        pe = pefile.PE(data=file_data)
        
        # Extract FileInfo
        file_description = None
        original_filename = None
        file_version = None
        
        if hasattr(pe, 'FileInfo') and pe.FileInfo:
            # FileInfo is a list of lists, where each inner list contains structures
            for fileinfo_list in pe.FileInfo:
                if not isinstance(fileinfo_list, list):
                    continue
                for fileinfo in fileinfo_list:
                    # Check if this structure has a Key attribute and it's StringFileInfo
                    if hasattr(fileinfo, 'Key') and fileinfo.Key == b'StringFileInfo':
                        # Check if it has StringTable attribute
                        if hasattr(fileinfo, 'StringTable') and fileinfo.StringTable:
                            for st in fileinfo.StringTable:
                                if hasattr(st, 'entries') and st.entries:
                                    for key, value in st.entries.items():
                                        if key == b'FileDescription':
                                            file_description = value.decode('utf-8', errors='ignore')
                                        elif key == b'OriginalFilename':
                                            original_filename = value.decode('utf-8', errors='ignore')
                                        elif key == b'FileVersion':
                                            file_version = value.decode('utf-8', errors='ignore')
        
        # Verify FileDescription is in allowed list
        if file_description not in ALLOW_FILEDESC:
            return None
        
        # Check required fields
        if not original_filename or not file_version:
            return None
        
        # Verify OriginalFilename is in allowed list
        if original_filename.lower() not in [name.lower() for name in ALLOW_FILENAME]:
            return None
        
        # Normalize filename: if OriginalFilename is ntkrnlmp.exe, use ntoskrnl.exe
        if original_filename.lower() == 'ntkrnlmp.exe':
            original_filename = 'ntoskrnl.exe'
        
        # Clean file version: remove content in parentheses if present
        # Example: "10.0.26100.7462 (WinBuild.160101.0800)" -> "10.0.26100.7462"
        if '(' in file_version:
            file_version = file_version.split('(')[0].strip()
        
        # Determine architecture
        machine = pe.FILE_HEADER.Machine
        if machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_I386']:
            arch = 'x86'
        elif machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64']:
            arch = 'amd64'
        elif machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_ARM64']:
            arch = 'arm64'
        else:
            return None
        
        pe.close()
        
        return {
            'file_name': original_filename,
            'file_version': file_version,
            'arch': arch
        }
        
    except pefile.PEFormatError:
        return None
    except Exception as e:
        print(f"Error parsing PE file: {e}")
        return None


def verify_signature(file_data):
    """
    Verify Authenticode digital signature.

    Args:
        file_data: Bytes data of the PE file

    Returns:
        True if signature is valid and matches requirements, False otherwise
    """
    try:
        # Debug: print file size and hash
        import hashlib
        print(f'[DEBUG] File size: {len(file_data)} bytes')
        print(f'[DEBUG] File SHA256: {hashlib.sha256(file_data).hexdigest()}')

        # Create SignedPEFile from bytes
        file_io = BytesIO(file_data)
        signed_pe = SignedPEFile(file_io)
        
        # Verify the signature - this will raise VerificationError if invalid
        try:
            signed_pe.verify()
        except VerificationError as e:
            print(f'VerificationError: {e}')
            return False
        
        # Check signer and issuer from embedded signatures
        for signature in signed_pe.iter_embedded_signatures():
            signer_info = signature.signer_info
            
            # Get signer certificate from signature certificates using issuer and serial_number
            signer_cert = None
            if hasattr(signature, 'certificates') and signature.certificates:
                # Find certificate matching signer_info's issuer and serial_number
                for cert in signature.certificates:
                    try:
                        if (hasattr(cert, 'issuer') and hasattr(cert, 'serial_number') and
                            hasattr(signer_info, 'issuer') and hasattr(signer_info, 'serial_number')):
                            if (str(cert.issuer) == str(signer_info.issuer) and
                                cert.serial_number == signer_info.serial_number):
                                signer_cert = cert
                                break
                    except:
                        pass
                
                # If no match found, use first certificate as fallback
                if not signer_cert and signature.certificates:
                    signer_cert = signature.certificates[0]
            
            if not signer_cert:
                continue
            
            # Extract signer name (subject CN) - try multiple methods
            signer_name = None
            if hasattr(signer_cert, 'subject'):
                subject = signer_cert.subject
                # Try common_name attribute
                if hasattr(subject, 'common_name'):
                    signer_name = subject.common_name
                # Try native representation
                elif hasattr(subject, 'native'):
                    subject_native = subject.native
                    if isinstance(subject_native, dict):
                        # Look for common_name in various formats
                        for attr in ['common_name', 'CN', '2.5.4.3', 'commonName']:
                            if attr in subject_native:
                                signer_name = subject_native[attr]
                                break
                    elif isinstance(subject_native, str):
                        signer_name = subject_native
                # Try to get from string representation
                elif hasattr(subject, '__str__'):
                    subject_str = str(subject)
                    # Try to extract CN from string like "CN=Microsoft Windows, ..."
                    if 'CN=' in subject_str:
                        cn_part = subject_str.split('CN=')[1].split(',')[0].strip()
                        signer_name = cn_part
            
            # Extract issuer name - try multiple methods
            issuer_name = None
            if hasattr(signer_cert, 'issuer'):
                issuer = signer_cert.issuer
                # Try common_name attribute
                if hasattr(issuer, 'common_name'):
                    issuer_name = issuer.common_name
                # Try native representation
                elif hasattr(issuer, 'native'):
                    issuer_native = issuer.native
                    if isinstance(issuer_native, dict):
                        # Look for common_name in various formats
                        for attr in ['common_name', 'CN', '2.5.4.3', 'commonName']:
                            if attr in issuer_native:
                                issuer_name = issuer_native[attr]
                                break
                    elif isinstance(issuer_native, str):
                        issuer_name = issuer_native
                # Try to get from string representation
                elif hasattr(issuer, '__str__'):
                    issuer_str = str(issuer)
                    # Try to extract CN from string like "CN=Microsoft Windows Production PCA 2011, ..."
                    if 'CN=' in issuer_str:
                        cn_part = issuer_str.split('CN=')[1].split(',')[0].strip()
                        issuer_name = cn_part
            
            # Verify signer and issuer
            if signer_name == 'Microsoft Windows' and issuer_name == 'Microsoft Windows Production PCA 2011':
                return True
        
        return False
        
    except VerificationError:
        return False
    except Exception as e:
        # Don't print error in production, just return False
        return False


def save_file(file_data, file_name, file_version, arch, symboldir):
    """
    Save file to target directory.

    Args:
        file_data: Bytes data of the file
        file_name: Original filename
        file_version: File version
        arch: Architecture (x86/amd64/arm64)
        symboldir: Base symbol directory

    Returns:
        Tuple of (success: bool, message: str, status_code: int, sha256: str or None)
    """
    # Calculate SHA256 hash of the file
    file_hash = hashlib.sha256(file_data).hexdigest().lower()

    # Build target path: {symboldir}/{arch}/{FileName}.{FileVersion}/{sha256}/{FileName}
    target_dir = os.path.join(symboldir, arch, f"{file_name}.{file_version}", file_hash)
    target_path = os.path.join(target_dir, file_name)

    # Check if file already exists
    if os.path.exists(target_path):
        # Compare file contents by hash (file path already includes hash, so it should match)
        with open(target_path, 'rb') as f:
            existing_data = f.read()

        existing_hash = hashlib.sha256(existing_data).hexdigest().lower()

        if existing_hash == file_hash:
            return (True, "File already exists and is identical", 200, file_hash)
        else:
            # This should not happen since path includes hash, but handle it anyway
            return (False, "File already exists with different content", 409, file_hash)

    # Create directory if needed
    try:
        os.makedirs(target_dir, exist_ok=True)
    except OSError as e:
        return (False, f"Failed to create directory: {e}", 500, file_hash)

    # Save file
    try:
        with open(target_path, 'wb') as f:
            f.write(file_data)
        return (True, "File uploaded successfully", 200, file_hash)
    except OSError as e:
        return (False, f"Failed to save file: {e}", 500, file_hash)


class UploadHandler(http.server.BaseHTTPRequestHandler):
    """HTTP request handler for file uploads."""
    
    def __init__(self, *args, symboldir=None, **kwargs):
        self.symboldir = symboldir
        super().__init__(*args, **kwargs)
    
    def send_json_response(self, status_code, message, data=None):
        """
        Send JSON response.
        
        Args:
            status_code: HTTP status code
            message: Response message
            data: Optional additional data dictionary
        """
        response = {
            'success': 200 <= status_code < 300,
            'message': message
        }
        if data:
            response.update(data)
        
        response_json = json.dumps(response, ensure_ascii=False)
        
        try:
            self.send_response(status_code)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.end_headers()
            self.wfile.write(response_json.encode('utf-8'))
        except (ConnectionResetError, BrokenPipeError):
            # 客户端已断开连接，忽略
            pass
    
    def send_error(self, code, message=None, explain=None):
        """
        Override send_error to return JSON instead of HTML.
        
        Args:
            code: HTTP status code
            message: Error message
            explain: Additional explanation (ignored, message is used instead)
        """
        if message is None:
            # Default messages for common status codes
            messages = {
                400: "Bad Request",
                401: "Unauthorized",
                403: "Forbidden",
                404: "Not Found",
                405: "Method Not Allowed",
                500: "Internal Server Error",
                501: "Not Implemented",
                502: "Bad Gateway",
                503: "Service Unavailable",
            }
            message = messages.get(code, f"Error {code}")
        
        self.send_json_response(code, message)
    
    def do_GET(self):
        """Handle GET requests to /health and /exists."""
        parsed_url = urlparse(self.path)
        path = parsed_url.path

        # Handle health check endpoint
        if path == '/health':
            self.send_json_response(200, "OK", {'status': 'healthy'})
            return

        if path == '/':
            self.send_json_response(200, "OK", {'status': 'healthy'})
            return

        # Handle file existence check endpoint
        if path != '/exists':
            self.send_json_response(404, "Not Found")
            return

        # Parse query parameters
        query_params = parse_qs(parsed_url.query)

        # Get required parameters
        filename = query_params.get('filename', [None])[0]
        arch = query_params.get('arch', [None])[0]
        fileversion = query_params.get('fileversion', [None])[0]
        sha256 = query_params.get('sha256', [None])[0]

        # Validate required parameters
        if not filename or not arch or not fileversion or not sha256:
            self.send_json_response(400, "Missing required parameters: filename, arch, fileversion, and sha256 are required")
            return

        # Normalize sha256 to lowercase
        sha256 = sha256.lower()

        # Validate parameter values
        is_valid, error_message = validate_exists_params(arch, filename, fileversion, sha256)
        if not is_valid:
            self.send_json_response(400, error_message)
            return

        # Check file existence
        response_data = check_file_exists(self.symboldir, arch, filename, fileversion, sha256)

        self.send_json_response(200, "File existence checked", response_data)

    def do_HEAD(self):
        """Handle HEAD requests for health checks."""
        parsed_url = urlparse(self.path)
        path = parsed_url.path

        if path in ('/health', '/'):
            # HEAD must not send a message body; only headers.
            self.send_response(200)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.send_header('Content-Length', '0')
            self.end_headers()
            return

        self.send_response(404)
        self.send_header('Content-Length', '0')
        self.end_headers()
    
    def do_POST(self):
        """Handle POST requests to /upload."""
        if self.path != '/upload':
            self.send_json_response(404, "Not Found")
            return
        
        # Check content length
        try:
            content_length = int(self.headers.get('Content-Length', 0))
        except ValueError:
            self.send_json_response(400, "Invalid Content-Length")
            return
        
        if content_length > MAX_FILE_SIZE:
            self.send_json_response(413, f"File too large (max {MAX_FILE_SIZE / (1024 * 1024)}MB)")
            return
        
        if content_length == 0:
            self.send_json_response(400, "No file data")
            return
        
        # Check Content-Type and handle accordingly
        content_type = self.headers.get('Content-Type', '').lower()

        # Only accept application/octet-stream or empty Content-Type
        if not (content_type.startswith('application/octet-stream') or content_type == ''):
            self.send_json_response(400, "Content-Type must be application/octet-stream")
            return

        # Read file data directly from request body
        try:
            file_data = self.rfile.read(content_length)
        except Exception as e:
            self.send_json_response(400, f"Failed to read file data: {e}")
            return

        # Verify file size does not exceed maximum allowed size (compressed size)
        if len(file_data) > MAX_FILE_SIZE:
            self.send_json_response(413, f"File too large (max {MAX_FILE_SIZE / (1024 * 1024)}MB)")
            return

        # Handle optional gzip compression indicated by header
        compression_type = self.headers.get('X-File-Compressed', '').strip().lower()
        if compression_type == 'gzip':
            try:
                file_data = gzip.decompress(file_data)
            except OSError as e:
                self.send_json_response(400, f"Failed to decompress gzip data: {e}")
                return

            # Check decompressed size as well
            if len(file_data) > MAX_FILE_SIZE:
                self.send_json_response(413, f"Decompressed file too large (max {MAX_FILE_SIZE / (1024 * 1024)}MB)")
                return
        
        # Verify PE file and extract information
        pe_info = verify_pe_file(file_data)
        if not pe_info:
            self.send_json_response(400, "Invalid PE file or FileDescription does not match 'NT Kernel & System'")
            return
        
        # Verify digital signature
        if not verify_signature(file_data):
            self.send_json_response(400, "Digital signature verification failed or does not match requirements")
            return
        
        # Save file
        success, message, status_code, file_hash = save_file(
            file_data,
            pe_info['file_name'],
            pe_info['file_version'],
            pe_info['arch'],
            self.symboldir
        )

        if success:
            self.send_json_response(status_code, message, {
                'file_name': pe_info['file_name'],
                'file_version': pe_info['file_version'],
                'arch': pe_info['arch'],
                'sha256': file_hash
            })
        else:
            self.send_json_response(status_code, message)
    
    def log_message(self, format, *args):
        """Override to customize log format."""
        pass
        sys.stderr.write("%s - - [%s] %s\n" %
                        (self.address_string(),
                         self.log_date_time_string(),
                         format % args))


def main():
    """Main entry point."""
    args = parse_args()
    
    # Get symboldir from environment variable or command line argument
    symboldir = os.environ.get('KPHTOOLS_SYMBOLDIR')
    if not symboldir:
        symboldir = args.symboldir
    
    # Validate that symboldir is provided
    if not symboldir:
        print("Error: symboldir must be provided either via KPHTOOLS_SYMBOLDIR environment variable or -symboldir command line argument")
        sys.exit(1)
    
    # Get port from environment variable or command line argument
    port_env = os.environ.get('KPHTOOLS_SERVER_PORT')
    if port_env:
        try:
            port = int(port_env)
        except ValueError:
            print(f"Error: Invalid KPHTOOLS_SERVER_PORT environment variable value: {port_env}")
            sys.exit(1)
    else:
        port = args.port
    
    # Validate symbol directory
    if not os.path.exists(symboldir):
        try:
            os.makedirs(symboldir, exist_ok=True)
        except OSError as e:
            print(f"Error: Cannot create symbol directory: {e}")
            sys.exit(1)
    
    # Ensure upload directory exists
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    
    print(f"Symbol directory: {symboldir}")
    print(f"Upload directory: {UPLOAD_DIR}")
    print(f"Max file size: {MAX_FILE_SIZE / (1024 * 1024)}MB")
    print(f"Starting server on port {port}...")
    print(f"Upload endpoint: http://localhost:{port}/upload")
    
    # Create handler with symboldir parameter
    def handler_factory(*args, **kwargs):
        return UploadHandler(*args, symboldir=symboldir, **kwargs)
    
    # Start server
    try:
        with ThreadedHTTPServer(("", port), handler_factory) as httpd:
            print(f"Server started. Press Ctrl+C to stop.")
            httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped.")
    except OSError as e:
        print(f"Error: Failed to start server: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

