# VulnBrew

**VulnBrew** is a versatile exploit crafting toolkit designed for penetration testers and cybersecurity enthusiasts. It enables users to generate payloads, set up reverse listeners, and test vulnerabilities with ease. The tool supports multiple file types, including Markdown-specific exploits, making it adaptable to various scenarios.

## Features

- **Payload Generation**: Create payloads for `.php`, `.jsp`, `.py`, `.sh`, and `.md` file types.
- **Markdown Exploits**: Choose from various Markdown-specific exploits:
  - Image SSRF
  - HTML XSS
  - Code Injection
  - Local File Inclusion
  - JavaScript Links
- **Reverse Shell Listener**: Easily set up a Netcat listener.
- **HTTP Server**: Start a Python-based HTTP server to host malicious files.
- **Interactive Console**: User-friendly interface with helpful prompts and validations.

## Requirements

- Python 3.6 or higher
- Netcat (optional, for setting up reverse shell listeners)

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/vulnbrew.git
   ```
2. Navigate to the project directory:
   ```bash
   cd vulnbrew
   ```
3. Run the script:
   ```bash
   python3 main.py
   ```

## Usage

1. Launch the tool:
   ```bash
   python3 main.py
   ```
2. Type `help` in the console to see available commands.
3. Use the `generate` command to create a payload:
   - Select the file type (`.php`, `.jsp`, `.py`, `.sh`, or `.md`).
   - For `.md`, choose the specific exploit type (e.g., Image SSRF, HTML XSS).
4. Use the `listener` command to set up a Netcat listener:
   ```bash
   listener <port>
   ```
5. Use the `http` command to start a Python HTTP server:
   ```bash
   http <port>
   ```

## Examples

### Generate a Markdown Payload (Image SSRF)

1. Enter your IP address and port:
   ```
   [>] Enter the IP address for the payload: 10.10.2.4
   [>] Enter the port for the reverse shell: 1234
   ```
2. Select `.md` as the file extension and choose `Image SSRF` as the exploit type.
3. Save the payload and upload the `.md` file to the target system.

### Set Up a Listener

Run the following command to catch reverse shells:
```bash
nc -lvnp 1234
```

## Contribution

Contributions are welcome! Feel free to submit issues, feature requests, or pull requests.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

---

*Disclaimer: This tool is intended for educational and authorized penetration testing purposes only. Misuse of this tool is strictly prohibited.*
