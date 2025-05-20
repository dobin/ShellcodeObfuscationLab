# SOL ShellcodeObfuscationLab

Shellcode obfuscations laboratory based on RedSiege [Chromatophore](https://github.com/RedSiege/Chromatophore/). 


## Results


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
| No obfuscation     | \-                    | \-                        | \-                                 | 2          | 3              |
## Usage

Use the `x64 native tools command prompt` from Visual Studio
so you have access to `ml.exe` and `Windows.h`. 



