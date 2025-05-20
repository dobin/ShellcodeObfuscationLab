from uuid import UUID


def bin_to_uuid(bin_file):
    # Author: Bobby Cooke (0xBoku/boku/boku7) // https://twitter.com/0xBoku // github.com/boku7 // https://www.linkedin.com/in/bobby-cooke/ // https://0xboku.com
    # Modified code from: https://blog.securehat.co.uk/process-injection/shellcode-execution-via-enumsystemlocala
    uuids = ''
    try:
        with open(bin_file, 'rb') as binfile:
            uuids = ''
            chunk = binfile.read(16)
            while chunk:
                if len(chunk) < 16:
                    padding = 16 - len(chunk)
                    chunk = chunk + (b"\x90" * padding)
                    uuids += "{}\"{}\"\n".format(' '*8,UUID(bytes_le=chunk))
                    break
                uuids += "{}\"{}\",\n".format(' '*8,UUID(bytes_le=chunk))
                chunk = binfile.read(16)
        return uuids
    except FileNotFoundError:
        exit("\nThe shellcode file you specified does not exist! Exiting...\n")


def uuidapi(input_file) -> str:
    uuids = bin_to_uuid(input_file)
    cstr = "char * UUIDs[] = {\n" + uuids + "\t};"
    return cstr

