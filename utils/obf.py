import argparse
import random
import re
import string

# C++ keywords to avoid renaming
KEYWORDS = {
    # Standard C++
    "alignas", "alignof", "and", "and_eq", "asm", "auto", "bitand", "bitor",
    "bool", "break", "case", "catch", "char", "char8_t", "char16_t", "char32_t",
    "class", "compl", "concept", "const", "consteval", "constexpr", "constinit",
    "const_cast", "continue", "co_await", "co_return", "co_yield", "decltype",
    "default", "delete", "do", "double", "dynamic_cast", "else", "enum",
    "explicit", "export", "extern", "false", "float", "for", "friend", "goto",
    "if", "inline", "int", "long", "mutable", "namespace", "new", "noexcept",
    "not", "not_eq", "nullptr", "operator", "or", "or_eq", "private",
    "protected", "public", "reflexpr", "register", "reinterpret_cast",
    "requires", "return", "short", "signed", "sizeof", "static", "size_t",
    "static_assert", "static_cast", "struct", "switch", "synchronized",
    "template", "this", "thread_local", "throw", "true", "try", "typedef",
    "typeid", "typename", "union", "unsigned", "using", "virtual", "void",
    "volatile", "wchar_t", "while", "xor", "xor_eq",

    # Standard Library
    "std", "cout", "wcout", "cin", "wcin", "endl", "string", "wstring", "vector", "map", "set",
    "list", "deque", "stack", "queue", "priority_queue", "pair",
    "tuple", "array", "unordered_map", "unordered_set", "shared_ptr",
    "unique_ptr", "weak_ptr", "thread", "mutex", "atomic", "future",
    "promise", "chrono", "iostream", "sstream", "str", "wstringstream", "fstream", "algorithm",
    "to_wstring", "size", "find", "replace", "substr", "find_last_not_of", "c_str",
    "length", "data", "begin", "end", "get", "hex", "npos", "getenv", "_stricmp",
    "reserve", "push_back",

    # Windows API Types & Constants
    "HANDLE", "PVOID", "LPWSTR", "DWORD", "BOOL", "NTSTATUS", "ULONG", "ULONG_PTR",
    "USHORT", "BYTE", "SIZE_T", "PULONG", "STARTUPINFOW", "PROCESS_INFORMATION",
    "SECURITY_ATTRIBUTES", "PROCESS_BASIC_INFORMATION", "PEB", "TEB",
    "CUSTOM_PEB", "CUSTOM_RTL_USER_PROCESS_PARAMETERS", "ProcessBasicInformation",
    "CREATE_SUSPENDED", "CREATE_NEW_CONSOLE", "FALSE", "NULL", "PebBaseAddress",
    "dwProcessId", "dwThreadId", "hProcess", "hThread", "cb", "nLength", "ProcessParameters",
    "CommandLine", "Length", "MaximumLength", "ImageBaseAddress", "Ldr", "HKEY", "LONG",
    "KEY_WRITE", "ERROR_SUCCESS", "REG_SZ", "MAX_PATH", "TRUE", "ERROR_FILE_EXISTS",
    "FILE_ATTRIBUTE_HIDDEN", "PROCESSENTRY32", "TH32CS_SNAPPROCESS", "INVALID_HANDLE_VALUE",
    "PROCESS_CREATE_THREAD", "PROCESS_VM_OPERATION", "PROCESS_VM_WRITE", "PROCESS_VM_READ",
    "MEM_COMMIT", "MEM_RESERVE", "PAGE_EXECUTE_READWRITE", "MEM_RELEASE", "LPTHREAD_START_ROUTINE",
    "dwSize", "szExeFile", "th32ProcessID", "RelocateResult", "RELOCATE_SUCCESS",
    "RELOCATE_ALREADY_EXISTS", "RELOCATE_FAILED",

    # Windows API Functions (CRITICAL ADDITION)
    "CreateProcessW", "NtQueryInformationProcess", "NtReadVirtualMemory",
    "NtWriteVirtualMemory", "NtResumeThread", "CloseHandle", "GetLastError",
    "ReadProcessMemory", "WriteProcessMemory", "ResumeThread", "OpenProcess",
    "VirtualAllocEx", "VirtualFreeEx", "VirtualProtectEx", "GetProcAddress",
    "LoadLibraryA", "LoadLibraryW", "FreeLibrary", "GetModuleHandleA", "GetModuleHandleW",
    "CreateFileW", "CreateFileA", "ReadFile", "WriteFile", "SetFilePointer",
    "GetFileSize", "CloseHandle", "FindFirstFileW", "FindFirstFileA",
    "FindNextFileW", "FindNextFileA", "FindClose", "CreateDirectoryW",
    "CreateDirectoryA", "RemoveDirectoryW", "RemoveDirectoryA", "DeleteFileW",
    "DeleteFileA", "MoveFileW", "MoveFileA", "CopyFileW", "CopyFileA",
    "GetCurrentDirectoryW", "GetCurrentDirectoryA", "SetCurrentDirectoryW",
    "SetCurrentDirectoryA", "GetTempPathW", "GetTempPathA", "CreateThread",
    "ExitThread", "WaitForSingleObject", "WaitForMultipleObjects", "Sleep",
    "GetTickCount", "GetSystemTime", "GetLocalTime", "QueryPerformanceCounter",
    "QueryPerformanceFrequency", "CreateMutexW", "CreateMutexA", "ReleaseMutex",
    "CreateEventW", "CreateEventA", "SetEvent", "ResetEvent", "CreateSemaphoreW",
    "CreateSemaphoreA", "ReleaseSemaphore", "InitializeCriticalSection",
    "EnterCriticalSection", "LeaveCriticalSection", "DeleteCriticalSection",
    "RegOpenKeyExW", "RegOpenKeyExA", "RegQueryValueExW", "RegQueryValueExA",
    "RegSetValueExW", "RegSetValueExA", "RegCloseKey", "RegCreateKeyExW",
    "RegCreateKeyExA", "RegDeleteKeyW", "RegDeleteKeyA", "RegDeleteValueW",
    "RegDeleteValueA", "GetConsoleWindow", "AllocConsole", "FreeConsole",
    "SetConsoleTitle", "SetConsoleTitleA", "SetConsoleTitleW",
    "GetStdHandle", "SetStdHandle", "WriteConsoleW", "WriteConsoleA",
    "ReadConsoleW", "ReadConsoleA", "MessageBoxW", "MessageBoxA",
    "ShowWindow", "UpdateWindow", "GetWindowTextW", "GetWindowTextA",
    "SetWindowTextW", "SetWindowTextA", "FindWindowW", "FindWindowA",
    "GetWindowRect", "SetWindowPos", "MoveWindow", "IsWindow",
    "DestroyWindow", "PostMessageW", "PostMessageA", "SendMessageW",
    "SendMessageA", "GetMessageW", "GetMessageA", "PeekMessageW",
    "PeekMessageA", "TranslateMessage", "DispatchMessageW", "DispatchMessageA",
    "GetModuleFileNameA", "SetFileAttributesA", "CreateToolhelp32Snapshot", "Process32First",
    "Process32Next", "CreateRemoteThread",
    "wcslen", "wcscpy", "wcscat", "wcscmp", "wcsncmp", "wcsstr", "wcstok",
    "malloc", "free", "calloc", "realloc", "memcpy", "memmove", "memset",
    "memcmp", "strlen", "strcpy", "strcat", "strcmp", "strncmp", "strstr",
    "strtok", "printf", "sprintf", "fprintf", "scanf", "sscanf", "fscanf",
    "fopen", "fclose", "fread", "fwrite", "fseek", "ftell", "rewind",
    "fflush", "feof", "ferror", "clearerr",

    # User-defined functions we want to preserve
    "PadRight", "Debug", "CheckForDebugger", "AntiVM", "isVM", "AntiSandbox",
    "check_cpuid", "check_timing", "check_ram", "check_mac_address",
    "check_hardware_names", "check_linux_artifacts", "check_registry_keys",
    "check_vm_files", "check_running_processes", "UnhookCriticalAPIs", "PreventRemoteThreadCreation",


    # Reserved words
    "main", "WinMain", "include", "define", "pragma", "ifdef", "endif", "ifndef", "comment", "lib"
}

# Regular expressions for parsing
RE_STRING = re.compile(r'(L)?("([^"\\]*(?:\\.[^"\\]*)*)")|R"(\((?:[^\)]|\n)*\))"')
RE_COMMENT = re.compile(r'//.*?$|/\*.*?\*/', re.MULTILINE | re.DOTALL)
RE_IDENTIFIER = re.compile(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b')
RE_PREPROCESSOR = re.compile(r'^\s*#.*', re.MULTILINE)

def minify(code):
    """Removes comments and extra whitespace."""
    preprocessor_lines = RE_PREPROCESSOR.findall(code)
    code = RE_PREPROCESSOR.sub('', code)
    code = RE_COMMENT.sub('', code)
    lines = [line.strip() for line in code.split('\n') if line.strip()]
    return '\n'.join(preprocessor_lines) + '\n' + '\n'.join(lines)

def get_random_name(length=8):
    """Generates a random identifier name."""
    return '_' + ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))

def generate_junk_struct_or_union():
    """Generates a C++ definition for a random struct or union."""
    type_keyword = random.choice(["struct", "union"])
    type_name = get_random_name()

    num_members = random.randint(2, 5)
    members = []
    basic_types = ["int", "char", "bool", "float", "double", "long"]

    for _ in range(num_members):
        member_name = get_random_name()
        member_type = random.choice(basic_types)

        # 25% chance to make it an array
        if random.random() < 0.25:
            array_size = random.randint(2, 64)
            members.append(f"    {member_type} {member_name}[{array_size}];")
        else:
            members.append(f"    {member_type} {member_name};")

    definition = f"{type_keyword} {type_name} {{\n"
    definition += "\n".join(members)
    definition += f"\n}}; // End of {type_keyword} {type_name}\n"

    return type_name, definition

def find_functions_and_calls(code):
    """
    A simple heuristic-based parser to find function definitions and calls.
    This is not a full C++ parser and is tailored to the style of psl.cpp.
    """
    known_functions = {
        "PadRight": ["std::wstring (const std::wstring&, size_t, wchar_t)"]
    }

    # Find calls to these functions
    call_sites = {}
    for func_name in known_functions:
        call_sites[func_name] = []
        pattern = re.compile(r'\b' + func_name + r'\s*\(')
        for match in pattern.finditer(code):
            call_sites[func_name].append(match.start())

    return known_functions, call_sites

def generate_fp_table(functions, rename_map):
    """Generates a C++ global array of function pointers."""

    table_name = get_random_name()
    table_entries = []
    func_map = {}
    i = 0

    for func_name, sig_list in functions.items():
        if func_name in rename_map:
            obfuscated_name = rename_map[func_name]
            for sig in sig_list:
                parts = sig.split('(', 1)
                return_type = parts[0].strip()
                args = parts[1][:-1]

                cast = f"({return_type} (*)({args}))"

                table_entries.append(f"    (void*)({cast}&{obfuscated_name})")

                if func_name not in func_map:
                    func_map[func_name] = {
                        "id": i,
                        "cast": cast,
                        "table": table_name,
                        "return_type": return_type
                    }
                i += 1

    if not table_entries:
        return "", {}

    table_code = f"\nvoid* {table_name}[] = {{\n"
    table_code += ",\n".join(table_entries)
    table_code += "\n};"

    return table_code, func_map

def replace_function_calls(code, func_map, rename_map):
    """Replaces direct function calls with indirect calls through a pointer table."""
    if not func_map:
        return code

    obf_func_map = {}
    for func_name, func_info in func_map.items():
        if func_name in rename_map:
            obf_name = rename_map[func_name]
            obf_func_map[obf_name] = func_info

    lines = code.split('\n')
    processed_lines = []
    for line in lines:
        is_definition = False
        for obf_name, func_info in obf_func_map.items():
            if re.search(r'\b' + re.escape(func_info['return_type']) + r'\s+' + re.escape(obf_name) + r'\s*\(', line):
                is_definition = True
                break

        if is_definition:
            processed_lines.append(line)
            continue

        temp_line = line
        for obf_name, func_info in obf_func_map.items():
            replacement = f"(({func_info['cast']}){func_info['table']}[{func_info['id']}])"
            temp_line = temp_line.replace(obf_name, replacement)

        processed_lines.append(temp_line)

    return '\n'.join(processed_lines)

def collect_identifiers(code):
    """Collects all valid identifiers from the code, avoiding protected contexts."""
    identifiers = set()

    for line in code.split('\n'):
        if line.strip().startswith('#') or 'extern "C"' in line:
            continue

        temp_line = RE_COMMENT.sub('', line)
        temp_line = RE_STRING.sub('""', temp_line)

        for match in RE_IDENTIFIER.finditer(temp_line):
            identifier = match.group(0)
            if identifier not in KEYWORDS and not identifier.isupper():
                identifiers.add(identifier)

    return identifiers

def build_rename_map(identifiers):
    """Builds a map from original identifier to a new random name."""
    return {identifier: get_random_name() for identifier in identifiers}

def replace_identifiers(code, rename_map):
    """Replaces identifiers in the code, respecting context."""
    if not rename_map:
        return code

    sorted_keys = sorted(rename_map.keys(), key=len, reverse=True)
    pattern = r'\b(' + '|'.join(re.escape(key) for key in sorted_keys) + r')\b'

    processed_lines = []
    for line in code.split('\n'):
        if line.strip().startswith('#') or 'extern "C"' in line:
            processed_lines.append(line)
            continue

        literals = {}
        def store_literal(match_obj):
            key = f"__LITERAL_{len(literals)}__"
            literals[key] = match_obj.group(0)
            return key

        temp_line = RE_COMMENT.sub(store_literal, line)
        temp_line = RE_STRING.sub(store_literal, temp_line)

        temp_line = re.sub(pattern, lambda m: rename_map.get(m.group(0), m.group(0)), temp_line)

        for key, value in literals.items():
            temp_line = temp_line.replace(key, value, 1)

        processed_lines.append(temp_line)

    return '\n'.join(processed_lines)

def obfuscate_strings(code, key_byte=0x55, wchar_key=0x5555, helper_names=None):
    """Finds all C-style strings, XORs them, and prepares for runtime decoding."""
    obfuscated_strings = []
    obfuscated_wstrings = []

    def repl(match):
        is_wide = match.group(1)
        original_str = match.group(3)
        raw_str = match.group(4)

        if raw_str is not None:
            return match.group(0)
        if original_str is None:
            return match.group(0)

        decoded_str = bytes(original_str, 'utf-8').decode('unicode_escape')

        if is_wide:
            xored_wchars = [ord(c) ^ wchar_key for c in decoded_str]
            array_id = len(obfuscated_wstrings)
            obfuscated_wstrings.append(xored_wchars)
            return f"{helper_names['_obf_wstr']}({array_id})"
        else:
            xored_bytes = [ord(b) ^ key_byte for b in decoded_str]
            array_id = len(obfuscated_strings)
            obfuscated_strings.append(xored_bytes)
            return f"{helper_names['_obf_str']}({array_id})"

    lines = code.split('\n')
    processed_lines = []
    RE_CHAR_ARRAY_INIT = re.compile(r'\bchar\s+[a-zA-Z_][a-zA-Z0-9_]*\s*\[\s*\]\s*=\s*')
    in_char_array_init = False
    for line in lines:
        if line.strip().startswith('#') or 'extern "C"' in line:
            processed_lines.append(line)
            continue
        if not in_char_array_init and RE_CHAR_ARRAY_INIT.search(line):
            in_char_array_init = True
        if in_char_array_init:
            processed_lines.append(line)
            if line.strip().endswith(';'):
                in_char_array_init = False
        else:
            processed_lines.append(RE_STRING.sub(repl, line))
    code = '\n'.join(processed_lines)
    return code, obfuscated_strings, obfuscated_wstrings

def insert_string_runtime_helpers(code, obfuscated_strings, obfuscated_wstrings, key_byte=0x55, wchar_key=0x5555, helper_names=None, fp_table_code=""):
    """Inserts the C++ helper code for decoding strings at runtime."""
    if not obfuscated_strings and not obfuscated_wstrings:
        return code

    junk_pool = []
    for _ in range(4):
        type_name, type_def = generate_junk_struct_or_union()
        var_name = get_random_name()
        junk_pool.append(f"{type_def}\n{type_name} {var_name};")

    helper_code = "\n// --- String Obfuscation Helper --- \n"
    helper_code += "namespace {\n"
    helper_code += fp_table_code + "\n"

    if obfuscated_strings:
        for i, data in enumerate(obfuscated_strings):
            helper_code += f"    char {helper_names['_obf_data_']}{i}[] = {{ {', '.join(f'(char){d}' for d in data)}, 0 }};\n"
            if i % 2 == 0 and junk_pool:
                helper_code += junk_pool.pop(0) + "\n"
        helper_code += f"\n    char* {helper_names['_obf_str_table']}[] = {{\n"
        for i in range(len(obfuscated_strings)):
            helper_code += f"        {helper_names['_obf_data_']}{i},\n"
        helper_code += "    };\n\n"
        helper_code += f"    char {helper_names['_obf_decode_buffer']}[4096];\n"
        helper_code += f"    const char* {helper_names['_obf_str']}(int id) {{\n"
        helper_code += f"        char* s = {helper_names['_obf_str_table']}[id];\n"
        helper_code += f"        int i = 0;\n"
        helper_code += f"        for (; s[i] != 0; ++i) {helper_names['_obf_decode_buffer']}[i] = s[i] ^ {key_byte};\n"
        helper_code += f"        {helper_names['_obf_decode_buffer']}[i] = 0;\n"
        helper_code += f"        return {helper_names['_obf_decode_buffer']};\n"
        helper_code += "    }\n"

    if obfuscated_wstrings:
        for i, data in enumerate(obfuscated_wstrings):
            helper_code += f"    wchar_t {helper_names['_obf_wdata_']}{i}[] = {{ {', '.join(map(str, data))}, 0 }};\n"
            if i % 2 != 0 and junk_pool:
                helper_code += junk_pool.pop(0) + "\n"
        helper_code += f"\n    wchar_t* {helper_names['_obf_wstr_table']}[] = {{\n"
        for i in range(len(obfuscated_wstrings)):
            helper_code += f"        {helper_names['_obf_wdata_']}{i},\n"
        helper_code += "    };\n\n"
        helper_code += f"    wchar_t {helper_names['_obf_wdecode_buffer']}[4096];\n"
        helper_code += f"    const wchar_t* {helper_names['_obf_wstr']}(int id) {{\n"
        helper_code += f"        wchar_t* s = {helper_names['_obf_wstr_table']}[id];\n"
        helper_code += f"        int i = 0;\n"
        helper_code += f"        for (; s[i] != 0; ++i) {helper_names['_obf_wdecode_buffer']}[i] = s[i] ^ {wchar_key};\n"
        helper_code += f"        {helper_names['_obf_wdecode_buffer']}[i] = 0;\n"
        helper_code += f"        return {helper_names['_obf_wdecode_buffer']};\n"
        helper_code += "    }\n"

    helper_code += "\n".join(junk_pool)
    helper_code += "\n} // anonymous namespace\n"
    helper_code += "// --- End String Obfuscation Helper --- \n\n"

    last_include_pos = code.rfind("#include")
    if last_include_pos != -1:
        insert_pos = code.find('\n', last_include_pos) + 1
        return code[:insert_pos] + helper_code + code[insert_pos:]
    return helper_code + code

def obfuscate_numbers(code):
    """Replaces integer literals with arithmetic expressions using a safe regex."""
    def repl(match):
        num_str = match.group(0)
        num = int(num_str)
        if num <= 10:
            return num_str
        addend = random.randint(2, num - 2)
        return f"({addend} + {num - addend})"

    processed_lines = []
    for line in code.split('\n'):
        if line.strip().startswith('#'):
            processed_lines.append(line)
            continue

        literals = {}
        def store_literal(match_obj):
            key = f"__LITERAL_{len(literals)}__"
            literals[key] = match_obj.group(0)
            return key

        temp_line = RE_COMMENT.sub(store_literal, line)
        temp_line = RE_STRING.sub(store_literal, temp_line)
        safe_integer_regex = r"(?<![a-zA-Z0-9_.$])\d+(?![a-zA-Z0-9_.])"
        temp_line = re.sub(safe_integer_regex, repl, temp_line)
        for key, value in literals.items():
            temp_line = temp_line.replace(key, value, 1)
        processed_lines.append(temp_line)
    return '\n'.join(processed_lines)

def run_obfuscation(input_path: str, output_path: str):
    """
    Reads C++ code from input_path, obfuscates it, and writes to output_path.
    """
    try:
        with open(input_path, 'r', encoding='utf-8') as f:
            code = f.read()
    except FileNotFoundError:
        print(f"Error: Input file not found at {input_path}")
        raise

    key_byte = random.randint(1, 255)
    wchar_key = random.randint(1, 65535)

    helper_names = {
        "_obf_str": get_random_name(),
        "_obf_wstr": get_random_name(),
        "_obf_data_": get_random_name() + "_",
        "_obf_wdata_": get_random_name() + "_",
        "_obf_str_table": get_random_name(),
        "_obf_wstr_table": get_random_name(),
        "_obf_decode_buffer": get_random_name(),
        "_obf_wdecode_buffer": get_random_name(),
    }

    known_funcs, call_sites = find_functions_and_calls(code)
    identifiers_to_rename = collect_identifiers(code)
    for func in known_funcs:
        if func in identifiers_to_rename:
            identifiers_to_rename.remove(func)

    rename_map = build_rename_map(identifiers_to_rename)
    fp_table_code, fp_map = generate_fp_table(known_funcs, rename_map)
    code = replace_function_calls(code, fp_map, rename_map)
    code = replace_identifiers(code, rename_map)
    code, strings, wstrings = obfuscate_strings(code, key_byte=key_byte, wchar_key=wchar_key, helper_names=helper_names)
    code = insert_string_runtime_helpers(code, strings, wstrings, key_byte=key_byte, wchar_key=wchar_key, helper_names=helper_names, fp_table_code=fp_table_code)
    code = obfuscate_numbers(code)
    final_code = minify(code)

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(final_code)

def main():
    parser = argparse.ArgumentParser(description="A simple C++ obfuscator.")
    parser.add_argument("-i", "--input", required=True, help="Input C++ file path.")
    parser.add_argument("-o", "--output", required=True, help="Output file path for obfuscated code.")
    args = parser.parse_args()

    try:
        run_obfuscation(args.input, args.output)
        print(f"Obfuscation complete. Output written to {args.output}")
    except FileNotFoundError:
        print(f"Error: Input file not found at {args.input}")

if __name__ == "__main__":
    main()
