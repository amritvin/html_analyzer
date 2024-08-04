import re
import jsbeautifier
import execjs
import base64
import binascii
import sys
import logging

# Set up logging
logging.basicConfig(level=logging.DEBUG, format='%(message)s')
logger = logging.getLogger()

# Function to set logging level based on verbosity
def set_logging_level(verbose):
    if verbose:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.WARNING)

# Define your obfuscation patterns (example patterns, adjust as needed)
obfuscation_patterns = [
    re.compile(r'eval\((.*)\)'),
    re.compile(r'unescape\((.*)\)'),
    re.compile(r'document\.write\((.*)\)'),
    re.compile(r'setTimeout\((.*)\)'),
    re.compile(r'setInterval\((.*)\)'),
    re.compile(r'Function\((.*)\)'),
    re.compile(r'atob\((.*)\)'),
    re.compile(r'btoa\((.*)\)'),
    re.compile(r'charCodeAt\((.*)\)'),
    re.compile(r'fromCharCode\((.*)\)'),
]

# Function to decode Base64 using Python's base64 library with padding fix
def decode_base64(encoded_str):
    # Fix padding
    padding_needed = len(encoded_str) % 4
    if padding_needed:
        encoded_str += '=' * (4 - padding_needed)
    try:
        decoded_bytes = base64.b64decode(encoded_str, validate=True)
        return decoded_bytes.decode('utf-8')
    except (binascii.Error, ValueError) as e:
        logger.warning(f"Base64 decoding error: {e}")
        return None

# Function to unescape percent-encoded strings
def decode_unescape(encoded_str):
    try:
        decoded_str = bytes(encoded_str, 'ascii').decode('unicode_escape')
        return decoded_str
    except Exception as e:
        logger.warning(f"Unescape decoding error: {e}")
        return None

# Function to decode fromCharCode strings
def decode_fromCharCode(encoded_str):
    try:
        # Extract numbers from the fromCharCode call
        char_codes = re.findall(r'fromCharCode\((.*?)\)', encoded_str)
        decoded_str = ''.join(chr(int(code)) for code in ','.join(char_codes).split(',') if code.isdigit())
        return decoded_str
    except ValueError as e:
        logger.warning(f"fromCharCode decoding error: {e}")
        return None

# Function to filter out or modify browser-specific code
def filter_browser_specific_code(js_code):
    # Remove or modify document.write() or other browser-specific functions
    js_code = re.sub(r'document\.write\([^\)]*\);?', '', js_code)
    return js_code

# Function to recursively deobfuscate content
def recursive_deobfuscate(content):
    changes_made = True
    while changes_made:
        changes_made = False
        for pattern in obfuscation_patterns:
            matches = pattern.findall(content)
            for match in matches:
                eval_content = match
                logger.debug(f"Extracted content:\n{eval_content}")  # Debug statement

                # Handle different patterns
                if 'atob' in eval_content:
                    atob_match = re.search(r'atob\("(.+?)"\)', eval_content)
                    if atob_match:
                        base64_encoded_str = atob_match.group(1)
                        decoded_content = decode_base64(base64_encoded_str)
                        if decoded_content:
                            beautified_content = jsbeautifier.beautify(decoded_content)
                            logger.debug(f"Beautified content:\n{beautified_content}")
                            content = content.replace(match, beautified_content)
                            changes_made = True
                elif 'unescape' in eval_content:
                    unescape_match = re.search(r'unescape\((\'|\")(.+?)\1\)', eval_content)
                    if unescape_match:
                        encoded_str = unescape_match.group(2)
                        decoded_content = decode_unescape(encoded_str)
                        if decoded_content:
                            beautified_content = jsbeautifier.beautify(decoded_content)
                            logger.debug(f"Beautified content:\n{beautified_content}")
                            content = content.replace(match, beautified_content)
                            changes_made = True
                elif 'fromCharCode' in eval_content:
                    decoded_content = decode_fromCharCode(eval_content)
                    if decoded_content:
                        beautified_content = jsbeautifier.beautify(decoded_content)
                        logger.debug(f"Beautified content:\n{beautified_content}")
                        content = content.replace(match, beautified_content)
                        changes_made = True
                else:
                    obfuscated_code = f"""
                    function deobfuse() {{
                        return {eval_content};
                    }}
                    """
                    logger.debug(f"JavaScript Code to Execute:\n{obfuscated_code}")

                    try:
                        ctx = execjs.compile(obfuscated_code)
                        result = ctx.call('deobfuse')
                        beautified_content = jsbeautifier.beautify(result)
                        logger.debug(f"Beautified content:\n{beautified_content}")
                        content = content.replace(match, beautified_content)
                        changes_made = True
                    except execjs.ProgramError as e:
                        logger.warning(f"Error in executing JavaScript code: {e}")

    return content

def extract_and_execute(script_content):
    return recursive_deobfuscate(script_content)

def main():
    # Read the HTML content from command line argument
    if len(sys.argv) < 2:
        print("Usage: python Deob.py <path_to_html_file> [--verbose]")
        sys.exit(1)

    input_file = sys.argv[1]
    verbose = '--verbose' in sys.argv

    # Set logging level based on verbosity
    set_logging_level(verbose)

    try:
        with open(input_file, 'r') as file:
            script_content = file.read()
    except Exception as e:
        logger.warning(f"Error reading file {input_file}: {e}")
        sys.exit(1)

    # Run the function
    deobfuscated_content = extract_and_execute(script_content)
    logger.debug(f"\nDeobfuscated content:\n{deobfuscated_content}")

    # Save deobfuscated content to a text file
    output_file = 'deobfuscated_content.txt'
    try:
        with open(output_file, 'w') as file:
            file.write(deobfuscated_content)
        logger.debug(f"Deobfuscated content saved to {output_file}")
    except Exception as e:
        logger.warning(f"Error writing to file {output_file}: {e}")

if __name__ == "__main__":
    main()
