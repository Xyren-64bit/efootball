import os
import subprocess
from Crypto.Cipher import AES

def decrypt_file(input_file, output_file, key):
    """
    Decrypt a file encrypted with AES.

    Args:
        input_file (str): Path to the encrypted input file.
        output_file (str): Path to save the decrypted output file.
        key (bytes): The 256-bit AES key (32 bytes).
    """
    if len(key) != 32:
        raise ValueError("AES key must be 32 bytes (256 bits).")

    try:
        with open(input_file, "rb") as f_in:
            encrypted_data = f_in.read()

        # Assume the first 16 bytes are the IV
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]

        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = cipher.decrypt(ciphertext)

        # Remove padding (PKCS7)
        pad_len = decrypted_data[-1]
        decrypted_data = decrypted_data[:-pad_len]

        # Write decrypted data to the output file
        with open(output_file, "wb") as f_out:
            f_out.write(decrypted_data)

        print(f"Decrypted: {input_file} -> {output_file}")
    except Exception as e:
        print(f"Error decrypting file {input_file}: {e}")

def extract_file_with_unrealpak(file_path, output_dir):
    """
    Extract a file using UnrealPak.

    Args:
        file_path (str): Path to the decrypted .pak file.
        output_dir (str): Directory to save the extracted files.
    """
    # Replace this path with the path to UnrealPak.exe or equivalent tool
    unrealpak_path = "/path/to/UnrealPak"

    if not os.path.exists(unrealpak_path):
        raise FileNotFoundError("UnrealPak tool not found. Please set the correct path.")

    try:
        command = [unrealpak_path, file_path, "-Extract", output_dir]
        subprocess.run(command, check=True)
        print(f"Extracted: {file_path} -> {output_dir}")
    except subprocess.CalledProcessError as e:
        print(f"Error extracting file {file_path}: {e}")

def process_files(directory, key):
    """
    Decrypt and extract files in the given directory.

    Args:
        directory (str): Path to the directory containing files to process.
        key (bytes): The 256-bit AES key (32 bytes).
    """
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith((".ucas", ".utoc", ".pak")):
                input_file = os.path.join(root, file)
                decrypted_file = os.path.join(root, f"decrypted_{file}")
                output_dir = os.path.join(root, f"extracted_{file}")

                # Step 1: Decrypt the file
                decrypt_file(input_file, decrypted_file, key)

                # Step 2: Extract the decrypted file
                extract_file_with_unrealpak(decrypted_file, output_dir)

if __name__ == "__main__":
    # Get the directory of the script
    script_dir = os.path.dirname(os.path.abspath(__file__))

    # Replace with your AES key (as a hex string)
    aes_key_hex = "4552D45005DFE94964893F4925EC747D3D591401E060ED8B3D58BE5721C81295"
    aes_key = bytes.fromhex(aes_key_hex)

    # Process files
    process_files(script_dir, aes_key)
