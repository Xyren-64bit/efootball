import os
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

def find_and_decrypt_files(directory, key):
    """
    Find and decrypt .ucas, .utoc, and .pak files in the specified directory.

    Args:
        directory (str): Path to the directory.
        key (bytes): The 256-bit AES key (32 bytes).
    """
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith((".ucas", ".utoc", ".pak")):
                input_file = os.path.join(root, file)
                output_file = os.path.join(root, f"decrypted_{file}")
                decrypt_file(input_file, output_file, key)

if __name__ == "__main__":
    # Get the directory of the script
    script_dir = os.path.dirname(os.path.abspath(__file__))

    # Replace with your AES key (as a hex string)
    aes_key_hex = "4552D45005DFE94964893F4925EC747D3D591401E060ED8B3D58BE5721C81295"
    aes_key = bytes.fromhex(aes_key_hex)

    # Find and decrypt files
    find_and_decrypt_files(script_dir, aes_key)
