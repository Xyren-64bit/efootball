from Crypto.Cipher import AES
import os

def decrypt_file(input_file, output_file, key):
    """
    Decrypt a file encrypted with AES.

    Args:
        input_file (str): Path to the encrypted input file.
        output_file (str): Path to save the decrypted output file.
        key (bytes): The 256-bit AES key (32 bytes).
    """
    # Ensure the key is 32 bytes long
    if len(key) != 32:
        raise ValueError("AES key must be 32 bytes (256 bits).")

    try:
        with open(input_file, "rb") as f_in:
            encrypted_data = f_in.read()

        # Assume the first 16 bytes are the IV
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]

        # Create AES cipher
        cipher = AES.new(key, AES.MODE_CBC, iv)

        # Decrypt the data
        decrypted_data = cipher.decrypt(ciphertext)

        # Remove padding (PKCS7)
        pad_len = decrypted_data[-1]
        decrypted_data = decrypted_data[:-pad_len]

        # Write the decrypted data to output file
        with open(output_file, "wb") as f_out:
            f_out.write(decrypted_data)

        print(f"File decrypted successfully: {output_file}")
    except Exception as e:
        print(f"Error decrypting file: {e}")

if __name__ == "__main__":
    # Convert the AES key from hex to bytes
    aes_key = bytes.fromhex("4552D45005DFE94964893F4925EC747D3D591401E060ED8B3D58BE5721C81295")

    # Specify the input and output file paths
    input_file_path = "path/to/encrypted_file.ucas"
    output_file_path = "path/to/decrypted_file.ucas"

    # Decrypt the file
    decrypt_file(input_file_path, output_file_path, aes_key)
