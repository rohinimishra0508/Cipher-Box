import gzip
import os
import shutil
from cryptography.fernet import Fernet

# Compress a file before encryption
def compress_file(file_path):
    compressed_file_path = file_path + ".gz"
    with open(file_path, 'rb') as f_in:
        with gzip.open(compressed_file_path, 'wb') as f_out:
            shutil.copyfileobj(f_in, f_out)
    return compressed_file_path

# Encrypt the compressed file and delete the compressed file afterward
def encrypt_compressed_file(file_path, key):
    compressed_file_path = compress_file(file_path)
    with open(compressed_file_path, 'rb') as f:
        data = f.read()
    encrypted_data = Fernet(key).encrypt(data)
    encrypted_file_path = compressed_file_path + ".encrypted"
    with open(encrypted_file_path, 'wb') as f:
        f.write(encrypted_data)
    
    # Delete the compressed file after encryption
    os.remove(compressed_file_path)
    
    return encrypted_file_path

# Decrypt the encrypted compressed file, decompress it, and save the decrypted file
# def decrypt_compressed_file(file_path, key):
#     with open(file_path, 'rb') as f:
#         encrypted_data = f.read()
    
#     decrypted_data = Fernet(key).decrypt(encrypted_data)
    
#     decompressed_temp_path = file_path.replace(".gz.encrypted", ".temp")

#     with open(decompressed_temp_path, 'wb') as temp_file:
#         temp_file.write(decrypted_data)
    
#     final_decrypted_path = file_path.replace(".gz.encrypted", "")
#     with gzip.open(decompressed_temp_path, 'rb') as f_in:
#         with open(final_decrypted_path, 'wb') as f_out:
#             shutil.copyfileobj(f_in, f_out)
#     file_name, file_extension = os.path.splitext(final_decrypted_path)
#     decrypted_file_path = f"{file_name}_FD{file_extension}"

#     os.rename(final_decrypted_path, decrypted_file_path)

#     os.remove(decompressed_temp_path)
    
#     return decrypted_file_path


def decrypt_compressed_file(file_path, key):
    # Read the encrypted data
    with open(file_path, 'rb') as f:
        encrypted_data = f.read()
    
    # Decrypt the data to get the compressed data
    decrypted_data = Fernet(key).decrypt(encrypted_data)
    
    # Create a temporary file to hold the decrypted (compressed) data
    decompressed_temp_path = file_path.replace(".encrypted", ".temp.gz")

    # Write the decrypted data to the temporary file
    with open(decompressed_temp_path, 'wb') as temp_file:
        temp_file.write(decrypted_data)
    
    # Decompress the temporary file
    final_decrypted_path = decompressed_temp_path.replace(".temp.gz", "")
    with gzip.open(decompressed_temp_path, 'rb') as f_in:
        with open(final_decrypted_path, 'wb') as f_out:
            shutil.copyfileobj(f_in, f_out)

    # Rename the final decrypted file to include the _FD suffix
    decrypted_file_path = final_decrypted_path.replace(".gz", "") 
    file_name, file_extension = os.path.splitext(decrypted_file_path)
    decrypted_file_path = f"{file_name}_FD{file_extension}"
    os.rename(final_decrypted_path, decrypted_file_path)
    
    # Remove the temporary file
    os.remove(decompressed_temp_path)
    
    return decrypted_file_path