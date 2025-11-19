import argparse
import getpass

# from Encrypt import encrypt_file
# from Decrypt import decrypt_file

def show_initial_warning():
    print("""
⚠️  IMPORTANT SECURITY WARNING  ⚠️
----------------------------------
If you forget your password, your encrypted data CANNOT be recovered.
There are no master keys, no backdoors, and no recovery methods.
Keep your password safe.

Use '--help' to view all commands and options.
""")

show_initial_warning()

### ### ###

