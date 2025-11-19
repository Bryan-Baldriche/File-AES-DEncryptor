import argparse
import getpass

from Encrypt import encrypt_file
from Decrypt import decrypt_file

def show_initial_warning():
    print("""
⚠️  IMPORTANT SECURITY WARNING  ⚠️
----------------------------------
If you forget your password, your encrypted data CANNOT be recovered.
There are no master keys, no backdoors, and no recovery methods.
Keep your password safe.

Use '--help' to view all commands and options.
""")

### ### ###

def command_parser():
    parser = argparse.ArgumentParser(
        description="AES-256 File Encryption and Decryption Tool"
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # Encrypt Parse
    enc = subparsers.add_parser("encrypt", help="Encrypt a File or Directory/Folder")
    enc.add_argument("input",help="Path to File or Directory to Encrypt")
    enc.add_argument("output",help="Output file (or directory to output to is using the --scramble-name flag)")
    enc.add_argument("--base64",action="store_true",help="Encode the output using Base64 (this will take up more space")
    enc.add_argument("--scramble-name",action="store_true",help="Scrambles the original filename to a random nonsense")

    # Decrypt Parse

    dec = subparsers.add_parser("decrypt", help="Decrypt a File or Directory/Folder")
    dec.add_argument("input",help="Path to File or Directory to Decrypt")
    dec.add_argument("output",help="Output file path or directory")
    dec.add_argument("--base64",action="store_true",help="Use if the input file or directory is Base64 encoded")
    dec.add_argument("--restore_name",action="store_true",help="Restore the original file name if it was scrambled using the --scramble-name flag.")

    return parser

def get_password(confirm: bool = False) -> str:
    """
    Prompt user for password, confirm twice, require match.
    :return:
    """
    while True:
        password = getpass.getpass("Password: ")

        if not confirm:
            return password

        confirm_pw = getpass.getpass("Confirm Password: ")
        if password == confirm_pw:
            return password

        print("Passwords do not match. Please try again.\n")

def main():

    show_initial_warning()

    parser = command_parser()
    args = parser.parse_args()

    try:
        if args.command == "encrypt":
            password= get_password(confirm=True)

            encrypt_file(
                input_path=args.input,
                output_path=args.output,
                password=password,
                base64_output=args.base64,
                scramble_name=args.scramble_name,
            )
            print(f"[+] Encryption Complete.\n -> {args.output}")

        elif args.command == "decrypt":
            password= get_password(confirm=False)

            decrypt_file(
                input_path=args.input,
                output_path=args.output,
                password=password,
                base64_output=args.base64,
                restore_name=args.restore_name,
            )
            print(f"[+] Decryption Complete.\n -> {args.output}")

    except Exception as e:
        print(f"[!] Error: {e}")


if __name__ == "__main__":
    main()
