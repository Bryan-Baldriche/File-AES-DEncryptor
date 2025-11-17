# AES-256 File & Directory Encryption Tool  
*A simple, zero-knowledge AES encryption program for files and folders.*

## What This Program Is  
This project is a lightweight Python tool that allows users to **encrypt and decrypt files** using **AES-256-GCM**, a modern, authenticated encryption algorithm.  
It requires **no database**, stores **no keys**, and is designed for use in **zero-knowledge environments** where even the developers have no access to decrypted user data.

The tool supports:

- **Individual file encryption**
- **Directory encryption**, via automatic ZIP archiving
- **Password-based AES-256-GCM encryption**
- **Fully local operation** with no network or external dependencies

All information required for decryption is embedded **within the encrypted file itself** (salt + nonce), never stored externally.

---

## Project Intent  
The goal of this project is to provide a secure, simple, and portable method for users to protect sensitive data without:

- Managing key files  
- Running servers  
- Using accounts, metadata, or databases  
- Exposing any **internal file metadata** such as video titles, EXIF data, creators, timestamps, codecs, or other embedded information

All internal metadata **inside the file’s contents** is fully encrypted.  
The only unencrypted metadata stored in the output file is cryptographic (salt + nonce), and it reveals **nothing** about the original data.

This project is intended for privacy-first, zero-knowledge workflows where only the user holds the power to decrypt.

---

## How It Works  

### **Encryption Process**
When you encrypt a file:

1. You provide a password.  
2. The program generates a random **salt** and **nonce**.  
3. Your password is transformed into a secure 256-bit AES key using PBKDF2-HMAC-SHA256.  
4. The file is encrypted using **AES-256-GCM**, protecting both its contents and authenticity.  
5. The final encrypted file is structured as:
6. 
[salt | nonce | encrypted data]

These cryptographic pieces are safe to store because they do not reveal anything about the original file.

### **Decryption Process**
When decrypting:

1. You provide the same password used during encryption.  
2. The stored salt + nonce regenerate the same AES key.  
3. If the password is correct, the file decrypts successfully.  
4. If the password is wrong, the file remains unreadable and fails authentication.

### **Directory Encryption**
If you provide a **folder**, the program will:

1. Automatically create a ZIP archive from the directory (including all subfolders) without compression to ensure file integrity.
2. Encrypt the resulting ZIP using AES-256-GCM  

When decrypting a directory, you will receive a ZIP file that you may extract normally.

---

## Zero-Knowledge Guarantee  
This tool is designed from the ground up for **zero-knowledge privacy**:

- No keys are stored  
- No passwords are stored  
- No user data or metadata is logged  
- No database or server infrastructure is used  
- Developers and administrators **cannot** decrypt your files  
- If you lose your password, the data is cryptographically unrecoverable  

Your encrypted data remains fully private and accessible **only to you**.

---

## What Gets Encrypted?

### ✔ All file contents  
### ✔ All embedded metadata (EXIF, codecs, authors, timestamps, tags, etc.)  
### ✔ Full directory structures when zipped  
### ✔ File headers and binary structure  
### ✔ Everything inside the original file  

The output file's name is also scrambled whilst in storage, with the original filename being stored as internal metadata which got encrypted alongside the file.
This means once unencrypted the files original name is restored, but that while sitting stored, all files present as a random scramble, example: "Bwi278usUAwuh97.enc"

---

## 📚 License  
This project is released under the **MIT License**, granting full permission to use, modify, redistribute, or integrate the tool into personal, academic, or commercial systems.
