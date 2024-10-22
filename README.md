# AutoCryptExtension

**AutoCryptExtension** is a Burp Suite extension that allows users to encrypt and decrypt HTTP request bodies or specific parameter values using external scripts (Python, Java, HTML). Once the user selects the script, the extension automates the encryption and decryption process.

## Features
- Select specific parameter values or the entire POST body for encryption and decryption.
- Supports running external Python, Java, and HTML scripts.
- Saves user selection for future encryption/decryption tasks.

## Installation

1. Download the Python script `automation.py`.
2. Open Burp Suite and go to `Extender` > `Extensions`.
3. Click on `Add` and select `Python` as the extension type.
4. Upload the `automation.py` file.
5. You're good to go!

## Usage

1. In the **Repeater** tab, right-click the request.
2. Choose the script you want to use for encryption/decryption (first time only).
3. Select the specific value or if entire body is encrypted then directly select `Encrypt` or `Decrypt`.
4. The selected portion (or entire POST body) will be processed.

