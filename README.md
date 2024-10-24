# AutoCryptExtension

**AutoCryptExtension** is a Burp Suite extension that allows users to encrypt and decrypt HTTP request bodies or specific parameter values using external scripts (Python & Java). Once the user selects the script, the extension will simply encrypt and decrypt data with right click.

The main goal of this Burp Suite extension is to simplify the process of handling encrypted data during penetration testing. Typically, when dealing with encryption in applications, pentesters have to write separate Python or Java scripts to decrypt data, then manually copy and paste the results between their terminal and Burp Suite, which is both time-consuming and tedious. This extension eliminates that hassle by allowing users to directly integrate their scripts within Burp Suite, enabling encryption and decryption of data with a simple right-click.

## Features
- Select specific parameter values or the entire POST body for encryption and decryption.
- Supports running external Python, Java scripts.
- Saves user selected scripts for future encryption/decryption tasks.

## Installation

1. Download the Python script `AutoCrypt.py`.
2. Open Burp Suite and go to `Extender` > `Extensions`.
3. Click on `Add` and select `Python` as the extension type.
4. Upload the `AutoCrypt.py` file.
5. You're good to go!

## Usage

1. In the **Repeater** tab, right-click the request.
2. Choose the script you want to use for encryption/decryption (first time only).
3. Select the specific value or if entire body is encrypted then directly select `Encrypt` or `Decrypt`.
4. The selected portion (or entire POST body) will be replaced with the output.

## Demo
![AutoCrypt Burp Extension Demo](https://github.com/vaishalinagori/AutoCrypt-Burp-Extension/blob/main/DEMO.gif)


## Help

Feel free to contact on vaishalijain0235@gmail.com / https://www.linkedin.com/in/vaishali-nagori/
