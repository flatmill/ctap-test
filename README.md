# ctap-test

This is a sample program for authenticatorCredentialManagement in CTAP 2.1.

## Description

- FIDO2 security key information can be output.
- Passkeys stored in FIDO2 security keys supporting CTAP 2.1 (including PRE) can be selected and deleted.

## Requirement

- These programs use the [Yubico/python-fido2](https://github.com/Yubico/python-fido2) library.
- For the interactive UI, these programs use the [Questionary](https://questionary.readthedocs.io/en/stable/) library.

## Installation

```bash
git clone https://github.com/flatmill/ctap-test
cd ctap-test
pip install fido2 questionary
```

## Usage

For Windows, these programs must be **run as an administrator**.

You will be prompted for a PIN or biometric authentication during program execution.
Note that failure of authentication may result in the security key being locked.

### Output FIDO2 security key information

```sh
python keyinfo.py
```

### Delete the passkey stored in the FIDO2 security key

```sh
python credmgr.py
```

## Author

flatmill

## License

[The Unlicense](UNLICENSE)
