# Credential Manager for CTAP2.1
#
#     pip install fido2 questionary
#     python credmgr.py
#
import sys
from dataclasses import dataclass
from questionary import questionary, Choice, Separator
from fido2.hid import CtapHidDevice, CAPABILITY
from fido2.ctap2 import Ctap2, Info, CredentialManagement, ClientPin
from fido2.webauthn import PublicKeyCredentialDescriptor

@dataclass
class AuthentocatorInfo:
    name: str
    is_credmgmt_suppoted: bool
    uv_enabled: bool
    pin_enabled: bool
    dev: CtapHidDevice
    ctap2: Ctap2
    info: Info

@dataclass
class CredentialsInfo:
    cred_id: PublicKeyCredentialDescriptor
    rp_id: str
    user_name: str

def get_authenticator_info(dev) -> AuthentocatorInfo:
    name = dev.product_name
    is_credmgmt_suppoted = False
    if dev.capabilities & CAPABILITY.CBOR:
        ctap2 = Ctap2(dev)
        info = ctap2.get_info()
        uv_enabled = is_enabled_uv(info)
        pin_enabled = is_enabled_pin(info)
        if CredentialManagement.is_supported(info) and (uv_enabled or pin_enabled):
            is_credmgmt_suppoted = True
    if not is_credmgmt_suppoted:
        dev = None
        ctap2 = None
        info = None
    return AuthentocatorInfo(name, is_credmgmt_suppoted, uv_enabled, pin_enabled, dev, ctap2, info)

def get_authenticator_choice(a):
    if a.is_credmgmt_suppoted:
        return Choice(title=a.name, value=a)
    return Choice(title=a.name, disabled="Not supported")

def is_enabled_uv(info):
    if "uv" in info.options:
        if info.options["uv"]:
            return ClientPin.is_token_supported(info)
    return False

def is_enabled_pin(info):
    if "clientPin" in info.options:
        if info.options["clientPin"]:
            return True
    return False

def get_all_credentials_info(cred_mgmt):
    credentials = []
    rp_entries = cred_mgmt.enumerate_rps()
    for rp_entry in rp_entries:
        rp_id = rp_entry[CredentialManagement.RESULT.RP].get("id")
        rpid_hash = rp_entry[CredentialManagement.RESULT.RP_ID_HASH]
        cred_entries = cred_mgmt.enumerate_creds(rpid_hash)
        for cred_entry in cred_entries:
            user_name = cred_entry[CredentialManagement.RESULT.USER].get("displayName")
            credential_id = cred_entry[CredentialManagement.RESULT.CREDENTIAL_ID]
            credentials.append(CredentialsInfo(credential_id, rp_id, user_name))
    return credentials

def get_credential_choice(c):
    title = c.rp_id + " - " + c.user_name
    return Choice(title=title, value=c)

# Get authenticator list
print("Get Authenticators...")
authenticators = list(map(get_authenticator_info, CtapHidDevice.list_devices()))
if len(authenticators) == 0:
    print("No Authenticators. Exited.")
    sys.exit(0)
selected_authenticators = questionary.select(
    'Select Authenticators',
    choices = [
        Choice(title="Exit", value=False),
        Separator("----")
    ] + sorted(list(map(get_authenticator_choice, authenticators)), key=lambda c: c.title)
).ask()
if not selected_authenticators:
    sys.exit(0)

# User verification or PIN
client_pin = ClientPin(selected_authenticators.ctap2)
pin_token = None
if is_enabled_uv(selected_authenticators.info):
    questionary.print("Touch your authenticator device now...", style="bold")
    pin_token = client_pin.get_uv_token(ClientPin.PERMISSION.CREDENTIAL_MGMT)
elif is_enabled_pin(selected_authenticators.info):
    pin = questionary.password("Enter PIN: ").ask()
    pin_token = client_pin.get_pin_token(pin, ClientPin.PERMISSION.CREDENTIAL_MGMT)

# Get credentials
cred_mgmt = CredentialManagement(selected_authenticators.ctap2, client_pin.protocol, pin_token)
creds_metadata = cred_mgmt.get_metadata()
num_credentials_used = creds_metadata.get(CredentialManagement.RESULT.EXISTING_CRED_COUNT)
num_credentials_free = creds_metadata.get(CredentialManagement.RESULT.MAX_REMAINING_COUNT)
print(f"Credentials {num_credentials_used} used, {num_credentials_free} free")
credentials = get_all_credentials_info(cred_mgmt)
if len(credentials) == 0:
    print("No credentials. Exited.")
    sys.exit(0)

# Select credentials
credential_choices = sorted(list(map(get_credential_choice, credentials)), key=lambda c: c.title)
selected_credentials = questionary.select(
    'Select credential to delete:',
    choices = [
        Choice(title="Exit", value=False),
        Separator("----")
    ] + credential_choices
).ask()
if not selected_credentials:
    sys.exit(0)

# Delete credential
if questionary.confirm("Are you sure?", default=False).ask():
    cred_mgmt.delete_cred(selected_credentials.cred_id)
    print("Done.")
else:
    print("Canceled.")
