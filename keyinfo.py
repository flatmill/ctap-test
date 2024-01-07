from fido2.hid import CtapHidDevice, CAPABILITY
from fido2.ctap2 import Ctap2, CredentialManagement, ClientPin
from getpass import getpass
from questionary import questionary

try:
    from fido2.pcsc import CtapPcscDevice
except ImportError:
    CtapPcscDevice = None

def enumerate_devices():
    for dev in CtapHidDevice.list_devices():
        yield dev
    if CtapPcscDevice:
        for dev in CtapPcscDevice.list_devices():
            yield dev

def obj_to_str(obj):
    if obj is None:
        return "----"
    return str(obj)

def bytes_to_str(b):
    if type(b) is not bytes:
        return obj_to_str(b)
    if len(b) == 0:
        return "<>[0]"
    return "<" + b.hex() + ">[" + str(len(b)) + "]"

def get_cose_kty_displayname(pkey):
    if 1 not in pkey:
        return "--Invalid COSE Key--"
    value = pkey[1]
    # from RFC9053 Table 18,22
    names = {
        0: "Reserved",
        1: "OKP",
        2: "EC2",
        3: "RSA",
        4: "Symmetric",
        5: "HSS-LMS",
        6: "WalnutDSA",
    }
    if value in names:
        return str(value) + " (" + names[value] + ")"
    return str(value)

def get_cose_alg_displayname(pkey):
    if 3 not in pkey:
        return "--No Algorithm--"
    value = pkey[3]
    # from RFC9053 Table 1-7,11-14,16
    names = {
        1: "A128GCM (AES-GCM mode w/ 128-bit key, 128-bit tag)",
        2: "A192GCM (AES-GCM mode w/ 192-bit key, 128-bit tag)",
        3: "A256GCM (AES-GCM mode w/ 256-bit key, 128-bit tag)",
        4: "HMAC 256/64 (HMAC w/ SHA-256 truncated to 64 bits)",
        5: "HMAC 256/256 (HMAC w/ SHA-256)",
        6: "HMAC 384/384 (HMAC w/ SHA-384)",
        7: "HMAC 512/512 (HMAC w/ SHA-512)",
        10: "AES-CCM-16-64-128 (AES-CCM mode 128-bit key, 64-bit tag, 13-byte nonce)",
        11: "AES-CCM-16-64-256 (AES-CCM mode 256-bit key, 64-bit tag, 13-byte nonce)",
        12: "AES-CCM-64-64-128 (AES-CCM mode 128-bit key, 64-bit tag, 7-byte nonce)",
        13: "AES-CCM-64-64-256 (AES-CCM mode 256-bit key, 64-bit tag, 7-byte nonce)",
        14: "AES-MAC 128/64 (AES-MAC 128-bit key, 64-bit tag)",
        15: "AES-MAC 256/64 (AES-MAC 256-bit key, 64-bit tag)",
        24: "ChaCha20/Poly1305 (ChaCha20/Poly1305 w/ 256-bit key, 128-bit tag)",
        25: "AES-MAC 128/128 (AES-MAC 128-bit key, 128-bit tag)",
        26: "AES-MAC 256/128 (AES-MAC 256-bit key, 128-bit tag)",
        30: "AES-CCM-16-128-128 (AES-CCM mode 128-bit key, 128-bit tag, 13-byte nonce)",
        31: "AES-CCM-16-128-256 (AES-CCM mode 256-bit key, 128-bit tag, 13-byte nonce)",
        32: "AES-CCM-64-128-128 (AES-CCM mode 128-bit key, 128-bit tag, 7-byte nonce)",
        33: "AES-CCM-64-128-256 (AES-CCM mode 256-bit key, 128-bit tag, 7-byte nonce)",
        -3: "A128KW (AES Key Wrap w/ 128-bit key)",
        -4: "A192KW (AES Key Wrap w/ 192-bit key)",
        -5: "A256KW (AES Key Wrap w/ 256-bit key)",
        -6: "direct (Direct use of content encryption key (CEK))",
        -7: "ES256 (ECDSA w/ SHA-256)",
        -8: "EdDSA (EdDSA)",
        -10: "direct+HKDF-SHA-256 (Shared secret w/ HKDF and SHA-256)",
        -11: "direct+HKDF-SHA-512 (Shared secret w/ HKDF and SHA-512)",
        -12: "direct+HKDF-AES-128 (Shared secret w/ AES-MAC 128-bit key)",
        -13: "direct+HKDF-AES-256 (Shared secret w/ AES-MAC 256-bit key)",
        -25: "ECDH-ES + HKDF-256 (ECDH ES w/ HKDF -- generate key directly)",
        -26: "ECDH-ES + HKDF-512 (ECDH ES w/ HKDF -- generate key directly)",
        -27: "ECDH-SS + HKDF-256 (ECDH SS w/ HKDF -- generate key directly)",
        -28: "ECDH-SS + HKDF-512 (ECDH SS w/ HKDF -- generate key directly)",
        -29: "ECDH-ES + A128KW (ECDH ES w/ HKDF and AES Key Wrap w/ 128-bit key)",
        -30: "ECDH-ES + A192KW (ECDH ES w/ HKDF and AES Key Wrap w/ 192-bit key)",
        -31: "ECDH-ES + A256KW (ECDH ES w/ HKDF and AES Key Wrap w/ 256-bit key)",
        -29: "ECDH-SS + A128KW (ECDH SS w/ HKDF and AES Key Wrap w/ 128-bit key)",
        -30: "ECDH-SS + A192KW (ECDH SS w/ HKDF and AES Key Wrap w/ 192-bit key)",
        -31: "ECDH-SS + A256KW (ECDH SS w/ HKDF and AES Key Wrap w/ 256-bit key)",
        -35: "ES384 (ECDSA w/ SHA-384)",
        -36: "ES512 (ECDSA w/ SHA-512)",
    }
    if value in names:
        return str(value) + " (" + names[value] + ")"
    return str(value)

def get_cose_key_parameters_for_display(pkey):
    if 1 not in pkey:
        return "--Invalid COSE Key--"
    kty = pkey[1]
    if kty == 2:    # EC2   from RFC9053 Table 19
        labels = { -1: "crv", -2: "x", -3: "y", -4: "d" }
    elif kty == 1:  # OKP   from RFC9053 Table 20
        labels = { -1: "crv", -2 :"x", -4: "d" }
    elif kty == 4:  # Symmetric from RFC9053 Table 21
        labels = { -1: "k" }
    else:
        return "No parameter"
    kobj = {}
    for k in pkey:
        if k in labels:
            kobj[labels[k]] = bytes_to_str(pkey[k])
    return str(kobj)

for dev in enumerate_devices():
    print(f"CONNECT: {dev}")

    # CTAPHID_INIT
    print(f"CTAP HID protocol version: {dev.version}")
    if hasattr(dev, "device_version"):
        print(f"Device version number: {dev.device_version}")
    capabilities_list = []
    if dev.capabilities & CAPABILITY.WINK:
        capabilities_list.append("CAPABILITY_WINK")
    if dev.capabilities & CAPABILITY.CBOR:
        capabilities_list.append("CAPABILITY_CBOR")
    if dev.capabilities & CAPABILITY.NMSG:
        capabilities_list.append("CAPABILITY_NMSG")
    print(f"Capabilities: {dev.capabilities} {capabilities_list}")
    print(f"Product name: {dev.product_name}")
    print(f"Serial number: {dev.serial_number}")

    # CBOR
    #   <https://fidoalliance.org/specs/fido-v2.1-rd-20201208/fido-client-to-authenticator-protocol-v2.1-rd-20201208.html#authenticatorGetInfo>
    if dev.capabilities & CAPABILITY.CBOR:
        ctap2 = Ctap2(dev)
        info = ctap2.get_info()
        print("DEVICE INFO:") 
        print(f"  versions: {info.versions}")
        print(f"  extensions: {info.extensions}")
        print(f"  aaguid: {info.aaguid}")
        print(f"  options: {info.options}")
        print(f"  maxMsgSize: {info.max_msg_size}")
        print(f"  pinUvAuthProtocols: {info.pin_uv_protocols}")
        print(f"  maxCredentialCountInList: {info.max_creds_in_list}")
        print(f"  maxCredentialIdLength: {info.max_cred_id_length}")
        print(f"  transports: {info.transports}")
        print(f"  algorithms: {info.algorithms}")
        print(f"  maxSerializedLargeBlobArray: {info.max_large_blob}")
        print(f"  forcePINChange: {info.force_pin_change}")
        print(f"  minPINLength: {info.min_pin_length}")
        print(f"  firmwareVersion: {info.firmware_version}")
        print(f"  maxCredBlobLength: {info.max_cred_blob_length}")
        print(f"  maxRPIDsForSetMinPINLength: {info.max_rpids_for_min_pin}")
        print(f"  preferredPlatformUvAttempts: {info.preferred_platform_uv_attempts}")
        print(f"  uvModality: {info.uv_modality}")
        print(f"  certifications: {info.certifications}")
        print(f"  remainingDiscoverableCredentials: {info.remaining_disc_creds}")
        print(f"  vendorPrototypeConfigCommands: {info.vendor_prototype_config_commands}")

        enabled_uv = False
        if "uv" in info.options:
            if info.options["uv"]:
                print("Built-in user verification capability: Configured")
                enabled_uv = ClientPin.is_token_supported(info)
            else:
                print("Built-in user verification capability: Not configured")
        else:
            print("Built-in user verification capability: Not implemented")

        enabled_pin = False
        if "clientPin" in info.options:
            if info.options["clientPin"]:
                print("Client PIN: Configured")
                enabled_pin = True
            else:
                print("Client PIN: Not configured")
        else:
            print("Client PIN: Not implemented")

        if CredentialManagement.is_supported(info) and ClientPin.is_supported(info):
            print("Device supports CredentialManagement")
            if enabled_uv or enabled_pin:
                client_pin = ClientPin(ctap2)
                if enabled_uv:
                    print("Touch your authenticator device now...")
                    pin_token = client_pin.get_uv_token(ClientPin.PERMISSION.CREDENTIAL_MGMT)
                elif enabled_pin:
                    pin = questionary.password("Please enter PIN: ").ask()
                    pin_token = client_pin.get_pin_token(pin, ClientPin.PERMISSION.CREDENTIAL_MGMT)
                cred_mgmt = CredentialManagement(ctap2, client_pin.protocol, pin_token)
                creds_metadata = cred_mgmt.get_metadata()
                existingCredCount = creds_metadata.get(CredentialManagement.RESULT.EXISTING_CRED_COUNT)
                maxRemainingCount = creds_metadata.get(CredentialManagement.RESULT.MAX_REMAINING_COUNT)
                print("  existingResidentCredentialsCount: " + obj_to_str(existingCredCount))
                print("  maxPossibleRemainingResidentCredentialsCount: " + obj_to_str(maxRemainingCount))
                print("  RP entries:")
                rp_entries = cred_mgmt.enumerate_rps()
                if len(rp_entries) > 0:
                    for i, entry in enumerate(rp_entries):
                        rp_info = entry[CredentialManagement.RESULT.RP]
                        rpid_hash = entry[CredentialManagement.RESULT.RP_ID_HASH]
                        print(f"    {i}:")
                        print("      RP ID: " + obj_to_str(rp_info.get("id")))
                        print("      RP name: " + obj_to_str(rp_info.get("name")))
                        print("      RP ID SHA-256 hash: " + bytes_to_str(rpid_hash))
                        print("      Credentials:")
                        cred_entries = cred_mgmt.enumerate_creds(rpid_hash)
                        if len(cred_entries) > 0:
                            for ci, cred in enumerate(cred_entries):
                                user_information = cred[CredentialManagement.RESULT.USER]
                                credential_desc = cred[CredentialManagement.RESULT.CREDENTIAL_ID]
                                public_key = cred[CredentialManagement.RESULT.PUBLIC_KEY]
                                cred_protect = cred[CredentialManagement.RESULT.CRED_PROTECT]
                                largeblobkey = cred.get(CredentialManagement.RESULT.LARGE_BLOB_KEY)
                                print(f"        {ci}:")
                                print("          User:")    # [PublicKeyCredentialUserEntity](https://www.w3.org/TR/webauthn-2/#dictionary-user-credential-params)
                                print("            ID: " + bytes_to_str(user_information.get("id")))
                                print("            Name: " + obj_to_str(user_information.get("name")))
                                print("            Display name: " + obj_to_str(user_information.get("displayName")))
                                print("          Credential ID:")   # [PublicKeyCredentialDescriptor](https://www.w3.org/TR/webauthn-2/#dictdef-publickeycredentialdescriptor)
                                print("            ID: " + bytes_to_str(credential_desc.get("id")))
                                print("            Type: " + obj_to_str(credential_desc.get("type")))
                                print("            Transports: " + obj_to_str(credential_desc.get("transports")))
                                print("          Public key:")  # COSE_Key
                                print("            Key type: " + get_cose_kty_displayname(public_key))
                                print("            Algorithm: " + get_cose_alg_displayname(public_key))
                                print("            Key parameters: " + get_cose_key_parameters_for_display(public_key))
                                print("          Credential protection policy: " + obj_to_str(cred_protect))
                                print("          Large blob encryption key: " + obj_to_str(largeblobkey))
                        else:
                            print("      No credentials")
                else:
                    print("    No credentials")
        else:
            print("Device does not support CredentialManagement")
    else:
        print("Device does not support CBOR")

    print()
