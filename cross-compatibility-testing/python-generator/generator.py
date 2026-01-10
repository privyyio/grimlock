#!/usr/bin/env python3
"""Python Test Data Generator for Cross-Compatibility Testing

Generates test data using Python grimlock implementation
that can be verified by Go and TypeScript implementations.
"""

import base64
import json
import os
import sys
from pathlib import Path

# Add grimlock to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "python" / "grimlock"))

import grimlock
from grimlock.types.common import Argon2Params, KdfParams, MessageContext, MessagePayload


def main():
    """Generate test data."""
    test_data = {}

    g = grimlock.v1

    # 1. Key Generation Test
    print("Generating key pair...")
    key_pair = g.generate_key_pair()
    test_data["keyPair"] = {
        "privateKey": base64.b64encode(key_pair.private_key).decode("ascii"),
        "publicKey": base64.b64encode(key_pair.public_key).decode("ascii"),
    }

    # 2. Passcode Key Derivation Test
    print("Deriving passcode key...")
    passcode = "MySecurePasscode123!"
    salt = g.generate_salt()
    kdf_params = KdfParams(
        salt=salt,
        argon2_params=Argon2Params(
            time_cost=4,
            memory_cost=128 * 1024,  # 128MB
            parallelism=2,
        ),
    )
    derived_key = g.derive_passcode_key(passcode, kdf_params)
    test_data["passcodeDerivation"] = {
        "passcode": passcode,
        "salt": base64.b64encode(salt).decode("ascii"),
        "params": {
            "timeCost": kdf_params.argon2_params.time_cost,
            "memoryCost": kdf_params.argon2_params.memory_cost,
            "parallelism": kdf_params.argon2_params.parallelism,
        },
        "derivedKey": base64.b64encode(derived_key).decode("ascii"),
    }

    # 3. Recovery Key Derivation Test
    print("Deriving recovery key...")
    recovery_key = g.generate_recovery_key()
    recovery_derived_key = g.derive_recovery_key(recovery_key.raw)
    test_data["recoveryKeyDerivation"] = {
        "recoveryKeyBytes": base64.b64encode(recovery_key.raw).decode("ascii"),
        "derivedKey": base64.b64encode(recovery_derived_key).decode("ascii"),
    }

    # 4. Private Key Encryption Test
    print("Encrypting private key...")
    private_key_to_encrypt = key_pair.private_key
    encryption_key = derived_key  # Use the derived key from passcode
    aad = b"user@example.com"
    encrypted_private_key = g.encrypt_private_key(
        private_key_to_encrypt, encryption_key, aad
    )
    test_data["privateKeyEncryption"] = {
        "privateKey": base64.b64encode(private_key_to_encrypt).decode("ascii"),
        "encryptionKey": base64.b64encode(encryption_key).decode("ascii"),
        "aad": base64.b64encode(aad).decode("ascii"),
        "encrypted": {
            "iv": base64.b64encode(encrypted_private_key.iv).decode("ascii"),
            "tag": base64.b64encode(encrypted_private_key.tag).decode("ascii"),
            "ciphertext": base64.b64encode(encrypted_private_key.ciphertext).decode(
                "ascii"
            ),
        },
    }

    # 5. Message Encryption Test
    print("Encrypting message...")
    user_key_pair = g.generate_key_pair()
    payload = MessagePayload(
        user_message="Hello, this is a test message!",
        assistant_response="I understand. This is a response.",
        context={
            "timestamp": "2024-01-15T10:30:00Z",
            "metadata": "test",
        },
    )
    context = MessageContext(
        conversation_id="conv-123",
        message_id="msg-456",
    )
    encrypted_message = g.encrypt_message(payload, user_key_pair.public_key, context)
    test_data["messageEncryption"] = {
        "payload": {
            "userMessage": payload.user_message,
            "assistantResponse": payload.assistant_response,
            "optionalContext": payload.context or {},
        },
        "userKeyPair": {
            "privateKey": base64.b64encode(user_key_pair.private_key).decode("ascii"),
            "publicKey": base64.b64encode(user_key_pair.public_key).decode("ascii"),
        },
        "context": {
            "conversationId": context.conversation_id,
            "messageId": context.message_id,
        },
        "encrypted": {
            "ephemeralPublicKey": base64.b64encode(
                encrypted_message.ephemeral_public_key
            ).decode("ascii"),
            "iv": base64.b64encode(encrypted_message.iv).decode("ascii"),
            "tag": base64.b64encode(encrypted_message.tag).decode("ascii"),
            "ciphertext": base64.b64encode(encrypted_message.ciphertext).decode("ascii"),
        },
    }

    # 6. ECDH Test
    print("Computing shared secret...")
    alice_key_pair = g.generate_key_pair()
    bob_key_pair = g.generate_key_pair()
    shared_secret = g.compute_shared_secret(
        alice_key_pair.private_key, bob_key_pair.public_key
    )
    test_data["ecdhTest"] = {
        "alicePrivateKey": base64.b64encode(alice_key_pair.private_key).decode("ascii"),
        "alicePublicKey": base64.b64encode(alice_key_pair.public_key).decode("ascii"),
        "bobPrivateKey": base64.b64encode(bob_key_pair.private_key).decode("ascii"),
        "bobPublicKey": base64.b64encode(bob_key_pair.public_key).decode("ascii"),
        "sharedSecret": base64.b64encode(shared_secret).decode("ascii"),
    }

    # 7. Recovery Key Test
    print("Testing recovery key encryption...")
    test_recovery_key = g.generate_recovery_key()
    private_key_for_recovery = key_pair.private_key
    aad_for_recovery = b"recovery@example.com"
    recovery_encryption_key = g.derive_recovery_key(test_recovery_key.raw)
    encrypted_with_recovery = g.encrypt_private_key(
        private_key_for_recovery, recovery_encryption_key, aad_for_recovery
    )
    test_data["recoveryKeyTest"] = {
        "recoveryKey": {
            "key": base64.b64encode(test_recovery_key.raw).decode("ascii"),
            "mnemonic": test_recovery_key.mnemonic or "",
        },
        "privateKey": base64.b64encode(private_key_for_recovery).decode("ascii"),
        "aad": base64.b64encode(aad_for_recovery).decode("ascii"),
        "encrypted": {
            "iv": base64.b64encode(encrypted_with_recovery.iv).decode("ascii"),
            "tag": base64.b64encode(encrypted_with_recovery.tag).decode("ascii"),
            "ciphertext": base64.b64encode(encrypted_with_recovery.ciphertext).decode(
                "ascii"
            ),
        },
    }

    # Write to JSON file
    output_path = Path(__file__).parent.parent / "test-data" / "python-generated.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w") as f:
        json.dump(test_data, f, indent=2)

    print(f"✅ Test data generated successfully: {output_path}")


if __name__ == "__main__":
    main()
