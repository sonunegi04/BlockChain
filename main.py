import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
import base64


# --- Vehicle Registration System ---
# Store vehicles as: {number_plate: {"owner": str, "model": str}}
vehicles = {}


def get_clean_plate():
    """Ask for number plate and return uppercased, non‑empty string."""
    plate = input("Enter vehicle number plate: ").strip().upper()
    while not plate:
        print("Number plate cannot be empty.")
        plate = input("Enter vehicle number plate: ").strip().upper()
    return plate


def register_vehicle():
    """Register a new vehicle with owner and model."""
    plate = get_clean_plate()

    if plate in vehicles:
        print("A vehicle with this number plate already exists.")
        return

    owner = input("Enter owner name: ").strip()
    while not owner:
        print("Owner name cannot be empty.")
        owner = input("Enter owner name: ").strip()

    model = input("Enter vehicle model: ").strip()
    while not model:
        print("Vehicle model cannot be empty.")
        model = input("Enter vehicle model: ").strip()

    vehicles[plate] = {"owner": owner, "model": model}
    print("Vehicle registered successfully.")


def get_vehicle():
    """Retrieve vehicle details by number plate."""
    plate = get_clean_plate()

    if plate not in vehicles:
        print("Vehicle not found for this number plate.")
        return

    data = vehicles[plate]
    print(f"Owner: {data['owner']}")
    print(f"Model: {data['model']}")


# --- SHA‑256 Hashing ---
def sha256_hash():
    """Compute SHA‑256 hash of a user message."""
    msg = input("Enter a message to hash: ").strip()
    while not msg:
        print("Message cannot be empty.")
        msg = input("Enter a message to hash: ").strip()

    hash_obj = hashlib.sha256()
    hash_obj.update(msg.encode("utf-8"))
    digest = hash_obj.hexdigest()
    print(f"SHA‑256 hash: {digest}")


# --- Digital Signature (RSA) ---
private_key = None
public_key = None


def generate_keys():
    """Generate RSA key pair (2048 bits)."""
    global private_key, public_key

    print("Generating RSA key pair (2048 bits)...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    print("RSA key pair generated.")


def sign_message():
    """Sign a message using the private key."""
    if private_key is None:
        print("First generate RSA keys (option 2).")
        return

    msg = input("Enter the message to sign: ").strip()
    while not msg:
        print("Message cannot be empty.")
        msg = input("Enter the message to sign: ").strip()

    msg_bytes = msg.encode("utf-8")
    signature = private_key.sign(
        msg_bytes,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    b64_sig = base64.b64encode(signature).decode("utf-8")
    print(f"Signature (base64): {b64_sig}")


def verify_signature():
    """Verify a signature using the public key."""
    if public_key is None:
        print("First generate RSA keys (option 2).")
        return

    msg = input("Enter the original message: ").strip()
    while not msg:
        print("Message cannot be empty.")
        msg = input("Enter the original message: ").strip()

    b64_sig = input("Enter the signature (base64): ").strip()
    while not b64_sig:
        print("Signature cannot be empty.")
        b64_sig = input("Enter the signature (base64): ").strip()

    try:
        signature = base64.b64decode(b64_sig)
    except Exception:
        print("Invalid base64 signature.")
        return

    try:
        public_key.verify(
            signature,
            msg.encode("utf-8"),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        print("Signature is valid.")
    except Exception:
        print("Signature is invalid.")


# --- Menu Loop ---
def main_menu():
    """Print the main menu."""
    print("\n" + "=" * 50)
    print("    Cryptography and Blockchain Fundamentals")
    print("=" * 50)
    print("1. SHA‑256 Hash a message")
    print("2. Generate RSA key pair")
    print("3. Sign a message")
    print("4. Verify a signature")
    print("5. Register a vehicle")
    print("6. Retrieve vehicle details")
    print("7. Exit")
    print("-" * 50)


def main():
    """Main menu‑driven loop."""
    while True:
        main_menu()
        choice = input("Enter choice [1–7]: ").strip()

        if choice == "1":
            sha256_hash()
        elif choice == "2":
            generate_keys()
        elif choice == "3":
            sign_message()
        elif choice == "4":
            verify_signature()
        elif choice == "5":
            register_vehicle()
        elif choice == "6":
            get_vehicle()
        elif choice == "7":
            print("Exiting the application. Goodbye!")
            break
        else:
            print("Please enter a number between 1 and 7.")


if __name__ == "__main__":
    main()