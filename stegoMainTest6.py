import customtkinter
from tkinter import filedialog, messagebox
from PIL import Image
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

# Initialize the application
def initialize_app():
    customtkinter.set_appearance_mode("dark")
    customtkinter.set_default_color_theme("green")

    root = customtkinter.CTk()
    root.geometry("500x600")
    root.title("Steganography Tool")
    return root

# Create the main UI with tabs
def create_main_ui(root):
    tabview = customtkinter.CTkTabview(master=root, width=400, height=500)
    tabview.pack(padx=20, pady=20)

    # Add tabs for encryption and decryption
    encryption_tab = tabview.add("Encryption")
    decryption_tab = tabview.add("Decryption")

    return encryption_tab, decryption_tab

# AES Encryption Function
def encrypt_aes(message, key, key_size):
    try:
        # Ensure the key is the correct length (16 bytes for 128-bit, 32 bytes for 256-bit)
        key = key.encode("utf-8")
        key = key[:key_size].ljust(key_size, b"\0")  # Pad or truncate the key

        # Generate a random initialization vector (IV)
        iv = get_random_bytes(16)

        # Create AES cipher
        cipher = AES.new(key, AES.MODE_CBC, iv)

        # Pad the message to be a multiple of 16 bytes
        padded_message = pad(message.encode("utf-8"), AES.block_size)

        # Encrypt the message
        encrypted_message = cipher.encrypt(padded_message)

        # Combine IV and encrypted message
        combined = iv + encrypted_message

        # Encode in base64 for easy storage
        return base64.b64encode(combined).decode("utf-8")
    except Exception as e:
        messagebox.showerror("Encryption Error", str(e))
        return None

# AES Decryption Function
def decrypt_aes(encrypted_message, key, key_size):
    try:
        # Ensure the key is the correct length
        key = key.encode("utf-8")
        key = key[:key_size].ljust(key_size, b"\0")  # Pad or truncate the key

        # Decode the base64 message
        combined = base64.b64decode(encrypted_message.encode("utf-8"))

        # Extract IV and encrypted message
        iv = combined[:16]
        encrypted_message = combined[16:]

        # Create AES cipher
        cipher = AES.new(key, AES.MODE_CBC, iv)

        # Decrypt the message
        decrypted_message = cipher.decrypt(encrypted_message)

        # Unpad the message
        return unpad(decrypted_message, AES.block_size).decode("utf-8")
    except Exception as e:
        messagebox.showerror("Decryption Error", str(e))
        return None

# Encryption UI
def create_encryption_ui(frame):
    def upload_image():
        file_path = filedialog.askopenfilename(filetypes=[("PNG files", "*.png")])
        if file_path:
            entry_image.delete(0, "end")
            entry_image.insert(0, file_path)
            show_preview(image_preview, file_path)

    def encrypt():
        image_path = entry_image.get()
        message = entry_message.get()
        key = entry_key.get()
        encryption_type = encryption_type_combobox.get()

        if not image_path or not message or not key or not encryption_type:
            messagebox.showerror("Error", "All fields are required!")
            return

        try:
            # Determine key size based on encryption type
            key_size = 16 if encryption_type == "128-bit" else 32

            # Encrypt the message using AES
            encrypted_message = encrypt_aes(message, key, key_size)
            if not encrypted_message:
                return

            # Embed the encrypted message into the image using LSB
            img = Image.open(image_path)
            encoded = img.copy()
            width, height = img.size
            binary_message = ''.join(format(ord(c), '08b') for c in (encrypted_message + '###'))
            data_index = 0

            for y in range(height):
                for x in range(width):
                    if data_index < len(binary_message):
                        r, g, b = img.getpixel((x, y))
                        r = (r & ~1) | int(binary_message[data_index])
                        encoded.putpixel((x, y), (r, g, b))
                        data_index += 1
                    else:
                        break

            # Save the encoded image
            output_path = os.path.splitext(image_path)[0] + "_encoded.png"
            encoded.save(output_path)
            messagebox.showinfo("Success", f"Message encrypted and saved as {output_path}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    # Create the encryption frame
    frame_encrypt = customtkinter.CTkFrame(master=frame)
    frame_encrypt.pack(pady=20, padx=10, expand=True, fill="both")

    # Image upload section
    entry_image = customtkinter.CTkEntry(master=frame_encrypt, placeholder_text="Image will show here")
    entry_image.pack(pady=5, padx=10)

    btn_upload = customtkinter.CTkButton(frame_encrypt, text="Upload Image", command=upload_image)
    btn_upload.pack(pady=5)

    image_preview = customtkinter.CTkLabel(frame_encrypt, text="")
    image_preview.pack(pady=5)

    # Message and key input
    entry_message = customtkinter.CTkEntry(master=frame_encrypt, placeholder_text="Enter secret message")
    entry_message.pack(pady=5, padx=10)

    entry_key = customtkinter.CTkEntry(master=frame_encrypt, placeholder_text="Enter secret key")
    entry_key.pack(pady=5, padx=10)

    # Encryption type selection
    encryption_type_combobox = customtkinter.CTkComboBox(master=frame_encrypt, values=["128-bit", "256-bit"])
    encryption_type_combobox.pack(pady=5, padx=10)
    encryption_type_combobox.set("128-bit")  # Default encryption type

    # Encrypt button
    btn_encrypt = customtkinter.CTkButton(frame_encrypt, text="Encrypt", command=encrypt)
    btn_encrypt.pack(pady=10)

# Decryption UI
def create_decryption_ui(frame):
    def upload_image():
        file_path = filedialog.askopenfilename(filetypes=[("PNG files", "*.png")])
        if file_path:
            entry_image.delete(0, "end")
            entry_image.insert(0, file_path)
            show_preview(image_preview, file_path)

    def decrypt():
        image_path = entry_image.get()
        key = entry_key.get()
        encryption_type = encryption_type_combobox.get()

        if not image_path or not key or not encryption_type:
            messagebox.showerror("Error", "All fields are required!")
            return

        try:
            # Determine key size based on encryption type
            key_size = 16 if encryption_type == "128-bit" else 32

            # Extract the encrypted message from the image using LSB
            img = Image.open(image_path)
            width, height = img.size
            binary_message = ""

            for y in range(height):
                for x in range(width):
                    r, g, b = img.getpixel((x, y))
                    binary_message += str(r & 1)

            # Convert binary to string
            decoded_chars = [binary_message[i:i+8] for i in range(0, len(binary_message), 8)]
            extracted_text = "".join([chr(int(b, 2)) for b in decoded_chars])
            extracted_text = extracted_text.split("###")[0]

            # Decrypt the message using AES
            decrypted_message = decrypt_aes(extracted_text, key, key_size)
            if decrypted_message:
                messagebox.showinfo("Decrypted Message", decrypted_message)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    # Create the decryption frame
    frame_decrypt = customtkinter.CTkFrame(master=frame)
    frame_decrypt.pack(pady=20, padx=10, expand=True, fill="both")

    # Image upload section
    entry_image = customtkinter.CTkEntry(master=frame_decrypt, placeholder_text="Image will show here")
    entry_image.pack(pady=5, padx=10)

    btn_upload = customtkinter.CTkButton(frame_decrypt, text="Upload Image", command=upload_image)
    btn_upload.pack(pady=5)

    image_preview = customtkinter.CTkLabel(frame_decrypt, text="")
    image_preview.pack(pady=5)

    # Key input
    entry_key = customtkinter.CTkEntry(master=frame_decrypt, placeholder_text="Enter secret key")
    entry_key.pack(pady=5, padx=10)

    # Encryption type selection
    encryption_type_combobox = customtkinter.CTkComboBox(master=frame_decrypt, values=["128-bit", "256-bit"])
    encryption_type_combobox.pack(pady=5, padx=10)
    encryption_type_combobox.set("128-bit")  # Default encryption type

    # Decrypt button
    btn_decrypt = customtkinter.CTkButton(frame_decrypt, text="Decrypt", command=decrypt)
    btn_decrypt.pack(pady=10)

# Image preview function
def show_preview(label, file_path):
    img = Image.open(file_path)
    img = img.resize((100, 100))  # Resize the image
    ctk_image = customtkinter.CTkImage(light_image=img, dark_image=img, size=(100, 100))  # Convert to CTkImage
    label.configure(image=ctk_image)  # Use .configure() to set the image
    label.image = ctk_image  # Keep a reference to avoid garbage collection

# Main function to run the application
def main():
    root = initialize_app()
    encryption_tab, decryption_tab = create_main_ui(root)
    create_encryption_ui(encryption_tab)
    create_decryption_ui(decryption_tab)
    root.mainloop()

if __name__ == "__main__":
    main()