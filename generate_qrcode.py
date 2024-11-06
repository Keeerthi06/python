import qrcode
from PIL import Image

# Data to encode in the QR code
data = "https://www.example.com"

# Create a QR code object
qr = qrcode.QRCode(
    version=1,
    error_correction=qrcode.constants.ERROR_CORRECT_L,
    box_size=10,
    border=4,
)

# Add data to the QR code
qr.add_data(data)
qr.make(fit=True)

# Create an image of the QR code
img = qr.make_image(fill_color="black", back_color="white")

# Display the QR code image
img.show()  # This will open the image in your default image viewer
