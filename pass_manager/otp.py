import re
import time

import pyotp
from django.http import HttpResponse


def generate_otp(secret_key):
    """Generates one time password"""

    def is_base32(secret_key):
        """Checks whether secret key corresponds Base32 or not"""
        return bool(re.match('^[A-Z2-7]*$', secret_key))

    if is_base32(secret_key):
        # If service gets Base32 key
        totp = pyotp.TOTP(secret_key)
        OTP = totp.now()

        time_remaining = totp.interval - (int(time.time()) % totp.interval)
        # return HttpResponse(OTP)
        return OTP, time_remaining
    else:
        # If service gets not Base32 key
        return HttpResponse("Invalid secret key")