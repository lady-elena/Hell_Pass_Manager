import unittest
from django.test import Client
from django.urls import reverse
from .models import Data
from .crypt import encrypt_aes_256, decrypt_main_key


class MainTests(unittest.TestCase):
    def setUp(self):
        self.client = Client()

    def test_main_page(self):
        response = self.client.get(reverse('main_page'))
        self.assertEqual(response.status_code, 200)

    def test_generate_otp(self):
        secret_key = "DTXMND2Y25J5C65L"
        response = self.client.get(reverse('generate_otp', args=[secret_key]))
        self.assertEqual(response.status_code, 200)

    def test_save_data(self):
        user_id = 1

        response = self.client.post(reverse('save_data', args=[user_id]), {
            'service_name': 'Test Service',
            'service_url': 'http://example.com',
            'login': 'testuser',
            'password': 'password123',
            'totp_secret': 'your_totp_secret',
            'notes': 'Some notes',
        })
        self.assertEqual(response.status_code, 200)

        service = Data.objects.filter(service_name="Test Service")
        self.assertEqual(len(service), 1)

    def test_edit_item(self):
        item_id = 1

        response = self.client.post(reverse('edit_item', args=[item_id]), {
            'service_name': 'New Service',
            'service_url': 'http://example.com',
            'login': 'newuser',
            'password': 'newpassword',
            'totp_secret': 'new_totp_secret',
            'notes': 'New notes',
        })
        self.assertEqual(response.status_code, 200)

    def test_delete_item(self):
        item_id = 1
        response = self.client.delete(reverse('delete_item', args=[item_id]))
        self.assertEqual(response.status_code, 200)
        # Добавьте дополнительные проверки для этой функции


if __name__ == '__main__':
    unittest.main()

