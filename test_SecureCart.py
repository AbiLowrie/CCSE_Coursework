import unittest
from app import app  # Replace with your actual filename (without .py)

class FlaskAppTestCase(unittest.TestCase):
    def setUp(self):
        # Creates a test client
        self.app = app.test_client()
        # Propagate exceptions to the test client
        self.app.testing = True

    def test_home_page_loads(self):
        # Send a GET request to the "/" route
        response = self.app.get('/')
        # Check that the status code is 200 (OK)
        self.assertEqual(response.status_code, 200)

if __name__ == '__main__':
    unittest.main()