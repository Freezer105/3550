import unittest
import requests
import json

class TestJWKS(unittest.TestCase):
    def test_jwks_endpoint(self):
        # Test JWKS endpoint
        response = requests.get('http://localhost:8080/.well-known/jwks.json')
        self.assertEqual(response.status_code, 200)
        # Add more assertions to validate the response content

    def test_auth_endpoint(self):
        # Test /auth endpoint without expired parameter
        response = requests.post('http://localhost:8080/auth', json={"username": "timmy", "password": "timmy123"})
        self.assertEqual(response.status_code, 200)
        # Add more assertions to validate the JWT in the response

        # Test /auth endpoint with expired parameter
        response_expired = requests.post('http://localhost:8080/auth?expired=true', json={"username": "timmy", "password": "timmy123"})
        self.assertEqual(response_expired.status_code, 200)
        # Add more assertions to validate the JWT in the response

    def test_register_endpoint(self):
        # Test /register endpoint
        response = requests.post('http://localhost:8080/register', json={"username": "newuser", "email": "newuser@example.com"})
        self.assertIn(response.status_code, [200, 201])
        # Add more assertions to validate the response content

if __name__ == '__main__':
    unittest.main()
