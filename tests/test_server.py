from __future__ import annotations

import base64
import hashlib
import hmac
import unittest

import config
import server


class AuthTests(unittest.TestCase):
    def test_proof_matches_protocol(self) -> None:
        nonce = "test-nonce"
        key = hashlib.pbkdf2_hmac(
            "sha256",
            config.ACCESS_CODE.encode(),
            config.PBKDF2_SALT.encode(),
            config.PBKDF2_ITERATIONS,
            dklen=32,
        )
        expected = base64.urlsafe_b64encode(hmac.new(key, nonce.encode(), hashlib.sha256).digest()).decode().rstrip("=")
        self.assertEqual(server.derive_proof(config.ACCESS_CODE, nonce), expected)

    def test_wrong_code_creates_different_proof(self) -> None:
        self.assertNotEqual(server.derive_proof(config.ACCESS_CODE, "nonce"), server.derive_proof("0000000000", "nonce"))


class ImageTests(unittest.TestCase):
    def test_detects_supported_signatures(self) -> None:
        self.assertEqual(server.detect_image_type(b"\xff\xd8\xff\x00"), "image/jpeg")
        self.assertEqual(server.detect_image_type(b"\x89PNG\r\n\x1a\nrest"), "image/png")
        self.assertEqual(server.detect_image_type(b"GIF89a" + b"\0" * 10), "image/gif")
        self.assertEqual(server.detect_image_type(b"RIFF\x00\x00\x00\x00WEBP"), "image/webp")
        self.assertIsNone(server.detect_image_type(b"not-an-image"))

    def test_reads_png_dimensions(self) -> None:
        data = b"\x89PNG\r\n\x1a\n" + b"\0" * 8 + (640).to_bytes(4, "big") + (480).to_bytes(4, "big")
        self.assertEqual(server.image_dimensions(data, "image/png"), (640, 480))

    def test_reads_extended_webp_dimensions(self) -> None:
        data = b"RIFF" + b"\0" * 4 + b"WEBPVP8X" + b"\0" * 8
        data += (511).to_bytes(3, "little") + (682).to_bytes(3, "little")
        self.assertEqual(server.image_dimensions(data, "image/webp"), (512, 683))

    def test_reads_lossy_webp_dimensions(self) -> None:
        data = b"RIFF" + b"\0" * 4 + b"WEBPVP8 " + b"\0" * 7 + b"\x9d\x01\x2a"
        data += (640).to_bytes(2, "little") + (480).to_bytes(2, "little")
        self.assertEqual(server.image_dimensions(data, "image/webp"), (640, 480))

    def test_reads_lossless_webp_dimensions(self) -> None:
        width, height = 321, 654
        bits = (width - 1) | ((height - 1) << 14)
        data = b"RIFF" + b"\0" * 4 + b"WEBPVP8L" + b"\0" * 4 + b"\x2f" + bits.to_bytes(4, "little")
        self.assertEqual(server.image_dimensions(data, "image/webp"), (width, height))

    def test_sanitizes_original_filename(self) -> None:
        self.assertEqual(server.safe_original_name("../../my%20photo!.jpg"), "my photo.jpg")


if __name__ == "__main__":
    unittest.main()
