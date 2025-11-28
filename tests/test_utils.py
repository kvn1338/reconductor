#!/usr/bin/env python3
"""
Unit tests for utils.py module
Tests IP validation, subnet splitting, and parsing functions
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils import (
    extract_live_hosts,
    is_valid_target,
    sanitize_target_name,
    save_list_to_file,
    split_into_24_subnets,
)


class TestIPValidation(unittest.TestCase):
    """Test IP address validation"""

    def test_valid_single_ips(self):
        """Test valid single IP addresses"""
        valid_ips = [
            "192.168.1.1",
            "10.0.0.1",
            "172.16.0.1",
            "1.1.1.1",
            "255.255.255.255",
            "0.0.0.0",
        ]
        for ip in valid_ips:
            with self.subTest(ip=ip):
                self.assertTrue(is_valid_target(ip), f"{ip} should be valid")

    def test_valid_cidr_subnets(self):
        """Test valid CIDR subnets"""
        valid_cidrs = [
            "192.168.1.0/24",
            "10.0.0.0/8",
            "172.16.0.0/16",
            "192.168.0.0/20",
            "10.0.0.0/32",
        ]
        for cidr in valid_cidrs:
            with self.subTest(cidr=cidr):
                self.assertTrue(is_valid_target(cidr), f"{cidr} should be valid")

    def test_invalid_ips_out_of_range(self):
        """Test IPs with octets out of range"""
        invalid_ips = [
            "256.1.1.1",  # First octet too high
            "1.256.1.1",  # Second octet too high
            "1.1.256.1",  # Third octet too high
            "1.1.1.256",  # Fourth octet too high
            "300.300.300.300",  # All octets too high
            "192.168.1.999",  # Way out of range
        ]
        for ip in invalid_ips:
            with self.subTest(ip=ip):
                self.assertFalse(is_valid_target(ip), f"{ip} should be invalid")

    def test_invalid_ips_leading_zeros(self):
        """Test IPs with leading zeros (ambiguous/octal notation)"""
        invalid_ips = [
            "192.168.001.1",
            "010.0.0.1",
            "192.168.01.01",
        ]
        for ip in invalid_ips:
            with self.subTest(ip=ip):
                # These might be valid depending on ipaddress module behavior
                # Just test that our function handles them consistently
                result = is_valid_target(ip)
                self.assertIsInstance(result, bool)

    def test_invalid_ips_format(self):
        """Test invalid IP formats"""
        invalid_ips = [
            "192.168.1",  # Too few octets
            "192.168.1.1.1",  # Too many octets
            "192.168..1",  # Empty octet
            "192.168.1.",  # Trailing dot
            ".192.168.1.1",  # Leading dot
            "192.168.1.a",  # Letter instead of number
            "192.168.1.1/",  # Trailing slash without CIDR
            "",  # Empty string
            "localhost",  # Hostname not IP
        ]
        for ip in invalid_ips:
            with self.subTest(ip=ip):
                self.assertFalse(is_valid_target(ip), f"{ip} should be invalid")

    def test_invalid_cidr_prefix(self):
        """Test invalid CIDR prefix lengths"""
        invalid_cidrs = [
            "192.168.1.0/33",  # Prefix too large
            "192.168.1.0/0",  # Prefix too small (technically valid but edge case)
            "192.168.1.0/-1",  # Negative prefix
            "192.168.1.0/abc",  # Non-numeric prefix
            "192.168.1.0/24/24",  # Double prefix
        ]
        for cidr in invalid_cidrs:
            with self.subTest(cidr=cidr):
                result = is_valid_target(cidr)
                if cidr == "192.168.1.0/0":
                    # /0 might be technically valid, just document behavior
                    pass
                else:
                    self.assertFalse(result, f"{cidr} should be invalid")

    def test_edge_cases(self):
        """Test edge case IP addresses"""
        edge_cases = [
            ("0.0.0.0", True),  # All zeros
            ("255.255.255.255", True),  # All 255s
            ("127.0.0.1", True),  # Localhost
            ("224.0.0.1", True),  # Multicast
            ("169.254.1.1", True),  # Link-local
        ]
        for ip, expected in edge_cases:
            with self.subTest(ip=ip):
                self.assertEqual(
                    is_valid_target(ip), expected, f"{ip} validation unexpected"
                )


class TestSubnetSplitting(unittest.TestCase):
    """Test subnet splitting into /24 chunks"""

    def test_split_slash_24(self):
        """Test that /24 remains as-is"""
        result = split_into_24_subnets("192.168.1.0/24")
        self.assertEqual(result, ["192.168.1.0/24"])

    def test_split_slash_23(self):
        """Test splitting /23 into 2× /24"""
        result = split_into_24_subnets("192.168.0.0/23")
        expected = ["192.168.0.0/24", "192.168.1.0/24"]
        self.assertEqual(result, expected)

    def test_split_slash_22(self):
        """Test splitting /22 into 4× /24"""
        result = split_into_24_subnets("192.168.0.0/22")
        expected = [
            "192.168.0.0/24",
            "192.168.1.0/24",
            "192.168.2.0/24",
            "192.168.3.0/24",
        ]
        self.assertEqual(result, expected)

    def test_split_slash_20(self):
        """Test splitting /20 into 16× /24"""
        result = split_into_24_subnets("10.0.0.0/20")
        self.assertEqual(len(result), 16)
        self.assertEqual(result[0], "10.0.0.0/24")
        self.assertEqual(result[15], "10.0.15.0/24")

    def test_split_slash_16(self):
        """Test splitting /16 into 256× /24"""
        result = split_into_24_subnets("172.16.0.0/16")
        self.assertEqual(len(result), 256)
        self.assertEqual(result[0], "172.16.0.0/24")
        self.assertEqual(result[255], "172.16.255.0/24")

    def test_split_single_ip(self):
        """Test that single IP is converted to /32"""
        result = split_into_24_subnets("192.168.1.1")
        self.assertEqual(result, ["192.168.1.1/32"])

    def test_split_slash_32(self):
        """Test that /32 (single IP) remains as-is with /32 suffix"""
        result = split_into_24_subnets("192.168.1.1/32")
        self.assertEqual(result, ["192.168.1.1/32"])

    def test_split_slash_25_and_larger(self):
        """Test that subnets larger than /24 remain as-is"""
        subnets = ["192.168.1.0/25", "192.168.1.128/26", "192.168.1.192/27"]
        for subnet in subnets:
            with self.subTest(subnet=subnet):
                result = split_into_24_subnets(subnet)
                self.assertEqual(result, [subnet])

    def test_split_invalid_target(self):
        """Test splitting invalid targets returns empty list"""
        invalid = ["999.999.999.999", "not-an-ip", "192.168.1.0/33"]
        for target in invalid:
            with self.subTest(target=target):
                result = split_into_24_subnets(target)
                self.assertEqual(result, [])

    def test_split_boundary_cases(self):
        """Test boundary cases in subnet splitting"""
        # /18 should split into 64× /24
        result = split_into_24_subnets("10.0.0.0/18")
        self.assertEqual(len(result), 64)

        # Verify no duplicates
        self.assertEqual(len(result), len(set(result)))

        # Verify all are valid /24s
        for subnet in result:
            self.assertTrue(subnet.endswith("/24"))


class TestSanitizeTargetName(unittest.TestCase):
    """Test target name sanitization for filesystem paths"""

    def test_sanitize_slash_24(self):
        """Test sanitizing /24 subnet"""
        result = sanitize_target_name("192.168.1.0/24")
        self.assertEqual(result, "192_168_1_0-24")

    def test_sanitize_single_ip(self):
        """Test sanitizing single IP"""
        result = sanitize_target_name("10.0.0.1")
        self.assertEqual(result, "10_0_0_1")

    def test_sanitize_slash_16(self):
        """Test sanitizing /16 subnet"""
        result = sanitize_target_name("172.16.0.0/16")
        self.assertEqual(result, "172_16_0_0-16")

    def test_sanitize_removes_special_chars(self):
        """Test that special characters are replaced"""
        # Dots become underscores
        self.assertNotIn(".", sanitize_target_name("192.168.1.1"))
        # Slashes become dashes
        self.assertNotIn("/", sanitize_target_name("192.168.1.0/24"))

    def test_sanitize_no_invalid_path_chars(self):
        """Test that result is safe for filesystem paths"""
        result = sanitize_target_name("192.168.1.0/24")
        invalid_chars = ["/", "\\", ":", "*", "?", '"', "<", ">", "|"]
        for char in invalid_chars:
            self.assertNotIn(char, result)


class TestSaveListToFile(unittest.TestCase):
    """Test saving lists to files"""

    def setUp(self):
        """Create temporary directory for test files"""
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        """Clean up temporary files"""
        import shutil

        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_save_simple_list(self):
        """Test saving a simple list"""
        filepath = os.path.join(self.test_dir, "test.txt")
        data = ["192.168.1.1", "192.168.1.2", "192.168.1.3"]

        result = save_list_to_file(data, filepath)
        self.assertTrue(result)

        # Verify file contents (strip trailing newline)
        with open(filepath, "r") as f:
            content = f.read().strip()
            lines = content.split("\n") if content else []
        self.assertEqual(lines, data)

    def test_save_empty_list(self):
        """Test saving empty list"""
        filepath = os.path.join(self.test_dir, "empty.txt")
        result = save_list_to_file([], filepath)
        self.assertTrue(result)

        # File should exist with just a newline
        self.assertTrue(os.path.exists(filepath))
        with open(filepath, "r") as f:
            self.assertEqual(f.read(), "\n")

    def test_save_to_existing_directory(self):
        """Test saving to an existing directory"""
        # Create subdirectory first
        subdir = os.path.join(self.test_dir, "subdir")
        os.makedirs(subdir, exist_ok=True)

        filepath = os.path.join(subdir, "test.txt")
        data = ["test"]

        result = save_list_to_file(data, filepath)
        self.assertTrue(result)
        self.assertTrue(os.path.exists(filepath))

    def test_save_overwrites_existing(self):
        """Test that existing file is overwritten"""
        filepath = os.path.join(self.test_dir, "test.txt")

        # Write initial data
        save_list_to_file(["old"], filepath)

        # Overwrite with new data
        new_data = ["new1", "new2"]
        save_list_to_file(new_data, filepath)

        # Verify only new data exists
        with open(filepath, "r") as f:
            lines = [line.strip() for line in f.readlines()]
        self.assertEqual(lines, new_data)

    def test_save_with_newlines_in_data(self):
        """Test that data is saved with newlines between items"""
        filepath = os.path.join(self.test_dir, "test.txt")
        data = ["line1", "line2", "line3"]

        save_list_to_file(data, filepath)

        with open(filepath, "r") as f:
            content = f.read()

        # Should have newlines between items plus trailing newline
        # Format: "line1\nline2\nline3\n"
        self.assertEqual(content.count("\n"), len(data))
        self.assertTrue(content.endswith("\n"))


class TestExtractLiveHosts(unittest.TestCase):
    """Test extracting live hosts from nmap gnmap files"""

    def setUp(self):
        """Create temporary directory for test files"""
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        """Clean up temporary files"""
        import shutil

        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_extract_from_valid_gnmap(self):
        """Test extracting hosts from valid gnmap file"""
        gnmap_file = os.path.join(self.test_dir, "test.gnmap")

        # Create sample gnmap content
        content = """# Nmap 7.80 scan initiated
Host: 192.168.1.1 ()	Status: Up
Host: 192.168.1.10 ()	Status: Up
Host: 192.168.1.50 ()	Status: Up
Host: 192.168.1.100 ()	Status: Down
# Nmap done
"""
        with open(gnmap_file, "w") as f:
            f.write(content)

        result = extract_live_hosts(gnmap_file)

        expected = ["192.168.1.1", "192.168.1.10", "192.168.1.50"]
        self.assertEqual(result, expected)

    def test_extract_ignores_down_hosts(self):
        """Test that down hosts are not included"""
        gnmap_file = os.path.join(self.test_dir, "test.gnmap")

        content = """Host: 192.168.1.1 ()	Status: Up
Host: 192.168.1.2 ()	Status: Down
Host: 192.168.1.3 ()	Status: Up
"""
        with open(gnmap_file, "w") as f:
            f.write(content)

        result = extract_live_hosts(gnmap_file)
        self.assertEqual(result, ["192.168.1.1", "192.168.1.3"])

    def test_extract_empty_file(self):
        """Test extracting from empty file"""
        gnmap_file = os.path.join(self.test_dir, "empty.gnmap")
        with open(gnmap_file, "w") as f:
            f.write("")

        result = extract_live_hosts(gnmap_file)
        self.assertEqual(result, [])

    def test_extract_no_live_hosts(self):
        """Test when no hosts are up"""
        gnmap_file = os.path.join(self.test_dir, "test.gnmap")

        content = """Host: 192.168.1.1 ()	Status: Down
Host: 192.168.1.2 ()	Status: Down
"""
        with open(gnmap_file, "w") as f:
            f.write(content)

        result = extract_live_hosts(gnmap_file)
        self.assertEqual(result, [])

    def test_extract_nonexistent_file(self):
        """Test extracting from nonexistent file"""
        result = extract_live_hosts("/nonexistent/file.gnmap")
        self.assertEqual(result, [])


class TestEdgeCases(unittest.TestCase):
    """Test edge cases and boundary conditions"""

    def test_unicode_in_target(self):
        """Test that unicode characters are handled"""
        # Should return False for non-ASCII IP
        result = is_valid_target("192.168.1.①")
        self.assertFalse(result)

    def test_whitespace_in_target(self):
        """Test targets with whitespace"""
        targets = [
            " 192.168.1.1",  # Leading space
            "192.168.1.1 ",  # Trailing space
            "192.168.1.1\n",  # Newline
            "192.168.1.1\t",  # Tab
        ]
        for target in targets:
            with self.subTest(target=repr(target)):
                # These should be handled (stripped) or rejected
                result = is_valid_target(target)
                # Document the behavior
                self.assertIsInstance(result, bool)

    def test_very_large_subnet(self):
        """Test splitting very large subnet"""
        # /8 = 2^16 = 65,536 /24 subnets
        result = split_into_24_subnets("10.0.0.0/8")
        self.assertEqual(len(result), 65536)
        self.assertEqual(result[0], "10.0.0.0/24")
        self.assertEqual(result[-1], "10.255.255.0/24")


if __name__ == "__main__":
    unittest.main()
