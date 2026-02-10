import unittest
import struct
from scanner import PatternGenerator

class TestPatternGenerator(unittest.TestCase):
    def test_create_length(self):
        """Test that the created pattern has the correct length."""
        lengths = [0, 1, 10, 100, 1000]
        for length in lengths:
            pattern = PatternGenerator.create(length)
            self.assertEqual(len(pattern), length)

    def test_create_content(self):
        """Test that the pattern contains expected characters."""
        pattern = PatternGenerator.create(10)
        # First 3 chars should be ABC (A=0, B=0, C=0)
        # Wait, looking at code: chars[a] + chars[b] + chars[c]
        # a=0 (A), b=0 (A), c=0 (A) -> AAA
        self.assertEqual(pattern[:3], "AAA")
        # Then c increments: AAB, AAC...
        self.assertEqual(pattern[3:6], "AAB")

    def test_create_unique_length(self):
        """Test unique pattern length."""
        lengths = [0, 4, 8, 16]
        for length in lengths:
            pattern = PatternGenerator.create_unique(length)
            self.assertEqual(len(pattern), length)

    def test_offset_string(self):
        """Test offset calculation for strings."""
        pattern_len = 100
        pattern = PatternGenerator.create(pattern_len)
        test_str = "ABC" # a=0, b=1, c=2 overlap?
        # Let's find a real one:
        # 0: AAA, 3: AAB, 6: AAC
        self.assertEqual(PatternGenerator.offset("AAA", pattern_len), 0)
        self.assertEqual(PatternGenerator.offset("AAB", pattern_len), 3)

    def test_offset_int(self):
        """Test offset calculation for integers (little-endian)."""
        # create_unique uses 0x41414100 + (i // 4) % 256
        # i=0: 0x41414100
        # i=4: 0x41414101
        self.assertEqual(PatternGenerator.offset(0x41414100, 100), 0)
        self.assertEqual(PatternGenerator.offset(0x41414101, 100), 4)

    def test_offset_not_found(self):
        """Test that offset returns -1 for non-existent values."""
        self.assertEqual(PatternGenerator.offset("ZZZZZZZZ", 100), -1)

if __name__ == '__main__':
    unittest.main()
