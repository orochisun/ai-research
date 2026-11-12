import struct
import unittest
from binary_policy import select_arm


def thin(cpu=0x0100000c, subtype=2):
    return struct.pack('<8I', 0xfeedfacf, cpu, subtype, 2, 0, 0, 0, 0)


def fat(parts, wide=False):
    offset = 8 + len(parts) * (32 if wide else 20)
    table = b''
    images = b''
    for cpu, subtype, image in parts:
        table += struct.pack('>IIQQII' if wide else '>IIIII', cpu, subtype, offset, len(image), 0, *([0] if wide else []))
        images += image
        offset += len(image)
    return struct.pack('>II', 0xcafebabf if wide else 0xcafebabe, len(parts)) + table + images


class BinaryPolicyTests(unittest.TestCase):
    def test_reject_x86_thin_and_fat(self):
        for cpu in (7, 0x01000007):
            image = thin(cpu, 3)
            for raw in (image, fat([(cpu, 3, image)])):
                with self.assertRaisesRegex(ValueError, '拒绝'):
                    select_arm(raw)

    def test_universal_only_returns_arm_for_both_tables(self):
        arm = thin() + b'ARM_ONLY'
        for wide in (False, True):
            raw = fat([(0x01000007, 3, thin(0x01000007, 3) + b'X86_SECRET'), (0x0100000c, 2, arm)], wide)
            image, metadata = select_arm(raw)
            self.assertEqual(image, arm)
            self.assertNotIn(b'X86_SECRET', image)
            self.assertEqual(metadata['architecture'], 'arm64e')
            self.assertFalse(metadata['non_arm_slices_analyzed'])

    def test_reject_bad_bounds_and_mismatched_header(self):
        raw = fat([(0x0100000c, 2, thin())])
        for invalid in (raw[:-1], fat([(0x0100000c, 2, thin(0x01000007, 3))]), b'\xca\xfe\xba\xbe'):
            with self.assertRaises(ValueError): select_arm(invalid)

    def test_prefers_arm64e(self):
        raw = fat([(12, 0, thin(12, 0)), (0x0100000c, 2, thin()), (0x0100000c, 0, thin(0x0100000c, 0))])
        self.assertEqual(select_arm(raw)[1]['architecture'], 'arm64e')
