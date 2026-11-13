"""ARM-only Mach-O selection. x86 slices are never passed to analyzers."""
import struct

ARM = 12
ARM64 = 0x0100000C
THIN = {b'\xce\xfa\xed\xfe': ('<', 28), b'\xcf\xfa\xed\xfe': ('<', 32),
        b'\xfe\xed\xfa\xce': ('>', 28), b'\xfe\xed\xfa\xcf': ('>', 32)}
FAT = {b'\xca\xfe\xba\xbe': ('>', False), b'\xbe\xba\xfe\xca': ('<', False),
       b'\xca\xfe\xba\xbf': ('>', True), b'\xbf\xba\xfe\xca': ('<', True)}


def thin_info(raw):
    spec = THIN.get(raw[:4])
    if not spec or len(raw) < spec[1]: raise ValueError('不是完整的 Mach-O 切片')
    cpu, subtype = struct.unpack_from(spec[0] + 'II', raw, 4)
    subtype &= 0xFFFFFF
    if cpu not in (ARM, ARM64): raise ValueError('拒绝分析 x86 或其他非 ARM 架构')
    return cpu, subtype, 'arm64e' if cpu == ARM64 and subtype == 2 else 'arm64e.x1' if cpu == ARM64 and subtype == 12 else 'arm64' if cpu == ARM64 else 'arm'


def select_arm(raw):
    """Return a verified thin ARM image and original container metadata."""
    if raw[:4] in THIN:
        cpu, subtype, arch = thin_info(raw)
        return raw, {'architecture': arch, 'universal': False, 'offset': 0, 'slice_size': len(raw)}
    spec = FAT.get(raw[:4])
    if not spec or len(raw) < 8:
        raise ValueError('真实二进制分析仅支持 ARM Mach-O；x86 和未识别格式拒绝分析')
    endian, wide = spec
    count = struct.unpack_from(endian + 'I', raw, 4)[0]
    entry_size = 32 if wide else 20
    if not 0 < count <= 64 or 8 + count * entry_size > len(raw): raise ValueError('Universal Binary 架构表无效')
    candidates = []
    for index in range(count):
        offset = 8 + index * entry_size
        cpu, subtype = struct.unpack_from(endian + 'II', raw, offset)
        start, size = struct.unpack_from(endian + ('QQ' if wide else 'II'), raw, offset + 8)
        if start < 8 + count * entry_size or size == 0 or start + size > len(raw):
            raise ValueError('Universal Binary 切片范围无效')
        if cpu in (ARM, ARM64):
            priority = 3 if cpu == ARM64 and subtype & 0xFFFFFF == 2 else 2 if cpu == ARM64 else 1
            candidates.append((priority, start, size, cpu, subtype & 0xFFFFFF))
    if not candidates: raise ValueError('Universal Binary 没有 ARM 切片，拒绝分析 x86')
    _, start, size, cpu, subtype = max(candidates)
    image = raw[start:start + size]
    actual_cpu, actual_subtype, arch = thin_info(image)
    if (actual_cpu, actual_subtype) != (cpu, subtype): raise ValueError('切片头与架构表不一致')
    return image, {'architecture': arch, 'universal': True, 'offset': start, 'slice_size': size,
                   'container_architecture_count': count, 'non_arm_slices_analyzed': False}


def all_arm_architectures(raw):
    """Allow a runtime fallback only if every possible slice is verified ARM."""
    select_arm(raw)  # Validate all container bounds first.
    if raw[:4] in THIN:
        return [thin_info(raw)]
    endian, wide = FAT[raw[:4]]
    count = struct.unpack_from(endian + 'I', raw, 4)[0]
    result=[]
    for index in range(count):
        entry=8+index*(32 if wide else 20)
        start,size=struct.unpack_from(endian+('QQ' if wide else 'II'),raw,entry+8)
        cpu,subtype=struct.unpack_from(endian+'II',raw,entry)
        actual=thin_info(raw[start:start+size])
        if actual[:2]!=(cpu,subtype & 0xFFFFFF): raise ValueError('切片头与架构表不一致')
        result.append(actual)
    return result
