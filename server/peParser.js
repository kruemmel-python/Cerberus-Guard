const DOS_SIGNATURE = 0x5a4d;
const PE_SIGNATURE = 0x00004550;
const SECTION_HEADER_SIZE = 40;
const IMPORT_DESCRIPTOR_SIZE = 20;

const MACHINE_NAMES = {
  0x014c: 'x86',
  0x0200: 'Intel Itanium',
  0x8664: 'x64',
  0xaa64: 'ARM64',
};

const SUBSYSTEM_NAMES = {
  0: 'Unknown',
  1: 'Native',
  2: 'Windows GUI',
  3: 'Windows CUI',
  5: 'OS/2 CUI',
  7: 'POSIX CUI',
  9: 'Windows CE GUI',
  10: 'EFI Application',
  11: 'EFI Boot Service Driver',
  12: 'EFI Runtime Driver',
  13: 'EFI ROM',
  14: 'XBOX',
  16: 'Windows Boot Application',
};

const COFF_CHARACTERISTICS = {
  0x0002: 'EXECUTABLE_IMAGE',
  0x0020: 'LARGE_ADDRESS_AWARE',
  0x0100: '32BIT_MACHINE',
  0x0200: 'DEBUG_STRIPPED',
  0x2000: 'DLL',
};

const SECTION_CHARACTERISTICS = {
  0x00000020: 'CODE',
  0x00000040: 'INITIALIZED_DATA',
  0x00000080: 'UNINITIALIZED_DATA',
  0x20000000: 'EXECUTE',
  0x40000000: 'READ',
  0x80000000: 'WRITE',
};

const decodeFlags = (value, mapping) =>
  Object.entries(mapping)
    .filter(([flag]) => (value & Number(flag)) === Number(flag))
    .map(([, label]) => label);

const readAsciiString = (buffer, offset, maxLength = 512) => {
  if (!Number.isInteger(offset) || offset < 0 || offset >= buffer.length) {
    return '';
  }

  let cursor = offset;
  const bytes = [];
  while (cursor < buffer.length && bytes.length < maxLength) {
    const value = buffer[cursor];
    if (value === 0) {
      break;
    }
    if (value < 32 || value > 126) {
      break;
    }
    bytes.push(value);
    cursor += 1;
  }
  return Buffer.from(bytes).toString('ascii');
};

const computeEntropy = buffer => {
  if (!buffer.length) {
    return 0;
  }

  const histogram = new Array(256).fill(0);
  for (const value of buffer) {
    histogram[value] += 1;
  }

  let entropy = 0;
  for (const count of histogram) {
    if (!count) {
      continue;
    }
    const probability = count / buffer.length;
    entropy -= probability * Math.log2(probability);
  }
  return entropy;
};

const clampSlice = (buffer, start, length) => {
  const safeStart = Math.max(0, start);
  const safeEnd = Math.min(buffer.length, safeStart + Math.max(0, length));
  return buffer.subarray(safeStart, safeEnd);
};

const hex = value => `0x${value.toString(16)}`;

const rvaToOffset = (rva, sections) => {
  for (const section of sections) {
    const sectionSize = Math.max(section.virtualSize, section.rawSize);
    if (rva >= section.virtualAddress && rva < section.virtualAddress + sectionSize) {
      return section.rawPointer + (rva - section.virtualAddress);
    }
  }
  return null;
};

const parseImports = ({ buffer, sections, importDirectoryRva, isPe32Plus }) => {
  if (!importDirectoryRva) {
    return [];
  }

  const descriptorOffset = rvaToOffset(importDirectoryRva, sections);
  if (descriptorOffset === null) {
    return [];
  }

  const imports = [];
  const thunkSize = isPe32Plus ? 8 : 4;
  const ordinalMask = isPe32Plus ? 0x8000000000000000n : 0x80000000n;
  const nameMask = isPe32Plus ? 0x7fffffffffffffffn : 0x7fffffffn;
  const maxDescriptors = 256;
  const maxFunctionsPerLibrary = 256;

  for (let descriptorIndex = 0; descriptorIndex < maxDescriptors; descriptorIndex += 1) {
    const offset = descriptorOffset + descriptorIndex * IMPORT_DESCRIPTOR_SIZE;
    if (offset + IMPORT_DESCRIPTOR_SIZE > buffer.length) {
      break;
    }

    const originalFirstThunk = buffer.readUInt32LE(offset);
    const timeDateStamp = buffer.readUInt32LE(offset + 4);
    const forwarderChain = buffer.readUInt32LE(offset + 8);
    const nameRva = buffer.readUInt32LE(offset + 12);
    const firstThunk = buffer.readUInt32LE(offset + 16);

    if (!originalFirstThunk && !timeDateStamp && !forwarderChain && !nameRva && !firstThunk) {
      break;
    }

    const nameOffset = rvaToOffset(nameRva, sections);
    const library = nameOffset === null ? `unknown_${descriptorIndex}` : readAsciiString(buffer, nameOffset);
    const thunkRva = originalFirstThunk || firstThunk;
    const thunkOffset = rvaToOffset(thunkRva, sections);
    if (thunkOffset === null) {
      imports.push({ library, functions: [] });
      continue;
    }

    const functions = [];
    for (let thunkIndex = 0; thunkIndex < maxFunctionsPerLibrary; thunkIndex += 1) {
      const entryOffset = thunkOffset + thunkIndex * thunkSize;
      if (entryOffset + thunkSize > buffer.length) {
        break;
      }

      const entryValue = isPe32Plus ? buffer.readBigUInt64LE(entryOffset) : BigInt(buffer.readUInt32LE(entryOffset));
      if (entryValue === 0n) {
        break;
      }

      if ((entryValue & ordinalMask) === ordinalMask) {
        functions.push(`ordinal_${Number(entryValue & 0xffffn)}`);
        continue;
      }

      const importNameOffset = rvaToOffset(Number(entryValue & nameMask), sections);
      if (importNameOffset === null || importNameOffset + 2 >= buffer.length) {
        continue;
      }

      const functionName = readAsciiString(buffer, importNameOffset + 2);
      if (functionName) {
        functions.push(functionName);
      }
    }

    imports.push({
      library,
      functions: [...new Set(functions)],
    });
  }

  return imports;
};

export const isPortableExecutable = buffer =>
  buffer.length > 0x40
  && buffer.readUInt16LE(0) === DOS_SIGNATURE
  && buffer.readUInt32LE(0x3c) + 4 < buffer.length
  && buffer.readUInt32LE(buffer.readUInt32LE(0x3c)) === PE_SIGNATURE;

export const parsePortableExecutable = buffer => {
  if (!isPortableExecutable(buffer)) {
    return null;
  }

  try {
    const peOffset = buffer.readUInt32LE(0x3c);
    const coffOffset = peOffset + 4;
    const machine = buffer.readUInt16LE(coffOffset);
    const numberOfSections = buffer.readUInt16LE(coffOffset + 2);
    const timeDateStamp = buffer.readUInt32LE(coffOffset + 4);
    const sizeOfOptionalHeader = buffer.readUInt16LE(coffOffset + 16);
    const characteristicsValue = buffer.readUInt16LE(coffOffset + 18);
    const optionalHeaderOffset = coffOffset + 20;
    const optionalMagic = buffer.readUInt16LE(optionalHeaderOffset);
    const isPe32Plus = optionalMagic === 0x20b;
    const format = isPe32Plus ? 'PE32+' : 'PE32';
    const entryPointRva = buffer.readUInt32LE(optionalHeaderOffset + 16);
    const imageBase = isPe32Plus
      ? `0x${buffer.readBigUInt64LE(optionalHeaderOffset + 24).toString(16)}`
      : hex(buffer.readUInt32LE(optionalHeaderOffset + 28));
    const subsystem = buffer.readUInt16LE(optionalHeaderOffset + 68);
    const dllCharacteristics = buffer.readUInt16LE(optionalHeaderOffset + 70);
    const sizeOfImage = buffer.readUInt32LE(optionalHeaderOffset + 56);
    const sizeOfHeaders = buffer.readUInt32LE(optionalHeaderOffset + 60);
    const numberOfRvaAndSizes = buffer.readUInt32LE(optionalHeaderOffset + (isPe32Plus ? 108 : 92));
    const dataDirectoryOffset = optionalHeaderOffset + (isPe32Plus ? 112 : 96);
    const importDirectoryRva = numberOfRvaAndSizes >= 2 ? buffer.readUInt32LE(dataDirectoryOffset + 8) : 0;
    const sectionTableOffset = optionalHeaderOffset + sizeOfOptionalHeader;

    const sections = [];
    for (let sectionIndex = 0; sectionIndex < numberOfSections; sectionIndex += 1) {
      const offset = sectionTableOffset + sectionIndex * SECTION_HEADER_SIZE;
      if (offset + SECTION_HEADER_SIZE > buffer.length) {
        break;
      }

      const rawName = clampSlice(buffer, offset, 8);
      const nullTerminator = rawName.indexOf(0);
      const name = rawName.subarray(0, nullTerminator === -1 ? rawName.length : nullTerminator).toString('ascii') || `section_${sectionIndex}`;
      const virtualSize = buffer.readUInt32LE(offset + 8);
      const virtualAddress = buffer.readUInt32LE(offset + 12);
      const rawSize = buffer.readUInt32LE(offset + 16);
      const rawPointer = buffer.readUInt32LE(offset + 20);
      const characteristics = buffer.readUInt32LE(offset + 36);
      const rawBytes = clampSlice(buffer, rawPointer, rawSize);

      sections.push({
        name,
        virtualSize,
        virtualAddress,
        rawSize,
        rawPointer,
        entropy: Number(computeEntropy(rawBytes).toFixed(3)),
        characteristics: decodeFlags(characteristics, SECTION_CHARACTERISTICS),
      });
    }

    const imports = parseImports({
      buffer,
      sections,
      importDirectoryRva,
      isPe32Plus,
    });
    const entryPointOffset = rvaToOffset(entryPointRva, sections);
    const entryPointBytes = entryPointOffset === null
      ? ''
      : clampSlice(buffer, entryPointOffset, 32).toString('hex').replace(/(..)/g, '$1 ').trim();

    return {
      format,
      machine: MACHINE_NAMES[machine] || hex(machine),
      compileTimestamp: timeDateStamp ? new Date(timeDateStamp * 1000).toISOString() : null,
      subsystem: SUBSYSTEM_NAMES[subsystem] || hex(subsystem),
      imageBase,
      entryPointRva: hex(entryPointRva),
      entryPointOffset: entryPointOffset === null ? null : hex(entryPointOffset),
      entryPointBytes,
      sizeOfImage,
      sizeOfHeaders,
      dllCharacteristics: hex(dllCharacteristics),
      characteristics: decodeFlags(characteristicsValue, COFF_CHARACTERISTICS),
      sections,
      imports,
    };
  } catch {
    return null;
  }
};
