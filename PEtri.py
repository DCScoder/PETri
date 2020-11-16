###################################################################################
#
#    Script:    PETri.py
#    Version:   1.0
#    Author:    Dan Saunders
#    Contact:   dcscoder@gmail.com
#    Purpose:   Portable Executable (PE) Triage
#    Usage:     python PETri.py <binary>
#    Reference: https://docs.microsoft.com/en-us/windows/win32/debug/pe-format
#
#    This program is free software: you can redistribute it and / or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program. If not, see <https://www.gnu.org/licenses/>.
#
###################################################################################

import sys
import os
import datetime
import time
import re
import hashlib
import pefile
import hexdump

__version__ = 'v1.0'
__author__ = 'Dan Saunders'
__email__ = 'dcscoder@gmail.com'

# Arguments
source = sys.argv[1]

# PE Signature
def check_signature(binary):
    sig = b'\x4d\x5a'
    f = open(binary, "rb")
    header = f.read(2)
    result = re.match(sig, header)
    if result:
        return True
    else:
        return False

# UNIX-10 Converter
def UNIX10(timestamp):
    return datetime.datetime.utcfromtimestamp(timestamp).strftime("%a %d %B %Y %H:%M:%S")

# Magic
magic_no = {0x10b:"32-bit", 0x20b:"64-bit", 0x107:"ROM Image"}

# CPU
cpu = {0x0:"Unknown", 0x1d3:"AM33", 0x8664:"AMD64", 0x1c0:"ARM", 0xaa64:"ARM64", 0x1c4:"ARMNT", 0xebc:"EBC",
       0x14c:"I386", 0x200:"IA64", 0x9041:"M32R", 0x266:"MIPS16", 0x366:"MIPSFPU", 0x466:"MIPSFPU16",
       0x1f0:"POWERPC", 0x1f1:"POWERPCFP", 0x166:"R4000", 0x5032:"RISCV32", 0x5064:"RISCV64", 0x5128:"RISCV128",
       0x1a2:"SH3", 0x1a3:"SH3DSP", 0x1a6:"SH4", 0x1a8:"SH5", 0x1c2:"THUMB", 0x169:"WCEMIPSV2"}

# Subsystem
subsystem = {0:"Unknown", 1:"Native", 2:"Windows GUI", 3:"Windows CUI", 5:"OS/2 CUI", 7:"Posix CUI", 8:"Win9x",
             9:"Windows CE GUI", 10:"EFI Application", 11:"EFI Boot Service Driver", 12:"EFI Runtime Service Driver",
             13:"EFI ROM", 14:"Xbox", 16:"Windows Boot Application"}

# DLL Characteristics
dllchar = {0x0000:"Unknown", 0x0001:"Reserved", 0x0002:"Reserved", 0x0004:"Reserved", 0x0008:"Reserved",
           0x0020:"High-Entropy Virtual Address", 0x0040:"Dynamic Base", 0x0080:"Force Integrity", 0x0100:"NX Compatible",
           0x0200:"No Isolation", 0x0400:"No Structured Expression", 0x0800:"Do not bind Image", 0x1000:"AppContainer Execution",
           0x2000:"WDM Driver", 0x4000:"Control Flow Guard", 0x8000:"Terminal Server Aware"}

# Main
def main():
    print("\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
    print("PETri.py " + __version__ + " Author: " + __author__ + " " + __email__)
    print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")

    print("\nScript initialised...")

    # Binary
    binary = source
    name = os.path.basename(binary)

    # File Signature Check
    result = check_signature(binary)
    if result == True:
        print("\nFile signature match for PE binary, proceeding with analysis...")
    else:
        sys.exit("\nFile is not a PE binary, terminating analysis.")

    # Read Data
    f = open(binary, "rb")
    data = f.read()
    size = len(data)
    # Header
    fh = open(binary, "rb")
    header = fh.read(256)
    # For PE
    pe = pefile.PE(binary)

    # Report
    out = os.path.join("PETri_" + time.strftime("%Y%m%d_%H%M%S") + "_" + name + ".txt")
    report = open(out, "w")
    report.write("~" * 53)
    report.write("\nPETri.py " + __version__ + " Author: " + __author__ + " " + __email__ + "\n")
    report.write("~" * 53)

    # Basic
    report.write("\n\n########## Metadata ##########\n\n")
    report.write("File Name:          " + name + "\n")
    report.write("File Size:          " + str(size) + " bytes" + "\n")

    # PE Header
    report.write("\n########## PE Header ##########\n\n")
    hd = pe.DOS_HEADER.e_magic
    if hex(hd == '0x5a4d'):
        h = "0x5a4d (MZ)"
    else:
        h = "Unknown"
    report.write("DOS Header:         " + h + "\n")
    sig = pe.NT_HEADERS.Signature
    if hex(sig == '0x4550'):
        s = "0x4550 (PE)"
    else:
        s = "Unknown"
    report.write("NT Header:          " + s + "\n")
    hdr = (hexdump.hexdump(header, result='return'))
    report.write("\n" + hdr + "\n")

    # File Properties
    report.write("\n########## File Properties ##########\n\n")
    if hasattr(pe, 'VS_VERSIONINFO'):
        if hasattr(pe, 'FileInfo'):
            for fi in pe.FileInfo:
                for entry in fi:
                    if hasattr(entry, 'StringTable'):
                        for st_entry in entry.StringTable:
                            for entry in st_entry.entries.items():
                                report.write(str(entry[0].decode('utf-8')) + " -> "
                                             + (str(entry[1].decode('utf-8')) + "\n"))
    else:
        report.write("No file properties identified.\n")

    # Hashing
    h1 = hashlib.md5()
    h2 = hashlib.sha1()
    h3 = hashlib.sha256()
    h4 = hashlib.sha512()
    h1.update(data)
    h2.update(data)
    h3.update(data)
    h4.update(data)
    md5 = h1.hexdigest()
    sha1 = h2.hexdigest()
    sha256 = h3.hexdigest()
    sha512 = h4.hexdigest()
    imphash = pe.get_imphash()
    report.write("\n########## Hash Values ##########\n\n")
    report.write("MD5:                " + md5 + "\n")
    report.write("SHA1:               " + sha1 + "\n")
    report.write("SHA256:             " + sha256 + "\n")
    report.write("SHA512:             " + sha512 + "\n")
    report.write("Imphash:            " + imphash + "\n")

    # COFF File Header (Object and Image)
    report.write("\n########## COFF File Header ##########\n\n")
    dll = pe.FILE_HEADER.IMAGE_FILE_DLL
    if dll == 1:
        d = "Yes"
    else:
        d = "No"
    report.write("Is DLL?:            " + d + "\n")
    machine = pe.FILE_HEADER.Machine
    report.write("Target Machine:     " + cpu.get(machine) + "\n")
    sections = pe.FILE_HEADER.NumberOfSections
    report.write("No of Sections:     " + (str(sections)) + "\n")
    compiled = pe.FILE_HEADER.TimeDateStamp
    report.write("Compiled Date:      " + UNIX10(compiled) + "\n")
    symbol_table = pe.FILE_HEADER.PointerToSymbolTable
    report.write("Sym Table Pointer:  " + (hex(symbol_table)) + "\n")
    no_symbols = pe.FILE_HEADER.NumberOfSymbols
    report.write("No of Symbols:      " + (str(no_symbols)) + "\n")
    op_header_size = pe.FILE_HEADER.SizeOfOptionalHeader
    report.write("Opt. Header Size:   " + (str(op_header_size)) + " bytes" + "\n")
    characteristics = pe.FILE_HEADER.Characteristics
    report.write("Characteristics:    " + (hex(characteristics)) + "\n")

    # Optional Header Standard Fields (Image Only)
    report.write("\n########## Optional File Header ##########\n\n")
    mag = pe.OPTIONAL_HEADER.Magic
    report.write("Magic:              " + magic_no.get(mag) + "\n")
    malv = pe.OPTIONAL_HEADER.MajorLinkerVersion
    report.write("Major Link Version: " + str(malv) + "\n")
    milv = pe.OPTIONAL_HEADER.MinorLinkerVersion
    report.write("Minor Link Version: " + str(milv) + "\n")
    text_section_size = pe.OPTIONAL_HEADER.SizeOfCode
    report.write("Code Size:          " + str(text_section_size) + " bytes" + "\n")
    soid = pe.OPTIONAL_HEADER.SizeOfInitializedData
    report.write("Initialised Size:   " + str(soid) + " bytes" + "\n")
    soud = pe.OPTIONAL_HEADER.SizeOfUninitializedData
    report.write("Uninitialised Size: " + str(soud) + " bytes" + "\n")
    entry = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    report.write("Entry Pointer:      " + hex(entry) + "\n")
    # Optional Header - Extension Fields (Image Only)
    report.write("-" * 35 + "\n")
    boc = pe.OPTIONAL_HEADER.BaseOfCode
    report.write("Base of Code:       " + hex(boc) + "\n")
    try:
        bod = pe.OPTIONAL_HEADER.BaseOfData
        report.write("Base of Data:       " + hex(bod) + "\n")
    except:
        report.write("Base of Data:       " + "No BaseOfData field.\n")
    ib = pe.OPTIONAL_HEADER.ImageBase
    report.write("Image Base:         " + hex(ib) + "\n")
    sa = pe.OPTIONAL_HEADER.SectionAlignment
    report.write("Section Alignment:  " + hex(sa) + "\n")
    fa = pe.OPTIONAL_HEADER.FileAlignment
    report.write("File Alignment:     " + hex(fa) + "\n")
    maosv = pe.OPTIONAL_HEADER.MajorOperatingSystemVersion
    report.write("Major OS Version:   " + str(maosv) + "\n")
    miosv = pe.OPTIONAL_HEADER.MinorOperatingSystemVersion
    report.write("Minor OS Version:   " + str(miosv) + "\n")
    maiv = pe.OPTIONAL_HEADER.MajorImageVersion
    report.write("Major Img Version:  " + str(maiv) + "\n")
    miiv = pe.OPTIONAL_HEADER.MinorImageVersion
    report.write("Minor OS Version:   " + str(miiv) + "\n")
    massv = pe.OPTIONAL_HEADER.MajorSubsystemVersion
    report.write("Major Sub Version:  " + str(massv) + "\n")
    missv = pe.OPTIONAL_HEADER.MinorSubsystemVersion
    report.write("Minor Sub Version:  " + str(missv) + "\n")
    w32v = pe.OPTIONAL_HEADER.Reserved1
    report.write("Win32 Version:      " + str(w32v) + "\n")
    soi = pe.OPTIONAL_HEADER.SizeOfImage
    report.write("Size of Image:      " + str(soi) + " bytes" + "\n")
    soh = pe.OPTIONAL_HEADER.SizeOfHeaders
    report.write("Size of Headers:    " + str(soh) + " bytes" + "\n")
    csum = pe.OPTIONAL_HEADER.CheckSum
    report.write("CheckSum:           " + hex(csum) + "\n")
    ss = pe.OPTIONAL_HEADER.Subsystem
    report.write("Subsystem:          " + subsystem.get(ss) + "\n")
    dllc = pe.OPTIONAL_HEADER.DllCharacteristics
    if dllchar.get(dllc) is not None:
        report.write("DllCharacteristics: " + dllchar.get(dllc) + "\n")
    else:
        report.write("DllCharacteristics: " + str(dllc) + " - Unknown DLL Characteristic.\n")
    sosr = pe.OPTIONAL_HEADER.SizeOfStackReserve
    report.write("Size of Stack Res:  " + str(sosr) + " bytes" + "\n")
    sosc = pe.OPTIONAL_HEADER.SizeOfStackCommit
    report.write("Size of Stack Com:  " + str(sosc) + " bytes" + "\n")
    sohr = pe.OPTIONAL_HEADER.SizeOfHeapReserve
    report.write("Size of Heap Res:   " + str(sohr) + " bytes" + "\n")
    sohc = pe.OPTIONAL_HEADER.SizeOfHeapCommit
    report.write("Size of Heap Com:   " + str(sohc) + " bytes" + "\n")
    lf = pe.OPTIONAL_HEADER.LoaderFlags
    report.write("Loader Flags:       " + str(lf) + "\n")
    nors = pe.OPTIONAL_HEADER.NumberOfRvaAndSizes
    report.write("No of Rva & Sizes:  " + str(nors) + "\n")
    
    # Sections
    report.write("\n########## Sections ##########\n")
    for section in pe.sections:
        report.write("\nSection Name:       " + section.Name.decode('utf-8'))
        report.write("\nVirtual Address:    " + hex(section.VirtualAddress))
        report.write("\nVirtual Size:       " + str(section.Misc_VirtualSize) + " bytes")
        report.write("\nPointer to Raw:     " + hex(section.PointerToRawData))
        report.write("\nRaw Size:           " + str(section.SizeOfRawData) + " bytes")
        report.write("\nEntropy:            " + str(section.get_entropy()))
        report.write("\nMD5:                " + str(section.get_hash_md5()))
        report.write("\nSHA1:               " + str(section.get_hash_sha1()))
        report.write("\nSHA256:             " + str(section.get_hash_sha256()))
        report.write("\nSHA512:             " + str(section.get_hash_sha512()) + "\n")

    # Data Directories
    report.write("\n########## Data Directories ##########\n")
    for dir in pe.OPTIONAL_HEADER.DATA_DIRECTORY:
        report.write("\nDirectory Name:     " + str(dir.name))
        report.write("\nVirtual Address:    " + hex(dir.VirtualAddress))
        report.write("\nSize:               " + str(dir.Size) + " bytes")
        report.write("\n")

    # Imports
    report.write("\n########## Imports ##########\n")
    try:
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            report.write("\n" + entry.dll.decode('utf-8') + "\n")
            for im in entry.imports:
                report.write("------------ Offset: " + hex(im.address) + " | Import: " + im.name.decode('utf-8') + "\n")
    except:
        report.write("\nNo import symbols identified.\n")

    # Exports
    report.write("\n########## Exports ##########\n")
    try:
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            report.write("\n------------ Offset: " + hex(pe.OPTIONAL_HEADER.ImageBase + exp.address) + " | Export: " + str(exp.name.decode('utf-8')))

    except:
        report.write("\nNo export symbols identified.\n")

    print("\nAnalysis completed!")

if __name__ == "__main__":
    main()
