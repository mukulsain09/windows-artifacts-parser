# parsers/prefetch_impl.py
# Improved Prefetch parser (backward compatible)
# Produces pf.parsed dict with run_count, run_times (ISO-Z), exe, pref_hash, files_count, files_sample, volumes_count, volumes.

import os
import ntpath
import struct
import tempfile
import json
from datetime import datetime, timezone, timedelta

# Optional decompressor support (kept optional)
try:
    from windowsprefetch.utils import DecompressWin10
except Exception:
    DecompressWin10 = None

def filetime_to_datetime(ft):
    try:
        if not ft or ft == 0:
            return None
        us = ft // 10
        return datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=us)
    except Exception:
        return None

def filetime_to_iso(ft):
    dt = filetime_to_datetime(ft)
    if dt is None:
        return None
    iso = dt.isoformat()
    if iso.endswith("+00:00"):
        iso = iso.replace("+00:00", "Z")
    return iso

def safe_decode_utf16le(raw_bytes):
    try:
        if raw_bytes is None:
            return None
        if isinstance(raw_bytes, str):
            return raw_bytes
        s = raw_bytes.decode("utf-16le", errors="ignore")
        return s.split("\x00", 1)[0]
    except Exception:
        return None

def extract_run_times_from_bytes(lastRunTime_bytes):
    timestamps = []
    if not lastRunTime_bytes:
        return timestamps
    for i in range(0, len(lastRunTime_bytes), 8):
        block = lastRunTime_bytes[i:i+8]
        if len(block) < 8:
            break
        try:
            ft = int.from_bytes(block, byteorder="little", signed=False)
        except Exception:
            continue
        if ft and ft != 0:
            iso = filetime_to_iso(ft)
            if iso:
                timestamps.append(iso)
    return timestamps

class Prefetch(object):
    """
    Improved Prefetch parser wrapper based on the Poor Billionaire implementation.
    Exposes pf.parsed (dict) with keys:
      version, exe, pref_hash, run_count, run_times, files_count, files_sample, volumes_count, volumes
    """

    def __init__(self, infile):
        self.pFileName = infile
        self.version = None
        self.executableName = None
        self.hash = None
        self.runCount = None
        self.lastRunTime = None
        self.timestamps = []
        self.filenames = b""
        self.resources = []
        self.volumesInformationArray = []
        self.directoryStringsArray = []
        self.parsed = {}

        try:
            with open(infile, "rb") as f:
                head = f.read(3)
                if head and head.decode("ASCII", errors="ignore") == "MAM":
                    if DecompressWin10 is not None:
                        try:
                            d = DecompressWin10()
                            decompressed = d.decompress(infile)
                            fd, path = tempfile.mkstemp()
                            os.close(fd)
                            with open(path, "wb+") as tf:
                                tf.write(decompressed)
                                tf.seek(0)
                                self._parse_from_filehandle(tf)
                            try:
                                os.remove(path)
                            except Exception:
                                pass
                            self.parsed = self.to_dict()
                            return
                        except Exception:
                            pass
                f.seek(0)
                self._parse_from_filehandle(f)
        except Exception as e:
            self.parsed = {"error": f"open_failed: {e}", "path": infile}
            return

        try:
            self.parsed = self.to_dict()
        except Exception:
            self.parsed = {}

    def _parse_from_filehandle(self, f):
        self.parseHeader(f)
        try:
            if self.version == 17:
                self.fileInformation17(f)
                self.metricsArray17(f)
                self.traceChainsArray17(f)
                self.volumeInformation17(f)
                if hasattr(self, "lastRunTime") and isinstance(self.lastRunTime, (bytes, bytearray)):
                    self.timestamps = extract_run_times_from_bytes(self.lastRunTime)
                self.directoryStrings(f)
            elif self.version == 23:
                self.fileInformation23(f)
                self.metricsArray23(f)
                self.traceChainsArray17(f)
                self.volumeInformation23(f)
                if hasattr(self, "lastRunTime") and isinstance(self.lastRunTime, (bytes, bytearray)):
                    self.timestamps = extract_run_times_from_bytes(self.lastRunTime)
                self.directoryStrings(f)
            elif self.version == 26:
                self.fileInformation26(f)
                self.metricsArray23(f)
                self.traceChainsArray17(f)
                try:
                    self.volumeInformation23(f)
                except Exception:
                    try:
                        self.volumeInformation30(f)
                    except Exception:
                        pass
                if hasattr(self, "lastRunTime") and isinstance(self.lastRunTime, (bytes, bytearray)):
                    self.timestamps = extract_run_times_from_bytes(self.lastRunTime)
                self.directoryStrings(f)
            else:
                try:
                    self.fileInformation26(f)
                    try:
                        self.metricsArray23(f)
                    except Exception:
                        pass
                    try:
                        self.traceChainsArray30(f)
                    except Exception:
                        try:
                            self.traceChainsArray17(f)
                        except Exception:
                            pass
                    try:
                        self.volumeInformation30(f)
                    except Exception:
                        try:
                            self.volumeInformation23(f)
                        except Exception:
                            pass
                    if hasattr(self, "lastRunTime") and isinstance(self.lastRunTime, (bytes, bytearray)):
                        self.timestamps = extract_run_times_from_bytes(self.lastRunTime)
                    self.directoryStrings(f)
                except Exception:
                    try:
                        self.getFilenameStrings(f)
                    except Exception:
                        pass
        except Exception:
            pass

        try:
            self.getFilenameStrings(f)
        except Exception:
            pass

    def parseHeader(self, infile):
        try:
            self.version = int.from_bytes(infile.read(4), byteorder="little", signed=False)
            self.signature = int.from_bytes(infile.read(4), byteorder="little", signed=False)
            _unknown0 = int.from_bytes(infile.read(4), byteorder="little", signed=False)
            self.fileSize = int.from_bytes(infile.read(4), byteorder="little", signed=False)
            rawexe = infile.read(60)
            self.executableName = safe_decode_utf16le(rawexe)
            rawhash_bytes = infile.read(4)
            if rawhash_bytes and len(rawhash_bytes) == 4:
                self.hash = hex(int.from_bytes(rawhash_bytes, byteorder="little", signed=False)).lstrip("0x").rstrip("L")
            else:
                self.hash = None
            _unknown1 = infile.read(4)
        except Exception:
            try:
                infile.seek(0)
            except Exception:
                pass

    def fileInformation17(self, infile):
        try:
            self.metricsOffset = int.from_bytes(infile.read(4), byteorder="little", signed=False)
            self.metricsCount = int.from_bytes(infile.read(4), byteorder="little", signed=False)
            self.traceChainsOffset = int.from_bytes(infile.read(4), byteorder="little", signed=False)
            self.traceChainsCount = int.from_bytes(infile.read(4), byteorder="little", signed=False)
            self.filenameStringsOffset = int.from_bytes(infile.read(4), byteorder="little", signed=False)
            self.filenameStringsSize = int.from_bytes(infile.read(4), byteorder="little", signed=False)
            self.volumesInformationOffset = int.from_bytes(infile.read(4), byteorder="little", signed=False)
            self.volumesCount = int.from_bytes(infile.read(4), byteorder="little", signed=False)
            self.volumesInformationSize = int.from_bytes(infile.read(4), byteorder="little", signed=False)
            self.lastRunTime = infile.read(8)
            _unknown0 = infile.read(16)
            self.runCount = int.from_bytes(infile.read(4), byteorder="little", signed=False)
            _unknown1 = infile.read(4)
        except Exception:
            pass

    def metricsArray17(self, infile):
        try:
            _unknown0 = infile.read(4)
            _unknown1 = infile.read(4)
            self.filenameOffset = int.from_bytes(infile.read(4), byteorder="little", signed=False)
            self.filenameLength = int.from_bytes(infile.read(4), byteorder="little", signed=False)
            _unknown2 = infile.read(4)
        except Exception:
            pass

    def traceChainsArray17(self, infile):
        try:
            infile.read(12)
        except Exception:
            pass

    def volumeInformation17(self, infile):
        try:
            infile.seek(self.volumesInformationOffset)
        except Exception:
            return
        self.volumesInformationArray = []
        self.directoryStringsArray = []
        count = 0
        while count < getattr(self, "volumesCount", 0):
            try:
                self.volPathOffset = int.from_bytes(infile.read(4), byteorder="little", signed=False)
                self.volPathLength = int.from_bytes(infile.read(4), byteorder="little", signed=False)
                self.volCreationTime = int.from_bytes(infile.read(8), byteorder="little", signed=False)
                self.volSerialNumber = hex(int.from_bytes(infile.read(4), byteorder="little", signed=False)).rstrip("L").lstrip("0x")
                self.fileRefOffset = int.from_bytes(infile.read(4), byteorder="little", signed=False)
                self.fileRefSize = int.from_bytes(infile.read(4), byteorder="little", signed=False)
                self.dirStringsOffset = int.from_bytes(infile.read(4), byteorder="little", signed=False)
                self.dirStringsCount = int.from_bytes(infile.read(4), byteorder="little", signed=False)
                unknown0 = infile.read(4)
                try:
                    self.directoryStringsArray.append(self.directoryStrings(infile))
                except Exception:
                    self.directoryStringsArray.append([])
                try:
                    infile.seek(self.volumesInformationOffset + self.volPathOffset)
                    rawname = infile.read(self.volPathLength * 2)
                    volname = safe_decode_utf16le(rawname)
                except Exception:
                    volname = None
                volume = {
                    "Volume Name": volname,
                    "Creation Date": filetime_to_iso(self.volCreationTime) if getattr(self, "volCreationTime", None) else None,
                    "Serial Number": self.volSerialNumber
                }
                self.volumesInformationArray.append(volume)
            except Exception:
                break
            count += 1
            try:
                infile.seek(self.volumesInformationOffset + (40 * count))
            except Exception:
                break

    def fileInformation23(self, infile):
        try:
            self.metricsOffset = int.from_bytes(infile.read(4), byteorder="little", signed=False)
            self.metricsCount = int.from_bytes(infile.read(4), byteorder="little", signed=False)
            self.traceChainsOffset = int.from_bytes(infile.read(4), byteorder="little", signed=False)
            self.traceChainsCount = int.from_bytes(infile.read(4), byteorder="little", signed=False)
            self.filenameStringsOffset = int.from_bytes(infile.read(4), byteorder="little", signed=False)
            self.filenameStringsSize = int.from_bytes(infile.read(4), byteorder="little", signed=False)
            self.volumesInformationOffset = int.from_bytes(infile.read(4), byteorder="little", signed=False)
            self.volumesCount = int.from_bytes(infile.read(4), byteorder="little", signed=False)
            self.volumesInformationSize = int.from_bytes(infile.read(4), byteorder="little", signed=False)
            unknown0 = infile.read(8)
            self.lastRunTime = infile.read(8)
            unknown1 = infile.read(16)
            self.runCount = int.from_bytes(infile.read(4), byteorder="little", signed=False)
            unknown2 = infile.read(84)
        except Exception:
            pass

    def metricsArray23(self, infile):
        try:
            infile.seek(self.metricsOffset)
            unknown0 = infile.read(4)
            unknown1 = infile.read(4)
            unknown2 = infile.read(4)
            self.filenameOffset = int.from_bytes(infile.read(4), byteorder="little", signed=False)
            self.filenameLength = int.from_bytes(infile.read(4), byteorder="little", signed=False)
            unknown3 = infile.read(4)
            mftref = infile.read(8)
            try:
                self.mftSeqNumber, self.mftEntryNumber = self.convertFileReference(mftref)
            except Exception:
                self.mftSeqNumber, self.mftEntryNumber = None, None
        except Exception:
            pass

    def volumeInformation23(self, infile):
        try:
            infile.seek(self.volumesInformationOffset)
        except Exception:
            return
        self.volumesInformationArray = []
        self.directoryStringsArray = []
        count = 0
        while count < getattr(self, "volumesCount", 0):
            try:
                self.volPathOffset = int.from_bytes(infile.read(4), byteorder="little", signed=False)
                self.volPathLength = int.from_bytes(infile.read(4), byteorder="little", signed=False)
                self.volCreationTime = int.from_bytes(infile.read(8), byteorder="little", signed=False)
                volSerialNumber = hex(int.from_bytes(infile.read(4), byteorder="little", signed=False))
                self.volSerialNumber = volSerialNumber.rstrip("L").lstrip("0x")
                self.fileRefOffset = int.from_bytes(infile.read(4), byteorder="little", signed=False)
                self.fileRefCount = int.from_bytes(infile.read(4), byteorder="little", signed=False)
                self.dirStringsOffset = int.from_bytes(infile.read(4), byteorder="little", signed=False)
                self.dirStringsCount = int.from_bytes(infile.read(4), byteorder="little", signed=False)
                unknown0 = infile.read(68)
                try:
                    self.directoryStringsArray.append(self.directoryStrings(infile))
                except Exception:
                    self.directoryStringsArray.append([])
                try:
                    infile.seek(self.volumesInformationOffset + self.volPathOffset)
                    rawname = infile.read(self.volPathLength * 2)
                    volname = safe_decode_utf16le(rawname)
                except Exception:
                    volname = None
                volume = {
                    "Volume Name": volname,
                    "Creation Date": filetime_to_iso(self.volCreationTime) if getattr(self, "volCreationTime", None) else None,
                    "Serial Number": self.volSerialNumber
                }
                self.volumesInformationArray.append(volume)
            except Exception:
                break
            count += 1
            try:
                infile.seek(self.volumesInformationOffset + (104 * count))
            except Exception:
                break

    def fileInformation26(self, infile):
        try:
            self.metricsOffset = int.from_bytes(infile.read(4), byteorder="little", signed=False)
            self.metricsCount = int.from_bytes(infile.read(4), byteorder="little", signed=False)
            self.traceChainsOffset = int.from_bytes(infile.read(4), byteorder="little", signed=False)
            self.traceChainsCount = int.from_bytes(infile.read(4), byteorder="little", signed=False)
            self.filenameStringsOffset = int.from_bytes(infile.read(4), byteorder="little", signed=False)
            self.filenameStringsSize = int.from_bytes(infile.read(4), byteorder="little", signed=False)
            self.volumesInformationOffset = int.from_bytes(infile.read(4), byteorder="little", signed=False)
            self.volumesCount = int.from_bytes(infile.read(4), byteorder="little", signed=False)
            self.volumesInformationSize = int.from_bytes(infile.read(4), byteorder="little", signed=False)
            unknown0 = infile.read(8)
            self.lastRunTime = infile.read(64)
            unknown1 = infile.read(16)
            self.runCount = int.from_bytes(infile.read(4), byteorder="little", signed=False)
            unknown2 = infile.read(96)
        except Exception:
            pass

    def traceChainsArray30(self, infile):
        try:
            infile.read(8)
        except Exception:
            pass

    def volumeInformation30(self, infile):
        try:
            infile.seek(self.volumesInformationOffset)
        except Exception:
            return
        self.volumesInformationArray = []
        self.directoryStringsArray = []
        count = 0
        while count < getattr(self, "volumesCount", 0):
            try:
                self.volPathOffset = int.from_bytes(infile.read(4), byteorder="little", signed=False)
                self.volPathLength = int.from_bytes(infile.read(4), byteorder="little", signed=False)
                self.volCreationTime = int.from_bytes(infile.read(8), byteorder="little", signed=False)
                self.volSerialNumber = hex(int.from_bytes(infile.read(4), byteorder="little", signed=False)).rstrip("L").lstrip("0x")
                self.fileRefOffset = int.from_bytes(infile.read(4), byteorder="little", signed=False)
                self.fileRefCount = int.from_bytes(infile.read(4), byteorder="little", signed=False)
                self.dirStringsOffset = int.from_bytes(infile.read(4), byteorder="little", signed=False)
                self.dirStringsCount = int.from_bytes(infile.read(4), byteorder="little", signed=False)
                unknown0 = infile.read(60)
                try:
                    self.directoryStringsArray.append(self.directoryStrings(infile))
                except Exception:
                    self.directoryStringsArray.append([])
                try:
                    infile.seek(self.volumesInformationOffset + self.volPathOffset)
                    rawname = infile.read(self.volPathLength * 2)
                    volname = safe_decode_utf16le(rawname)
                except Exception:
                    volname = None
                volume = {
                    "Volume Name": volname,
                    "Creation Date": filetime_to_iso(self.volCreationTime) if getattr(self, "volCreationTime", None) else None,
                    "Serial Number": self.volSerialNumber
                }
                self.volumesInformationArray.append(volume)
            except Exception:
                break
            count += 1
            try:
                infile.seek(self.volumesInformationOffset + (96 * count))
            except Exception:
                break

    def getFilenameStrings(self, infile):
        try:
            if not hasattr(self, "filenameStringsOffset") or not hasattr(self, "filenameStringsSize"):
                return
            infile.seek(self.filenameStringsOffset)
            self.filenames = infile.read(self.filenameStringsSize)
            try:
                decoded = self.filenames.decode("utf-16le", errors="ignore")
                self.resources = [r for r in decoded.split("\x00") if r]
            except Exception:
                self.resources = []
        except Exception:
            self.resources = []

    def convertTimestamp(self, timestamp):
        return filetime_to_iso(timestamp)

    def getTimeStamps(self, lastRunTime):
        try:
            if isinstance(lastRunTime, (bytes, bytearray)):
                self.timestamps = extract_run_times_from_bytes(lastRunTime)
            else:
                self.timestamps = []
        except Exception:
            self.timestamps = []

    def directoryStrings(self, infile):
        try:
            infile.seek(self.volumesInformationOffset)
        except Exception:
            return []
        try:
            infile.seek(self.dirStringsOffset, 1)
        except Exception:
            return []
        directoryStrings = []
        count = 0
        while count < getattr(self, "dirStringsCount", 0):
            try:
                raw = infile.read(2)
                if not raw or len(raw) < 2:
                    break
                stringLength_words = int.from_bytes(raw, byteorder="little", signed=False)
                stringLength_bytes = stringLength_words * 2 + 2
                rawstr = infile.read(stringLength_bytes)
                directoryStrings.append(safe_decode_utf16le(rawstr))
            except Exception:
                break
            count += 1
        return directoryStrings

    def convertFileReference(self, buf):
        try:
            sequenceNumber = int.from_bytes(buf[-2:], byteorder="little")
            entryNumber = int.from_bytes(buf[0:6], byteorder="little")
            return sequenceNumber, entryNumber
        except Exception:
            return None, None

    def prettyPrint(self):
        banner = "=" * (len(ntpath.basename(self.pFileName)) + 2)
        print("\n{0}\n{1}\n{0}\n".format(banner, ntpath.basename(self.pFileName)))
        print("Executable Name: {}\n".format(self.executableName))
        print("Run count: {}\n".format(self.runCount))
        if getattr(self, "timestamps", None):
            if len(self.timestamps) > 1:
                print("Last Executed:")
                for timestamp in self.timestamps:
                    print("    " + timestamp)
            else:
                print("Last Executed: {}".format(self.timestamps[0] if self.timestamps else ""))
        else:
            print("Last Executed: (none)\n")
        print("\nVolume Information:")
        for i in self.volumesInformationArray:
            vname = i.get("Volume Name")
            if isinstance(vname, (bytes, bytearray)):
                vname = safe_decode_utf16le(vname)
            print("   Volume Name: " + (vname or ""))
            print("   Creation Date: " + str(i.get("Creation Date")))
            print("   Serial Number: " + str(i.get("Serial Number")))
            print()
        print("Directory Strings:")
        for volume in self.directoryStringsArray:
            for dirstring in enumerate(volume):
                print("{:>4}: {}".format(dirstring[0], dirstring[1]))
        print()
        print("Resources Loaded:")
        for resource in enumerate(self.resources):
            print("{:>4}: {}".format(resource[0], resource[1]))
        print()

    def to_dict(self, max_files_sample=200):
        run_times = []
        try:
            if getattr(self, "timestamps", None):
                run_times = list(self.timestamps)
            elif getattr(self, "lastRunTime", None):
                run_times = extract_run_times_from_bytes(self.lastRunTime)
        except Exception:
            run_times = []
        files_list = []
        try:
            if getattr(self, "resources", None):
                files_list = [r for r in self.resources if r]
        except Exception:
            files_list = []
        volumes = []
        try:
            if getattr(self, "volumesInformationArray", None):
                for v in self.volumesInformationArray:
                    vol_name = v.get("Volume Name")
                    if isinstance(vol_name, (bytes, bytearray)):
                        vol_name = safe_decode_utf16le(vol_name)
                    volumes.append({
                        "name": vol_name,
                        "creation_time": v.get("Creation Date"),
                        "serial": v.get("Serial Number")
                    })
        except Exception:
            volumes = []
        parsed = {
            "version": getattr(self, "version", None),
            "exe": getattr(self, "executableName", None),
            "pref_hash": getattr(self, "hash", None),
            "run_count": int(self.runCount) if self.runCount is not None else None,
            "run_times": run_times,
            "files_count": len(files_list),
            "files_sample": files_list[:max_files_sample],
            "volumes_count": len(volumes),
            "volumes": volumes
        }
        return parsed
