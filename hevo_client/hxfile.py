import struct
from dataclasses import dataclass

from .errors import HxError

VERSION_MAP = {
    "hx1.0": "V1_0",
    "hx1.1": "V1_1",
    "hx1.2": "V1_2",
    "hx1.3": "V1_3",
}

HX_HEAD_FORMAT = "<6sIIHHI"
HX_FIELD_FORMAT = "<IBBH"

@dataclass
class HxHead:
    version_string: bytes
    record_count: int
    size_with_padding: int
    single_record_length: int
    data_field_count: int
    extra_data_total_length: int

    @property
    def version(self):
        text = self.version_string.split(b"\x00", 1)[0].decode("ascii", "replace")
        return VERSION_MAP.get(text, "UnKnow")

@dataclass
class HxFieldInfo:
    field_id: int
    field_type: int
    field_format: int
    value_length: int

    @property
    def data_type(self):
        return self.field_type

class HexinMinuteTime:
    @staticmethod
    def get_offset(value, bit_index, bit_count):
        num = (value & 0xFFFFFFFF) >> bit_index
        num <<= 32 - bit_count
        return (num >> (32 - bit_count)) & 0xFFFFFFFF

    @staticmethod
    def try_to_unix_timestamp_int64(value):
        if value > 230000000:
            return value
        if value <= 0:
            return -1
        if value < 22000000:
            if value < 10000000:
                return value
            year = value // 10000
            month = (value // 100) % 100
            day = value % 100
            try:
                from datetime import datetime, timezone
                dt = datetime(year, month, day, tzinfo=timezone.utc).astimezone()
                epoch = datetime(1970, 1, 1, tzinfo=timezone.utc).astimezone()
                return int((dt.replace(tzinfo=None) - epoch.replace(tzinfo=None)).total_seconds())
            except ValueError:
                return value
        offset1 = HexinMinuteTime.get_offset(value, 0, 6)
        offset2 = HexinMinuteTime.get_offset(value, 6, 5)
        offset3 = HexinMinuteTime.get_offset(value, 11, 5)
        offset4 = HexinMinuteTime.get_offset(value, 16, 4)
        year = HexinMinuteTime.get_offset(value, 20, 8) + 1900
        try:
            from datetime import datetime, timezone
            dt = datetime(year, offset4, offset3, offset2, offset1, 0, tzinfo=timezone.utc)
            epoch = datetime(1970, 1, 1, 8, 0, 0, tzinfo=timezone.utc)
            return int((dt - epoch).total_seconds())
        except ValueError:
            return value

    @staticmethod
    def try_to_unix_timestamp_int32(value):
        return int(HexinMinuteTime.try_to_unix_timestamp_int64(value))


class HxFile:
    def __init__(self, data, offset, conversion):
        self.source_bytes = bytes(data)
        self.total_length_start = offset
        self.conversion = conversion
        self.is_candle_data = False
        self._total_length = None
        self._head = None
        self._field_infos = None
        self._decompressed = None
        self._version = None
        if self.total_length != 0:
            self.decompress()

    @property
    def total_length(self):
        if self._total_length is None:
            self._total_length = int.from_bytes(self.source_bytes[self.total_length_start:self.total_length_start + 4], "little")
        return self._total_length

    @property
    def is_bad(self):
        return self.total_length <= 0

    @property
    def head_start(self):
        return self.total_length_start + 4

    @property
    def version(self):
        if self._version is None:
            raw = self.source_bytes[self.head_start:self.head_start + 6]
            text = raw.split(b"\x00", 1)[0].decode("ascii", "replace")
            self._version = VERSION_MAP.get(text, "UnKnow")
        return self._version

    @property
    def is_compressed(self):
        return self.version != "V1_0"

    @property
    def original_bytes(self):
        if self.is_compressed:
            return self.decompressed_bytes
        return self.source_bytes

    @property
    def full_bytes(self):
        if self.is_compressed:
            return self.decompressed_bytes
        return self.source_bytes

    @property
    def decompressed_bytes(self):
        if not self.is_compressed:
            return self.source_bytes
        if self._decompressed is None:
            self.decompress()
        return self._decompressed

    @property
    def head(self):
        if self._head is None:
            raw = self.original_bytes[self.head_start:self.head_start + struct.calcsize(HX_HEAD_FORMAT)]
            unpacked = struct.unpack(HX_HEAD_FORMAT, raw)
            self._head = HxHead(
                version_string=unpacked[0],
                record_count=unpacked[1],
                size_with_padding=unpacked[2],
                single_record_length=unpacked[3],
                data_field_count=unpacked[4],
                extra_data_total_length=unpacked[5],
            )
        return self._head

    @property
    def field_infos_start(self):
        return self.head_start + struct.calcsize(HX_HEAD_FORMAT)

    @property
    def field_infos(self):
        if self._field_infos is None:
            count = self.head.data_field_count
            start = self.field_infos_start
            infos = []
            for i in range(count):
                raw = self.full_bytes[start + i * struct.calcsize(HX_FIELD_FORMAT):start + (i + 1) * struct.calcsize(HX_FIELD_FORMAT)]
                unpacked = struct.unpack(HX_FIELD_FORMAT, raw)
                infos.append(HxFieldInfo(
                    field_id=unpacked[0],
                    field_type=unpacked[1],
                    field_format=unpacked[2],
                    value_length=unpacked[3],
                ))
            self._field_infos = infos
        return self._field_infos

    @property
    def records_start(self):
        return self.field_infos_start + struct.calcsize(HX_FIELD_FORMAT) * self.head.data_field_count

    @property
    def extra_data_start(self):
        return self.head_start + self.head.size_with_padding + self.head.record_count * self.head.single_record_length

    def get_record_offset(self, n):
        return self.records_start + self.head.single_record_length * n

    def decompress(self):
        version = self.version
        if version == "V1_0":
            self._decompressed = self.source_bytes
            return
        if version == "V1_1":
            num = int(self.head.size_with_padding + 4)
            num2 = self.head_start + num
            unzipped = self.unzip3sharp(self.source_bytes, num2)
            prefix = self.source_bytes[:num2]
            self._decompressed = prefix + unzipped
            return
        if version in ("V1_2", "V1_3"):
            compressed = self.source_bytes[self.head_start + 6:self.head_start + 6 + (self.total_length - 6)]
            unzipped = snappy_decompress(compressed)
            prefix = self.source_bytes[:self.head_start + 6]
            self._decompressed = prefix + unzipped
            return
        raise HxError("bad hx version: " + str(version))

    @staticmethod
    def hxlong_to_double(value, conversion):
        if conversion == "AsPush":
            if value == 0x80000000:
                return float("nan")
            if value == 0xFFFFFFFF:
                return -1.7976931348623157e308
        if conversion == "AsResponse":
            if value in (0xFFFFFFFF, 0x80000000):
                return float("nan")
        num = value & 0x7FFFFFF
        sign = (value & 0x8000000) >> 27
        scale = (value & 0x70000000) >> 28
        divisor = (value & 0x80000000) >> 31
        multi = (10 ** scale)
        if divisor == 1:
            num = num / multi
        else:
            num = num * multi
        if sign == 1:
            num = -num
        return float(num)

    @staticmethod
    def parse_full_bytes_span(fi, offset, full_bytes, is_trail_detail_data, is_candle_data, conversion):
        span = full_bytes[offset:offset + fi.value_length]
        if fi.data_type == 1:
            if fi.field_id != 55 or (len(span) > 0 and span[0] == 255):
                value = span.decode("gbk", "replace")
            else:
                value = span.decode("utf-8", "replace")
        elif fi.data_type == 2:
            value_int = int.from_bytes(span[:4], "little")
            value = HxFile.hxlong_to_double(value_int, conversion)
        elif fi.data_type == 3:
            raw_int = int.from_bytes(span[:8], "little")
            if raw_int == 0x8000000000000000:
                value = None
            else:
                value = struct.unpack("<d", span[:8])[0]
        elif fi.data_type == 4:
            num = int.from_bytes(span[:4], "little", signed=True)
            unsigned = int.from_bytes(span[:4], "little")
            if fi.field_id == 1 and not is_trail_detail_data:
                if is_candle_data:
                    value = HexinMinuteTime.try_to_unix_timestamp_int64(num)
                else:
                    value = HexinMinuteTime.try_to_unix_timestamp_int32(num)
            elif fi.field_id == 56:
                value = HexinMinuteTime.try_to_unix_timestamp_int32(num)
            else:
                value = num
            if unsigned in (0x80000000, 0xFFFFFFFF):
                value = None
        else:
            value = span
        return (fi.field_id, value)

    def as_list(self, is_candle_data=False):
        self.is_candle_data = is_candle_data
        result = []
        num = self.get_record_offset(0)
        is_trail_detail_data = any(fi.field_id == 1 for fi in self.field_infos) and any(fi.field_id == 56 for fi in self.field_infos)
        for _ in range(self.head.record_count):
            row = {}
            for fi in self.field_infos:
                field_id, value = self.parse_full_bytes_span(fi, num, self.full_bytes, is_trail_detail_data, is_candle_data, self.conversion)
                row[field_id] = value
                num += fi.value_length
            result.append(row)
        return result

    def as_dic_list(self, is_multi_pack, result, code_indexs, time_indexs, is_candle_data, get_merge_index, merge):
        self.is_candle_data = is_candle_data
        num = self.get_record_offset(0)
        is_trail_detail_data = any(fi.field_id == 1 for fi in self.field_infos) and any(fi.field_id == 56 for fi in self.field_infos)
        for record_index in range(self.head.record_count):
            row = {}
            for fi in self.field_infos:
                field_id, value = self.parse_full_bytes_span(fi, num, self.full_bytes, is_trail_detail_data, is_candle_data, self.conversion)
                row[field_id] = value
                num += fi.value_length
            index = get_merge_index(is_multi_pack, code_indexs, time_indexs, record_index, row, len(result))
            merge(result, index, row)

    def extra_fields(self):
        if getattr(self, "_extra", None) is None:
            self._extra = self._create_extra()
        return self._extra

    def _create_extra(self):
        result = {}
        if self.head.extra_data_total_length == 0:
            return result
        num = self.extra_data_start
        end = self.extra_data_start + self.head.extra_data_total_length
        data = self.original_bytes
        while num < end:
            fi = HxFieldInfo(
                field_id=int.from_bytes(data[num:num + 4], "little"),
                field_type=data[num + 4],
                field_format=data[num + 5],
                value_length=int.from_bytes(data[num + 6:num + 8], "little"),
            )
            num += 8
            span = data[num:num + fi.value_length]
            num += fi.value_length
            if fi.data_type == 1:
                split = span.split(b"\x00", 1)[0]
                value = split.decode("gbk", "replace")
            elif fi.data_type == 2:
                value = self.hxlong_to_double(int.from_bytes(span[:4], "little"), self.conversion)
            elif fi.data_type == 3:
                raw_int = int.from_bytes(span[:8], "little")
                if raw_int == 0x8000000000000000:
                    value = None
                else:
                    value = struct.unpack("<d", span[:8])[0]
            elif fi.data_type == 4:
                num_value = int.from_bytes(span[:4], "little", signed=True)
                if fi.field_id in (1, 56):
                    value = HexinMinuteTime.try_to_unix_timestamp_int32(num_value)
                else:
                    value = num_value
            else:
                value = span
            result[fi.field_id] = value
        return result

    @staticmethod
    def unzip3sharp(source, index):
        source = bytes(source)
        ptr2 = index
        num = len(source) - index
        num2 = int.from_bytes(source[ptr2:ptr2 + 4], "big")
        array = bytearray(num2 + 1)
        ptr4 = ptr2 + 4
        ptr5 = 0
        ptr6 = num2
        cp = ptr4
        control = source[cp]
        cp += 1
        controlb = 8
        b = source[cp]
        cp += 1
        array[ptr5] = b
        ptr5 += 1

        def dec_get_control2():
            nonlocal control, controlb, cp, getbit
            getbit = control & 0x80
            control = (control << 1) & 0xFF
            controlb -= 1
            if controlb == 0:
                control = source[cp]
                cp += 1
                controlb = 8

        getbit = 0
        while ptr5 < ptr6:
            dec_get_control2()
            if getbit == 0:
                if ptr5 > ptr6:
                    return None
                array[ptr5] = source[cp]
                cp += 1
                ptr5 += 1
                if ptr5 > ptr6:
                    return None
                b = source[cp]
                cp += 1
                array[ptr5] = b
                ptr5 += 1
                continue
            dec_get_control2()
            if getbit == 0:
                if ptr5 > ptr6:
                    return None
                b = source[cp]
                cp += 1
            if ptr5 > ptr6:
                return None
            array[ptr5] = b
            ptr5 += 1
            dec_get_control2()
            if getbit == 0:
                continue
            if ptr5 > ptr6:
                return None
            array[ptr5] = b
            ptr5 += 1
            dec_get_control2()
            if getbit != 0:
                if ptr5 > ptr6:
                    return None
                array[ptr5] = b
                ptr5 += 1
                if ptr5 > ptr6:
                    return None
                array[ptr5] = b
                ptr5 += 1
                dec_get_control2()
                if getbit == 0:
                    continue
                if ptr5 > ptr6:
                    return None
                array[ptr5] = b
                ptr5 += 1
                dec_get_control2()
                if getbit != 0:
                    if ptr5 > ptr6:
                        return None
                    array[ptr5] = b
                    ptr5 += 1
                    if ptr5 > ptr6:
                        return None
                    array[ptr5] = b
                    ptr5 += 1
                    if ptr5 > ptr6:
                        return None
                    array[ptr5] = b
                    ptr5 += 1
                    if ptr5 > ptr6:
                        return None
                    array[ptr5] = b
                    ptr5 += 1
                    dec_get_control2()
                    if getbit != 0:
                        dec_get_control2()
                        if getbit != 0:
                            if ptr5 > ptr6:
                                return None
                            array[ptr5] = b
                            ptr5 += 1
                            if ptr5 > ptr6:
                                return None
                            array[ptr5] = b
                            ptr5 += 1
                            if ptr5 > ptr6:
                                return None
                            array[ptr5] = b
                            ptr5 += 1
                            num3 = 0
                            while True:
                                b2 = source[cp]
                                cp += 1
                                signed = b2 if b2 < 128 else b2 - 256
                                if signed < 0:
                                    num5 = 256 + signed
                                    num3 = num5
                                else:
                                    num5 = num3 = signed
                                if num3 > 127:
                                    num3 -= 128
                                    num3 <<= 8
                                    b2 = source[cp]
                                    cp += 1
                                    signed2 = b2 if b2 < 128 else b2 - 256
                                    if signed2 < 0:
                                        num3 += 256
                                    num3 += signed2
                                    num5 = num3
                                while num5 != 0:
                                    if ptr5 > ptr6:
                                        return None
                                    array[ptr5] = b
                                    ptr5 += 1
                                    num5 -= 1
                                if num3 != 32767:
                                    break
                    else:
                        if ptr5 > ptr6:
                            return None
                        array[ptr5] = b
                        ptr5 += 1
                        if ptr5 > ptr6:
                            return None
                        array[ptr5] = b
                        ptr5 += 1
                    continue
                dec_get_control2()
                if getbit != 0:
                    if ptr5 > ptr6:
                        return None
                    array[ptr5] = b
                    ptr5 += 1
                continue
            dec_get_control2()
            if getbit != 0:
                dec_get_control2()
                if getbit != 0:
                    if ptr5 > ptr6:
                        return None
                    array[ptr5] = b
                    ptr5 += 1
                    if ptr5 > ptr6:
                        return None
                    array[ptr5] = b
                    ptr5 += 1
                    if ptr5 > ptr6:
                        return None
                    array[ptr5] = b
                    ptr5 += 1
                else:
                    if ptr5 > ptr6:
                        return None
                    array[ptr5] = b
                    ptr5 += 1
                    if ptr5 > ptr6:
                        return None
                    array[ptr5] = b
                    ptr5 += 1
                continue
            dec_get_control2()
            if getbit != 0:
                if ptr5 > ptr6:
                    return None
                array[ptr5] = b
                ptr5 += 1
            continue
        if cp != ptr4 + num - 4:
            return None
        return bytes(array)


def snappy_decompress(data):
    data = bytes(data)
    pos = 0
    shift = 0
    length = 0
    while True:
        byte = data[pos]
        pos += 1
        length |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            break
        shift += 7
    out = bytearray()
    while pos < len(data):
        tag = data[pos]
        pos += 1
        t = tag & 3
        if t == 0:
            lit_len = tag >> 2
            if lit_len < 60:
                lit_len += 1
            elif lit_len == 60:
                lit_len = data[pos] + 1
                pos += 1
            elif lit_len == 61:
                lit_len = int.from_bytes(data[pos:pos + 2], "little") + 1
                pos += 2
            elif lit_len == 62:
                lit_len = int.from_bytes(data[pos:pos + 3], "little") + 1
                pos += 3
            elif lit_len == 63:
                lit_len = int.from_bytes(data[pos:pos + 4], "little") + 1
                pos += 4
            out.extend(data[pos:pos + lit_len])
            pos += lit_len
        else:
            if t == 1:
                length_copy = ((tag >> 2) & 7) + 4
                offset = ((tag & 0xE0) << 3) | data[pos]
                pos += 1
            elif t == 2:
                length_copy = (tag >> 2) + 1
                offset = int.from_bytes(data[pos:pos + 2], "little")
                pos += 2
            else:
                length_copy = (tag >> 2) + 1
                offset = int.from_bytes(data[pos:pos + 4], "little")
                pos += 4
            start = len(out) - offset
            for i in range(length_copy):
                out.append(out[start + i])
    if len(out) != length:
        raise HxError("snappy length mismatch")
    return bytes(out)

HxHead.RecordCount = property(lambda self: self.record_count)
HxHead.SizeWithPadding = property(lambda self: self.size_with_padding)
HxHead.SingleRecordLength = property(lambda self: self.single_record_length)
HxHead.DataFieldCount = property(lambda self: self.data_field_count)
HxHead.ExtraDataTotalLength = property(lambda self: self.extra_data_total_length)
HxHead.Version = property(lambda self: self.version)

HxFieldInfo.FieldID = property(lambda self: self.field_id)
HxFieldInfo.DataType = property(lambda self: self.data_type)
HxFieldInfo.ValueLength = property(lambda self: self.value_length)

HxFile.TotalLength = property(lambda self: self.total_length)
HxFile.IsBad = property(lambda self: self.is_bad)
HxFile.Head = property(lambda self: self.head)
HxFile.FieldInfos = property(lambda self: self.field_infos)
HxFile.RecordsStart = property(lambda self: self.records_start)
HxFile.FullBytes = property(lambda self: self.full_bytes)
HxFile.OriginalBytes = property(lambda self: self.original_bytes)
HxFile.DecompressedBytes = property(lambda self: self.decompressed_bytes)
HxFile.IsCompressed = property(lambda self: self.is_compressed)
HxFile.Version = property(lambda self: self.version)
HxFile.ExtraDataStart = property(lambda self: self.extra_data_start)
HxFile.HeadStart = property(lambda self: self.head_start)
HxFile.FieldInfosStart = property(lambda self: self.field_infos_start)
HxFile.AsList = HxFile.as_list
HxFile.AsDicList = HxFile.as_dic_list
HxFile.AsListDictionary = HxFile.as_list
HxFile.ExtraFields = HxFile.extra_fields
HxFile.GetRecordOffset = HxFile.get_record_offset
HxFile.HxLongToDouble = staticmethod(HxFile.hxlong_to_double)
HxFile.ParseFullBytesSpan = staticmethod(HxFile.parse_full_bytes_span)
HxFile.Unzip3Sharp = staticmethod(HxFile.unzip3sharp)

HexinMinuteTime.GetOffset = staticmethod(HexinMinuteTime.get_offset)
HexinMinuteTime.TryToUnixTimeStampInt64 = staticmethod(HexinMinuteTime.try_to_unix_timestamp_int64)
HexinMinuteTime.TryToUnixTimeStampInt32 = staticmethod(HexinMinuteTime.try_to_unix_timestamp_int32)
