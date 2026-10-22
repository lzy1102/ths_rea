import struct
import zlib

from .errors import HxError, ProtocolError
from .hxfile import snappy_decompress
from .encoding import gbk_encode, gbk_decode

INSTANCE_COUNTER = {"value": 1}

TEMPLATE = bytes([253, 253, 253, 253, 0, 0, 0, 0, 0, 0, 0, 0, 9])

class BinaryPack:
    TEMPLATE = TEMPLATE

    def __init__(self, raw):
        self.raw = bytes(raw)

    @classmethod
    def from_bytes(cls, raw):
        return cls(raw)

    @classmethod
    def from_body(cls, body):
        body = bytes(body)
        head = bytearray(TEMPLATE)
        head[4:12] = ("%08x" % len(body)).encode("ascii")
        return cls(bytes(head) + body)

    @property
    def full_bytes(self):
        return self.raw

    @property
    def head_length(self):
        return 13

    @property
    def body_start_index(self):
        return 13

    @property
    def body_length(self):
        try:
            return int(self.raw[4:12].decode("ascii"), 16)
        except Exception:
            return 0

    @property
    def body(self):
        return self.raw[13:13 + self.body_length]

class BinaryPackLayoutV2:
    def __init__(self, full_pack):
        self.full_pack = full_pack
        raw = full_pack.full_bytes
        self.response_info = struct.unpack("<HiIHiB", raw[13:30])
        self._offsets = None

    @property
    def rsp_data_length(self):
        return self.response_info[0]

    @property
    def instance_id(self):
        return self.response_info[1]

    @property
    def biz_rsp_type(self):
        return self.response_info[2]

    @property
    def format_flag(self):
        return self.response_info[3]

    @property
    def total_records_length(self):
        return self.response_info[4]

    @property
    def record_count(self):
        return self.response_info[5]

    @property
    def data_format(self):
        return self.format_flag & 0xFF

    @property
    def compression_method(self):
        return self.format_flag & 0xFF00

    @property
    def response_info_start(self):
        return 13

    @property
    def response_info_length(self):
        return 17

    @property
    def data_start(self):
        return 30

    @property
    def data_length(self):
        return self.total_records_length

    @property
    def data_segment_offsets(self):
        if self._offsets is not None:
            return self._offsets
        offsets = []
        raw = self.full_pack.full_bytes
        num = 30
        while num + 4 < len(raw):
            if len(offsets) >= self.record_count:
                break
            length = int.from_bytes(raw[num:num + 4], "little")
            if length <= 0:
                break
            offsets.append(num)
            num += 4 + length
        self._offsets = offsets
        return offsets

    @property
    def pack_type_auth(self):
        raw = self.full_pack.full_bytes
        return len(raw) > 13 and raw[13] == 65

class DataResponseV2:
    def __init__(self, pack_bytes=None, full_pack=None, layout=None, is_push_response=False):
        if layout is not None:
            self.pack_layout = layout
        else:
            if full_pack is None:
                full_pack = BinaryPack.from_bytes(pack_bytes)
            self.pack_layout = BinaryPackLayoutV2(full_pack)
        self.is_push_response = is_push_response
        self._decompressed = None
        self._extra = None

    @property
    def is_bad(self):
        layout = self.pack_layout
        if layout is None:
            return True
        return layout.total_records_length == 0

    @property
    def decompressed_bytes(self):
        if self._decompressed is not None:
            return self._decompressed
        layout = self.pack_layout
        raw = layout.full_pack.full_bytes
        if layout.compression_method == 0:
            self._decompressed = None
            return None
        if layout.compression_method == 0x200:
            payload = raw[layout.data_start + 4:layout.data_start + layout.data_length]
            self._decompressed = zlib.decompress(payload)
            return self._decompressed
        if layout.compression_method == 0x100:
            self._decompressed = snappy_decompress(raw[layout.data_start + 4:layout.data_start + layout.data_length])
            return self._decompressed
        return None

    def as_string(self):
        if self.is_bad:
            return "空包，AsString失败"
        layout = self.pack_layout
        raw = layout.full_pack.full_bytes
        if layout.compression_method == 0:
            if layout.data_length == 0:
                return ""
            return gbk_decode(raw[layout.data_start + 4:layout.data_start + layout.data_length])
        decompressed = self.decompressed_bytes
        if decompressed is None:
            return ""
        num = int.from_bytes(decompressed[:4], "little")
        if num > 0:
            return gbk_decode(decompressed[4:4 + num])
        return ""

    def get_extra_dic(self):
        from .hxfile import HxFile
        layout = self.pack_layout
        if self.is_bad:
            return None
        if self._extra is not None:
            return self._extra
        hxlong_conversion = "AsPush" if self.is_push_response else "AsResponse"
        files = []
        try:
            for offset in layout.data_segment_offsets:
                files.append(HxFile(layout.full_pack.full_bytes, offset, hxlong_conversion))
        except Exception:
            return None
        if not files:
            return None
        self._extra = files[0].extra_fields()
        return self._extra

    def as_list_dictionary(self):
        from .hxfile import HxFile
        layout = self.pack_layout
        if self.is_bad:
            return []
        hxlong_conversion = "AsPush" if self.is_push_response else "AsResponse"
        files = []
        for offset in layout.data_segment_offsets:
            hx = HxFile(layout.full_pack.full_bytes, offset, hxlong_conversion)
            if hx.version != "UnKnow" and not hx.is_bad:
                files.append(hx)
        result = []
        code_indexs = {}
        time_indexs = {}
        is_multi = len(layout.data_segment_offsets) > 1
        for hx in files:
            hx.as_dic_list(is_multi, result, code_indexs, time_indexs, False, get_merge_index, merge_rows)
        return result

def get_merge_index(is_multi_pack, code_indexs, time_indexs, row_number, row_val, result_number):
    if not is_multi_pack:
        return -1
    code = _get_or_add_index(row_val, code_indexs, 5, result_number)
    time = _get_or_add_index(row_val, time_indexs, 1, result_number)
    if code[0]:
        return code[1]
    if time[0]:
        return time[1]
    return row_number

def _get_or_add_index(row_val, indexs, field_id, result_number):
    if field_id not in row_val:
        return (False, 0)
    value = row_val[field_id]
    if value not in indexs:
        indexs[value] = result_number
        return (False, -1)
    return (True, indexs[value])

def merge_rows(result, index, val):
    if index < 0 or index >= len(result):
        result.append(dict(val))
        return
    for key, value in val.items():
        if key not in result[index]:
            result[index][key] = value

def string_to_parameter_dictionary(source):
    from .encoding import parse_key_value_string
    result = parse_key_value_string(source, True, "&")
    if "zipversion" not in result:
        result["zipversion"] = "2"
    if "instance" not in result:
        result["instance"] = str(INSTANCE_COUNTER["value"])
        INSTANCE_COUNTER["value"] += 1
    return result

def parameter_dictionary_to_string(mapping):
    mapping = dict(mapping)
    if "instance" not in mapping:
        mapping["instance"] = str(INSTANCE_COUNTER["value"])
        INSTANCE_COUNTER["value"] += 1
    if "id" not in mapping:
        raise ProtocolError("missing id")
    parts = ["id=" + str(mapping["id"])]
    for key, value in mapping.items():
        if key == "id":
            continue
        parts.append(str(key) + "=" + str(value))
    return "&".join(parts)

def parameter_dictionary_to_binary_pack(mapping):
    text = parameter_dictionary_to_string(mapping)
    return BinaryPack.from_body(gbk_encode(text))

def request_trend_v2(request_id, market, code, date, fields=None, is_auto_add_base_id=True):
    if fields is None:
        from .constants import DEFAULT_FIELDS
        fields = list(DEFAULT_FIELDS)
    else:
        fields = list(fields)
    if request_id == 207 and is_auto_add_base_id:
        if "latest" not in fields:
            fields.append("latest")
        if "date_time" not in fields:
            fields.append("date_time")
    return "id=%s&market=%s&code=%s&date=%s&datatype=%s" % (request_id, market, code, date, ",".join(fields))

BinaryPack.FullBytes = property(lambda self: self.full_bytes)
BinaryPack.HeadLength = property(lambda self: self.head_length)
BinaryPack.BodyStartIndex = property(lambda self: self.body_start_index)
BinaryPack.BodyLength = property(lambda self: self.body_length)
BinaryPack.Body = property(lambda self: self.body)

BinaryPackLayoutV2.RspDataLength = property(lambda self: self.rsp_data_length)
BinaryPackLayoutV2.InstanceID = property(lambda self: self.instance_id)
BinaryPackLayoutV2.BizRspType = property(lambda self: self.biz_rsp_type)
BinaryPackLayoutV2.FormatFlag = property(lambda self: self.format_flag)
BinaryPackLayoutV2.TotalRecordsLength = property(lambda self: self.total_records_length)
BinaryPackLayoutV2.RecordCount = property(lambda self: self.record_count)
BinaryPackLayoutV2.DataFormat = property(lambda self: self.data_format)
BinaryPackLayoutV2.CompressionMethod = property(lambda self: self.compression_method)
BinaryPackLayoutV2.ResponseInfoStart = property(lambda self: self.response_info_start)
BinaryPackLayoutV2.ResponseInfoLength = property(lambda self: self.response_info_length)
BinaryPackLayoutV2.DataStart = property(lambda self: self.data_start)
BinaryPackLayoutV2.DataLength = property(lambda self: self.data_length)
BinaryPackLayoutV2.DataSegmentOffsets = property(lambda self: self.data_segment_offsets)
BinaryPackLayoutV2.PackTypeAuth = property(lambda self: self.pack_type_auth)

DataResponseV2.IsBad = property(lambda self: self.is_bad)
DataResponseV2.DecompressedBytes = property(lambda self: self.decompressed_bytes)
DataResponseV2.AsString = DataResponseV2.as_string
DataResponseV2.GetExtraDic = DataResponseV2.get_extra_dic
DataResponseV2.AsListDictionary = DataResponseV2.as_list_dictionary

StringToParameterDictionary = string_to_parameter_dictionary
ParameterDictionaryToString = parameter_dictionary_to_string
ParameterDictionaryToBinaryPack = parameter_dictionary_to_binary_pack
