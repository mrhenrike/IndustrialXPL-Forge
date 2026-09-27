import io
import struct
import datetime
import traceback
from functools import wraps

ENABLE_PRINT = 0


def decorate_all_functions(function_decorator):
    def decorator(cls):
        for name, obj in vars(cls).items():
            if callable(obj):
                try:
                    obj = obj.__func__  # unwrap Python 2 unbound method
                except AttributeError:
                    pass  # not needed in Python 3
                setattr(cls, name, function_decorator(obj))
        return cls

    return decorator


class BinaryStreamParseError(BaseException):
    pass


def exception_proxy(func):
    global ENABLE_PRINT

    @wraps(func)
    def wrapper(*args, **kw):
        res = None

        try:
            res = func(*args, **kw)
        except:
            if ENABLE_PRINT:
                traceback.print_exc()
            raise BinaryStreamParseError(func.__name__)

        return res

    return wrapper


@decorate_all_functions(exception_proxy)
class BinaryStream:
    def __init__(self, base_stream=b''):
        if isinstance(base_stream, str):
            self.base_stream = io.StringIO(base_stream)
        elif isinstance(base_stream, bytes):
            self.base_stream = io.BytesIO(base_stream)
        else:
            self.base_stream = base_stream

    def readChar(self):
        return self.base_stream.read(1)

    def readByte(self):
        return ord(self.readChar())

    def readBytes(self, length):
        return self.base_stream.read(length)

    def readBool(self):
        return self.unpack('?')

    def readInt16(self):
        return self.unpack('h', 2)

    def readUInt16(self):
        return self.unpack('H', 2)

    def readUInt16be(self):
        return self.unpack('>H', 2)

    def readInt32(self):
        return self.unpack('i', 4)

    def readUInt32(self):
        return self.unpack('I', 4)

    def readUInt32be(self):
        return self.unpack('>I', 4)

    def readInt64(self):
        return self.unpack('q', 8)

    def readUInt64(self):
        return self.unpack('Q', 8)

    def readUInt64Be(self):
        return self.unpack('>Q', 8)

    def readFloat(self):
        return self.unpack('f', 4)

    def readDouble(self):
        return self.unpack('d', 8)

    def readDoublebe(self):
        return self.unpack('>d', 8)

    def readString8(self):
        length = self.readByte()
        return self.unpack(str(length) + 's', length)

    def readString16(self):
        length = self.readUInt16()
        return self.unpack(str(length) + 's', length)

    def readString32(self):
        length = self.readUInt32()
        return self.unpack(str(length) + 's', length)

    def readString32be(self):
        length = self.readUInt32be()
        return self.unpack(str(length) + 's', length)

    def readString(self, length, encoding='ascii'):
        return self.readBytes(length).decode(encoding=encoding)

    def readMac(self):
        return "%02x:%02x:%02x:%02x:%02x:%02x" % self.unpack_tp("BBBBBB", 6)

    def readIp(self):
        return "%d.%d.%d.%d" % self.unpack_tp("BBBB", 4)

    def readS7Datetime(self):
        d = self.readBytes(6)
        millis = struct.unpack(">I", d[:4])[0]
        days = struct.unpack(">H", d[4:][:2])[0]
        dt = datetime.datetime(1984, 1, 1) + datetime.timedelta(microseconds=millis * 1000, days=days)
        return dt

    def writeBytes(self, value):
        self.base_stream.write(value)

    def writeChar(self, value):
        self.pack('c', value)

    def writeUChar(self, value):
        self.pack('C', value)

    def writeBool(self, value):
        self.pack('?', value)

    def writeInt16(self, value):
        self.pack('h', value)

    def writeUInt16(self, value):
        self.pack('H', value)

    def writeInt32(self, value):
        self.pack('i', value)

    def writeUInt32(self, value):
        self.pack('I', value)

    def writeInt64(self, value):
        self.pack('q', value)

    def writeUInt64(self, value):
        self.pack('Q', value)

    def writeFloat(self, value):
        self.pack('f', value)

    def writeDouble(self, value):
        self.pack('d', value)

    def writeString(self, value):
        length = len(value)
        self.writeUInt16(length)
        self.pack(str(length) + 's', value)

    def pack(self, fmt, data):
        return self.writeBytes(struct.pack(fmt, data))

    def read(self):
        return self.base_stream.read()

    def unpack(self, fmt, length=1):
        return struct.unpack(fmt, self.readBytes(length))[0]

    def unpack_tp(self, fmt, length=1):
        return struct.unpack(fmt, self.readBytes(length))

    def seek(self, pos, whence=0):
        self.base_stream.seek(pos, whence)

    def tell(self):
        return self.base_stream.tell()

    def dump(self):
        self.seek(0)
        return self.read()

    def __len__(self):
        pos = self.tell()
        self.seek(0, 2)
        size = self.tell()
        self.seek(pos)
        return size
