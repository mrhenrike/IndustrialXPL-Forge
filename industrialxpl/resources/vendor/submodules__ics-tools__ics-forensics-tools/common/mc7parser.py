import struct
import base64
import binascii
from loguru import logger

from . import utils
from .mc7consts import *
from .mc7convert import *
from .stream import BinaryStream, BinaryStreamParseError


def to_version(data):
    return f'{str((data & 0xF0) >> 4)}.{str(data & 0x0F)}'


class MC7Parser(object):
    def __init__(self, data):
        self._bkp_data = data
        self._data = BinaryStream(data)

    def parse(self):
        res = self.parse_header(self._data)
        return res

    def _get_interface_val(self, db_data, start_values, actual_values):
        data_type = get_val_def(DATA_BLOCK_PARAMS_TYPE, db_data.readByte())
        param_type = get_val_def(PARAMETERS_TYPE, db_data.readByte())
        if "ex" in param_type:
            db_data.readByte()
        value = None
        act_val = None

        if "_Init" in param_type:
            if data_type in ('INT', 'WORD', 'DATE', 'S5TIME'):
                value = start_values.readUInt16()
                act_val = actual_values.readUInt16be()
            elif data_type in ('CHAR', 'BOOL', 'BYTE'):
                value = start_values.readByte()
                act_val = actual_values.readByte()
            elif data_type in ('DWORD', 'DINT', 'TIME_OF_DAY', 'TIME'):
                value = start_values.readUInt32()
                act_val = actual_values.readUInt32()
            elif data_type in ('REAL',):
                value = start_values.readFloat()
                act_val = actual_values.readFloat()
            elif data_type in ('DATE_AND_TIME',):
                value = start_values.readUInt64()
                act_val = actual_values.readUInt64()
            elif data_type in ('STRING',):
                value = start_values.readString8()
                act_val = actual_values.readString8()
        elif data_type in ('ARRAY',):
            value = []
            array_dim = db_data.readByte()
            db_data.seek(3 + 4 * array_dim)
        elif data_type in ('STRUCT',):
            childs = db_data.readByte()
            if childs == 255:
                childs = db_data.readUInt16()
            value = []
            for i in range(childs):
                value.append(self._get_interface_val(db_data, start_values, actual_values))
        else:
            if data_type in ('INT', 'WORD', 'DATE', 'S5TIME') and len(actual_values) >= 2:
                act_val = actual_values.readUInt16be()
            elif data_type in ('CHAR', 'BOOL', 'BYTE') and len(actual_values) >= 1:
                act_val = actual_values.readByte()
            elif data_type in ('DWORD', 'DINT', 'TIME_OF_DAY', 'TIME') and len(actual_values) >= 4:
                act_val = actual_values.readUInt32()
            elif data_type in ('REAL',) and len(actual_values) >= 2:
                act_val = actual_values.readFloat()
            elif data_type in ('DATE_AND_TIME',) and len(actual_values) >= 8:
                act_val = actual_values.readUInt64()
            elif data_type in ('STRING',):
                act_val = actual_values.readString8()

        return (data_type, param_type, value, act_val)

    def parse_header(self, data):
        block_data_len = len(data)
        if not (data.readChar() == b'p' and data.readChar() == b'p'):
            raise Exception('BadBlockMagic')

        res = dict()
        res['ver'] = data.readByte()
        res['attr'] = get_val_def(BLOCK_ATTRIBUTE, data.readByte())
        res['lang'] = get_val_def(BLOCK_LANGUAGE, data.readByte())
        res['type'] = get_val_def(BLOCK_TYPE, data.readByte())
        res['block_num'] = data.readUInt16be()
        res['len'] = data.readUInt32be()
        password = data.readBytes(4).hex()
        protection = True
        if password == '00000000':
            password = 'Empty'
            protection = False
        res["password"] = password
        res['Know-how protection'] = protection
        res["last_modified"] = data.readS7Datetime()
        res["last_interface_change"] = data.readS7Datetime()

        if "DB" in res['type']:
            res["body_len"] = data.readUInt16be()
            res["seg_len"] = data.readUInt16be()
            res["local_data_len"] = data.readUInt16be()
            res["data_len"] = data.readUInt16be()
            if res["data_len"]:
                res["data"] = binascii.hexlify(data.readBytes(res["data_len"]))
            if res["seg_len"]:
                res["seg"] = binascii.hexlify(data.readBytes(res["seg_len"]))
            if res["local_data_len"]:
                res["local_data"] = binascii.hexlify(data.readBytes(res["local_data_len"]))
            if res["body_len"]:
                res["body"] = binascii.hexlify(data.readBytes(res["body_len"]))
            if "body" in res:
                data_struct = []
                actual_values = BinaryStream(binascii.unhexlify(res["data"]))
                db_data = BinaryStream(binascii.unhexlify(res["body"]))
                db_type = db_data.readByte()
                fb_num = db_data.readUInt16()
                if db_type == 0xa:
                    res['db_type'] = 'InstanceDB'
                    res['FB_related'] = fb_num
                else:
                    res['db_type'] = 'GlobalDB'
                interface_len = db_data.readUInt16()
                value_position = db_data.readUInt16()
                start_values = BinaryStream(binascii.unhexlify(res["body"])[interface_len + 7:])
                try:
                    while db_data.tell() <= (interface_len + 5) and start_values.tell() <= value_position:
                        interface = self._get_interface_val(db_data, start_values, actual_values)
                        data_struct.append(interface)
                except BinaryStreamParseError:
                    pass
                res["body_parse"] = data_struct
        else:
            res["interface_len"] = data.readUInt16be()
            res["seg_len"] = data.readUInt16be()
            res["local_data_len"] = data.readUInt16be()
            res["mc7_len"] = data.readUInt16be()
            if res["mc7_len"]:
                res["data"] = binascii.hexlify(data.readBytes(res["mc7_len"]))
            if res["interface_len"]:
                res["interface"] = binascii.hexlify(data.readBytes(res["interface_len"]))
            if res["seg_len"]:
                res["seg"] = binascii.hexlify(data.readBytes(res["seg_len"]))
            res["used_block"] = []
            if res["seg"]:
                seg_data_raw = BinaryStream(binascii.unhexlify(res["seg"]))
                res["seg_num"] = seg_data_raw.readUInt16()
                pointer = 0
                for x in range(0, res["seg_num"]):
                    seg_size = seg_data_raw.readUInt16()

                    res[f"network_{x + 1}_raw"] = res["data"][pointer * 2:(pointer + seg_size) * 2]
                    res[f"network_{x + 1}_mc7"] = MC7_to_AWL(res[f"network_{x + 1}_raw"])
                    if res[f"network_{x + 1}_mc7"]:
                        res["used_block"] += [" ".join(s.split(' ')[1:]) if s else s for s in
                                              res[f"network_{x + 1}_mc7"] if
                                              any(xs in s for xs in ['UC', 'CC'])]
                    pointer += seg_size

        # footer
        footer_start = block_data_len - HEADER_SIZE
        data.seek(footer_start)
        res["author_name"] = utils.to_str(data.readString(8))
        res["block_family"] = utils.to_str(data.readString(8))
        res["block_name"] = utils.to_str(data.readString(8))
        res["block_version"] = to_version(data.readByte())
        res["check_sum"] = data.readUInt16()

        if res['type'] == 'DB' and res['data_len']:
            data = BinaryStream(binascii.unhexlify(res["data"]))
            res["db_ext_header"] = dict()
            if res["block_name"] == "TCON_PAR":  # S7-300/400 only
                res["db_ext_header"]["tcon_params"] = self.parse_tcon_params(data)

        return res

    def parse_tcon_params(self, body):
        tcon_params = dict()

        try:
            tcon_params["block_length"] = body.readUInt16be()
            tcon_params["connection_id"] = body.readUInt16be()  # valid range 0x0001 - 0x0fff
            tcon_params["connection_type"] = get_val_def(CONNECTION_TYPE, body.readByte())
            tcon_params["active_est"] = body.readByte()
            tcon_params["local_device_id"] = body.readByte()  # allowed values: 0 / 2 / 3 / 5
            tcon_params['local_tsap_id_len'] = body.readByte()  # used length of the "local_tsap_id" parameter
            tcon_params["rem_subnet_id_len"] = body.readByte()  # unused
            tcon_params["rem_staddr_len"] = body.readByte()  # 0 (unspecified) / 4 (valid IP address)
            tcon_params["rem_tsap_id_len"] = body.readByte()  # used length of the "rem_tsap_id" parameter
            tcon_params[
                "next_staddr_len"] = body.readByte()  # Used length of the "next_staddr" parameter. This parameter is not relevant for TCP.
            tcon_params["local_tsap_id"] = body.readUInt16be()  # local port number
            body.readBytes(14)
            body.readBytes(6)
            tcon_params["rem_subnet_id"] = 0  # unused
            tcon_params["rem_staddr"] = body.readIp()
            body.readBytes(2)
            tcon_params["rem_tsap_id"] = body.readUInt16be()  # remote port number
            body.readBytes(14)

            # rest of params are irrelevant (next_staddr, spare)
        except Exception as e:
            logger.debug('db_parser: parse_tcon_params: exception occurred while parsing.')
            logger.error(e)

        return tcon_params
