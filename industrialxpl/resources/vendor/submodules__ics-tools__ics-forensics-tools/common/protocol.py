import snap7
from loguru import logger

from .mc7consts import BLOCK_TYPE


class S7:
    def __init__(self, ip, rack=0, slot=0, port=102):
        self.ip = ip
        self.rack = rack
        self.slot = slot
        self.port = port
        self.client = snap7.client.Client()

    def __enter__(self):
        if self._connect():
            return self
        raise Exception('ConnectionSetupFailed')

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.client.get_connected():
            self._disconnect()

    def _connect(self):
        try:
            self.client.connect(address=self.ip, rack=self.rack, slot=self.slot, tcpport=self.port)
        except Exception as e:
            logger.debug(
                'error while connecting to ip: {}, rack: {}, slot: {}, port: {}'.format(self.ip, self.rack, self.slot,
                                                                                        self.port))
            return None
        if self.client.get_connected():
            return self.client
        return None

    def _disconnect(self):
        self.client.destroy()

    def get_cpu_state(self):
        cpu_states = {'S7CpuStatusRun': 'run', 'S7CpuStatusStop': 'stop', 'S7CpuStatusUnknown': 'unknown'}

        try:
            cpu_state = self.client.get_cpu_state()
        except Exception as e:
            logger.debug(
                'error while getting cpu state info for ip: {}, rack: {}, slot: {}, port: {}'.format(self.ip, self.rack,
                                                                                                     self.slot,
                                                                                                     self.port))
            return cpu_states['S7CpuStatusUnknown']

        if cpu_state in cpu_states.keys():
            return cpu_states[cpu_state]

        return ''

    def get_plc_datetime(self):
        try:
            plc_dt = self.client.get_plc_datetime()
        except Exception as e:
            logger.debug(
                'error while getting cpu datetime info for ip: {}, rack: {}, slot: {}, port: {}'.format(self.ip,
                                                                                                        self.rack,
                                                                                                        self.slot,
                                                                                                        self.port))
            return ''

        return plc_dt.isoformat()

    def get_plc_protection(self):
        protection = dict()
        protec_values = {'anl_sch': {'name': 'startup_switch_setting', 'value': None,
                                     'values_desc': {0: 'undefined', 1: 'crst', 2: 'wrst'}},
                         'bart_sch': {'name': 'mode_selector_setting', 'value': None,
                                      'values_desc': {0: 'undefined', 1: 'run', 2: 'run-p', 3: 'stop', 4: 'mres'}},
                         'sch_par': {'name': 'password_level', 'value': None, 'values_desc': {0: 'no_password'}},
                         'sch_rel': {'name': 'protection_level_of_the_cpu', 'value': None, 'values_desc': {}},
                         'sch_schal': {'name': 'protection_level_set_with_the_mode_selector', 'value': None,
                                       'values_desc': {}}}

        try:
            plc_protection = self.client.get_protection()
        except Exception as e:
            logger.debug(
                'error while getting cpu protection info for ip: {}, rack: {}, slot: {}, port: {}'.format(self.ip,
                                                                                                          self.rack,
                                                                                                          self.slot,
                                                                                                          self.port))
            return protection

        protec_values['anl_sch']['value'] = plc_protection.anl_sch
        protec_values['bart_sch']['value'] = plc_protection.bart_sch
        protec_values['sch_par']['value'] = plc_protection.sch_par
        protec_values['sch_rel']['value'] = plc_protection.sch_rel
        protec_values['sch_schal']['value'] = plc_protection.sch_schal

        for key in protec_values:  # value to description
            if protec_values[key]['value'] in protec_values[key]['values_desc'].keys():
                protec_values[key]['value'] = protec_values[key]['values_desc'][protec_values[key]['value']]

        return {protec_values[key]['name']: protec_values[key]['value'] for key in protec_values.keys()}

    def get_module(self):
        try:
            order_code = self.client.get_order_code().OrderCode
        except Exception as e:
            logger.debug(
                'error while getting module for ip: {}, rack: {}, slot: {}, port: {}'.format(self.ip, self.rack,
                                                                                             self.slot, self.port))
            return ''

        return order_code.decode()

    def get_identity(self):
        identity = dict.fromkeys(
            ['plc_name', 'copyright', 'module_name', 'module_type_name', 'module_serial_number'])
        try:
            cpu_info = self.client.get_cpu_info()
        except Exception as e:
            logger.debug(
                'error while getting identity info for ip: {}, rack: {}, slot: {}, port: {}'.format(self.ip, self.rack,
                                                                                                    self.slot,
                                                                                                    self.port))
            return identity

        identity['module'] = self.get_module()
        identity['plc_name'] = cpu_info.ASName.decode()
        identity['copyright'] = cpu_info.Copyright.decode()
        identity['module_name'] = cpu_info.ModuleName.decode()
        identity['module_type_name'] = cpu_info.ModuleTypeName.decode()
        identity['module_serial_number'] = cpu_info.SerialNumber.decode()

        return identity

    def block_count_by_type(self):
        try:
            list_blocks = self.client.list_blocks()
        except Exception as e:
            logger.debug(
                'error while listing blocks for ip: {}, rack: {}, slot: {}, port: {}'.format(self.ip, self.rack,
                                                                                             self.slot, self.port))
            return None

        block_count = dict.fromkeys(BLOCK_TYPE.values())
        block_count['OB'] = list_blocks.OBCount
        block_count['FC'] = list_blocks.FCCount
        block_count['FB'] = list_blocks.FBCount
        block_count['DB'] = list_blocks.DBCount
        block_count['SFC'] = list_blocks.SFCCount
        block_count['SFB'] = list_blocks.SFBCount
        block_count['SDB'] = list_blocks.SDBCount
        return block_count

    def block_numbers_by_type(self, list_blocks):
        block_numbers = dict()

        for block_type in BLOCK_TYPE.values():
            try:
                block_type_usage = self.client.list_blocks_of_type(block_type, list_blocks[block_type])
            except Exception as e:
                logger.debug(
                    'error while listing blocks of type: {} for ip: {}, rack: {}, slot: {}, port: {}'.format(block_type,
                                                                                                             self.ip,
                                                                                                             self.rack,
                                                                                                             self.slot,
                                                                                                             self.port))
                continue

            if not block_type_usage:  # size is 0
                continue

            block_numbers[block_type] = list(block_type_usage)

        return block_numbers

    def upload_all_blocks(self):
        block_count = self.block_count_by_type()
        if not block_count:
            return

        block_numbers = self.block_numbers_by_type(block_count)

        block_data = dict()

        for block_type in block_numbers.keys():
            for block_num in block_numbers[block_type]:
                try:
                    data = self.client.full_upload(block_type, block_num)
                    block_data[(block_type, block_num)] = {'value': bytes(data[0]), 'len': data[1]}
                except:
                    logger.debug(
                        'failed upload {} block number {} from ip: {}, rack: {}, slot: {}, port: {}'.format(block_type,
                                                                                                            block_num,
                                                                                                            self.ip,
                                                                                                            self.rack,
                                                                                                            self.slot,
                                                                                                            self.port))
        return block_data