import os
import json
from loguru import logger
from base64 import b64encode

from . import utils
from .protocol import S7
from .mc7parser import MC7Parser


def split_bin(ar, size):
    """ split sequence into blocks of given size
    """
    return [ar[i:i + size] for i in range(0, len(ar), size)]


def parse_block(block_bytes):
    block_metadata = {'raw_block': b64encode(block_bytes).decode()}
    try:
        parsed_block = MC7Parser(block_bytes).parse()
    except Exception as e:
        logger.debug('error while parsing block: {}'.format(str(e)))
        return

    for k in parsed_block:
        if type(parsed_block[k]) == bytes:
            parsed_block[k] = parsed_block[k].decode()

    block_metadata.update(parsed_block)

    return block_metadata


def scan(plc_ip_address, output_directory, port, rack_start=0, rack_end=7, slot_start=0, slot_end=31):
    logger.debug('checking if ip address "{}" is online ...'.format(plc_ip_address))
    if not utils.is_host_alive(plc_ip_address, port):
        logger.warning('ip address "{}" is not online'.format(plc_ip_address))
        return

    logger.info('scanning ip address "{}" ...'.format(plc_ip_address))
    for rack in range(rack_start, rack_end + 1):
        for slot in range(slot_start, slot_end + 1):
            try:
                logger.debug('scanning ip address "{}" rack "{}" slot "{}" ...'.format(plc_ip_address, rack, slot))

                with S7(plc_ip_address, rack, slot, port) as client:
                    response = dict()
                    response['ip'] = plc_ip_address
                    response['port'] = port
                    response['rack'] = rack
                    response['slot'] = slot
                    response['identity'] = client.get_identity()
                    response['cpu_state'] = client.get_cpu_state()
                    response['protection'] = client.get_plc_protection()
                    response['available_blocks'] = client.block_count_by_type()
                    block_data = client.upload_all_blocks()
                    response['blocks'] = list(filter(lambda parsed_block: parsed_block, list(
                        map(lambda block: parse_block(block_data[block]['value']), block_data))))

                    output_file_name = plc_ip_address.replace(".", "_") + "-rack_" + str(rack) + "-slot_" + str(slot)
                    output_file_path = os.path.join(output_directory, output_file_name)

                    with open(output_file_path, 'w') as f:
                        json.dump(response, f, default=str)

                    return
            except Exception as e:
                logger.error(
                    'failed to process scan. ip address "{}" rack "{}" slot "{}"'.format(plc_ip_address, rack, slot))

    logger.warning('ip address "{}" produced no results'.format(plc_ip_address))
