import os
import glob
import json
import re
import shutil
import socket
import pandas as pd
from loguru import logger
from tqdm import tqdm

def to_str(data):
    return data.strip("\x00").strip(" ")

def get_ip_addresses(fpath):
    if not os.path.exists(fpath):
        raise Exception(
            'IP addresses file: {} does not exist. Usage: ./main.py <IP_addresses_file_to_scan>'.format(fpath))
    with open(r'./ips_to_scan.txt', 'r') as f:
        return f.read().splitlines()


def get_ip_blocks(ip, parsed_devices_data, raw_files_directory):
    ip_blocks = []
    if parsed_devices_data:
        ip_rows = list(filter(lambda row: row['ip'] == ip, parsed_devices_data))
        if ip_rows:
            ip_blocks = list(map(lambda row: row['blocks'], ip_rows))
    else:
        for fpath in glob.glob(os.path.join(raw_files_directory, ip.replace('.', '_') + '*')):
            with open(fpath, 'r') as f:
                device_output = json.load(f)
                ip_blocks.extend(device_output['blocks'])
    return ip_blocks


def is_host_alive(host, port, timeout=10):
    s = None

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        response = s.connect_ex((host, port))
        return response == 0
    finally:
        if s:
            s.close()


def ensure_directory_exists(directory_path, override=True):
    if os.path.exists(directory_path) and override:
        shutil.rmtree(directory_path)
    os.makedirs(directory_path, exist_ok=True)


def get_parsed_devices_data(raw_files_directory):
    parsed_data = []

    for fname in os.listdir(raw_files_directory):
        logger.info(f'loading file:{fname}')
        fpath = os.path.join(raw_files_directory, fname)

        with open(fpath, 'r') as f:
            device_output = json.load(f)

        row_prefix = {'ip': device_output['ip'],
                      'rack': device_output['rack'], 'slot': device_output['slot'],
                      'port': device_output['port']}

        if device_output['identity']:
            df = pd.json_normalize(device_output['identity'], sep='_')
            row_prefix.update(df.to_dict(orient='records')[0])
        logger.info(f'load blocks:{fname}')
        for block in tqdm(device_output['blocks']):
            df = pd.json_normalize(block, sep='_')
            block_row = df.to_dict(orient='records')[0]
            block_row.update(row_prefix)
            parsed_data.append(block_row)

    return parsed_data

def validate_network_subnet(subnet):
    res = re.search(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.$", subnet)
    if not res:
        return False
    return True


def validate_port_number(num):
    if type(num) == int and 1 <= 65535:
        return True
    return False

def twosComplement_hex(hexval):
    bits = 16
    val = int(hexval, bits)
    if val & (1 << (bits - 1)):
        val -= 1 << bits
    return val