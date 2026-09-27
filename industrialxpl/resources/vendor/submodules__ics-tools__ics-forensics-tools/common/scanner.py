from loguru import logger
from multiprocessing import Pool

from . import utils
from . protocol import S7


def scan(ip, port, rack_start=0, rack_end=7, slot_start=0, slot_end=31):
    if not utils.is_host_alive(ip, port):
        return None

    for rack in range(rack_start, rack_end + 1):
        for slot in range(slot_start, slot_end + 1):
            try:
                with S7(ip, rack, slot) as _:
                    logger.debug('scanner found s7 device. ip: {}, rack: {}, slot: {}'.format(ip, rack, slot))
                    return ip
            except Exception as e:
                continue

    return None


def start(subnet='192.168.0.', port=102, subnet_start=1, subnet_end=255):
    logger.debug('start scanning for S7 plcs in subnet: {}'.format(subnet))
    ip_addr_list = list(map(lambda o: subnet + str(o), range(subnet_start, subnet_end)))
    args = [(ip, port) for ip in ip_addr_list]
    found_devices = Pool(processes=5).starmap(func=scan, iterable=args)
    # found_devices = Pool(processes=5).map(scan, ip_addr_list)
    return list(filter(lambda e: e, found_devices))
