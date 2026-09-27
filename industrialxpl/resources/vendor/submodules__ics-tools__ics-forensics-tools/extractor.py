import os
from queue import Queue
from loguru import logger
from threading import Thread

from common import s7

queue = Queue()


def process_queue(raw_files_directory, port, threads=10):
    logger.debug('initializing queue handler thread...')

    def worker():
        while True:
            ip_address = queue.get()
            try:
                s7.scan(ip_address, raw_files_directory, port)
            except Exception as e:
                logger.debug('failed to scan ip address {}'.format(ip_address))
            queue.task_done()

    for i in range(threads):
        t = Thread(target=worker)
        t.daemon = True
        t.start()

    queue.join()


def process_addresses(ip_addresses, port, raw_files_directory):
    for ip_address in ip_addresses:
        queue.put(ip_address)
        process_queue(raw_files_directory, port, threads=30)  # Wait for all jobs to complete

    logger.info('processing results ...')
    if not len(os.listdir(raw_files_directory)):
        raise Exception('no results')


def start(ip_addresses, port, raw_files_directory):
    process_addresses(ip_addresses, port, raw_files_directory)
