import os
import json
import glob
import struct
from loguru import logger


def extract_offset(blocks_data, offset):
    if offset:
        offset = int(offset)
        padding = struct.unpack('<H', blocks_data[offset * 512 + 2:offset * 512 + 4])[0]
        size = struct.unpack('<I', blocks_data[offset * 512 + 4:offset * 512 + 8])[0]
        return blocks_data[offset * 512 + 8:offset * 512 + 8 + size - padding]
    return b''


def extract_blocks(path):
    res = []
    if os.path.exists(os.path.join(path, 'SUBBLK.DBT')) and os.path.join(path, 'SUBBLK.DBF'):
        with open(os.path.join(path, 'SUBBLK.DBT'), 'rb') as f:
            blocks_data = f.read()
        with open(os.path.join(path, 'SUBBLK.DBF'), 'rb') as f:
            f.read(833)
            data = f.read(192)
            while len(data) == 192:
                # block_type = int(data[17:22])
                # block_num = int(data[22:27])
                offset1 = extract_offset(blocks_data, data[162:172].strip())
                offset2 = extract_offset(blocks_data, data[172:182].strip())
                offset3 = extract_offset(blocks_data, data[182:192].strip())
                block_data = offset1 + offset2 + offset3
                res.append(block_data.hex())
                data = f.read(192)

    return res


def compare_project(ip, blocks, project_path, offline_project_files_path, block_comparison_directory):
    all_offline_blocks_data = []
    for path in glob.glob(offline_project_files_path):
        all_offline_blocks_data += extract_blocks(path)

    res = {'ip': ip, 'project_path': project_path, 'online_blocks': dict()}

    for block in blocks:
        block_row = dict.fromkeys(['type', 'can_compare', 'match_to_offline'])
        block_row['block_type'] = block['type']
        block_row['can_compare'] = False
        block_row['match_to_offline'] = False

        if block['type'] in ('FB', 'FC', 'OB'):
            block_row['can_compare'] = True
            if 'interface_len' in block.keys(): # TODO: change only to interface_len
                block_size = block['interface_len'] + block['seg_len'] + block['mc7_len']
            else:
                block_size = block['body_len'] + block['seg_len'] + block['data_len']
            if block['data'] not in list(
                    map(lambda offline_block: offline_block[block_size:], all_offline_blocks_data)):
                block_row['match_to_offline'] = True

        block_id = block['type'] + '_' + str(block['block_num'])
        res['online_blocks'][block_id] = block_row

    ip_str = ip.replace('.', '_')
    with open(os.path.join(block_comparison_directory, 'ip-{}_proj-{}'.format(ip_str, os.path.basename(project_path))),
              'w') as f:
        json.dump(res, f)


def start(ip, blocks, block_comparison_directory, proj_def_path, proj_name=None):
    if not proj_def_path:
        proj_def_path = r"C:\ProgramData\Siemens\Automation\Step7\S7Proj"
    if not os.path.exists(proj_def_path):
        logger.debug(
            'projects directory: {} does not exist. use --offline_projects_directory to change directory path'.format(
                proj_def_path))
        return
    logger.info(
        'start offline/online project comparison: online blocks from: {}, projects directory path: {}'.format(ip,
                                                                                                              proj_def_path))

    if not blocks:
        logger.debug('no blocks to compare were found for given ip: {}'.format(ip))
        return

    if not proj_name:
        logger.debug('no project directory name was given: compare to all found project directories')
        projects = glob.glob(proj_def_path)
    else:
        project_path = os.path.join(proj_def_path, proj_name)
        if not os.path.exists(project_path):
            logger.error('project path: {} does not exist'.format(project_path))
            return
        projects = [project_path]

    for project_path in projects:
        logger.debug('compare to project: {}'.format(os.path.join(project_path)))
        offline_project_files_path = os.path.join(project_path, 'ombstx', 'offline', '*')
        compare_project(ip, blocks, project_path, offline_project_files_path, block_comparison_directory)

    if projects:
        logger.debug('comparison results were saved at: {}'.format(block_comparison_directory))
