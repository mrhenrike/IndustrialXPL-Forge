import os
import json
import warnings
import datetime
import ipaddress
import pandas as pd
import networkx as nx
from loguru import logger
from copy import deepcopy
import matplotlib.pyplot as plt
from collections import Counter
from pathlib import Path

from tqdm import tqdm

warnings.simplefilter(action='ignore', category=FutureWarning)


def get_called_blocks_edges(block_id, called_blocks):
    if (not called_blocks) or (called_blocks != called_blocks):  # nan
        return []
    return [(block_id, called_block) for called_block in called_blocks]


def call_tree(df, ip_addresses, export_dpath):
    logger.info('create call tree graph')
    for ip in ip_addresses:
        df_ip = deepcopy(df.loc[df['ip'] == ip])
        df_ip['called_blocks_edges'] = df_ip.apply(
            lambda row: get_called_blocks_edges(row['block_id'], row['used_block']), axis=1)

        blocks_graph = nx.DiGraph()
        blocks_graph.add_nodes_from(df_ip.block_id.tolist())
        blocks_graph.add_edges_from(sum(df_ip['called_blocks_edges'].tolist(), []))
        blocks_graph.remove_nodes_from(list(nx.isolates(blocks_graph)))
        nx.draw(blocks_graph, with_labels=True, node_size=400, node_color='#ced2d9')
        plt.title('call tree - {}'.format(ip))

        ip_fmt = ip.replace('.', '_')
        export_ip_dpath = os.path.join(export_dpath, ip_fmt)
        path = Path(export_ip_dpath)
        path.mkdir(parents=True, exist_ok=True)
        plt.savefig(os.path.join(export_ip_dpath, 'call_tree_{}.png'.format(ip_fmt)), dpi=300, bbox_inches='tight')



def map_module_to_cpu(cpu_modules_mapping, module):
    module = module.replace(' ', '')
    if module in cpu_modules_mapping['300'].keys():
        return cpu_modules_mapping['300'][module]
    return ''


def map_module_to_cpu_series(cpu_modules_mapping, module):
    module = module.replace(' ', '')
    if module in cpu_modules_mapping['300'].keys():
        return '300'
    return ''


def get_block_name_by_cpu(func_mapping, block_id, cpu_series):
    if block_id in func_mapping.keys():
        if cpu_series:
            if func_mapping[block_id][cpu_series]:
                return func_mapping[block_id][cpu_series]
        return func_mapping[block_id]['default']
    return []


def parse_ob_roles_results(df, ip_addresses):
    result_msg = ''

    for ip in ip_addresses:
        ob_blocks = df.loc[(df['ip'] == ip) & (df['type'] == 'OB')]
        if not ob_blocks.empty:
            result_msg += '\n\tip: {}'.format(ip)
            for i, row in ob_blocks.iterrows():
                result_msg += '\n\t\tOB {} - start event: {}, used blocks: {}'.format(row.block_num, row.ob_role,
                                                                                      row.used_block)

    if len(result_msg) > 0:
        logger.info('Organizational blocks found:' + result_msg)
    else:
        logger.info('No Organizational blocks were found.')


def ob_roles_check(df, ip_addresses):
    logger.debug('executing organizational block check')
    with open("./mapping/ob_mapping.json", 'rb') as f:
        ob_mapping = json.loads(f.read())

    df.loc[df['type'] == 'OB', 'ob_role'] = df['block_num'].apply(
        lambda block_num: ob_mapping[str(block_num)]['start_event'] if str(
            block_num) in ob_mapping.keys() else 'Unknown')

    parse_ob_roles_results(df, ip_addresses)


def parse_network_results(df, ip_addresses):
    result_msg = ''

    for ip in ip_addresses:
        ip_anomaly_found = False
        tcon_params_msg = ''
        comm_blocks_used_msg = ''
        tcon_params = df.loc[(df['ip'] == ip) & (df['db_ext_header_tcon_params_block_length'].isnull() == False)]
        if not tcon_params.empty:
            ip_anomaly_found = True
            tcon_params_msg += '\n\t\tnetwork parameters found for:'
            for i, row in tcon_params.iterrows():
                if row.conn_remote_address != row.conn_remote_address:  # nan
                    is_remote_addr_external = 'unknown'
                else:
                    is_remote_addr_external = not row.conn_remote_address['is_private']
                tcon_params_msg += '\n\t\t\t{} {} - connection type: {}, active connection: {}, local port: {}, remote ip: {}, is remote ip external: {}, remote port: {}'.format(
                    row.type, row.block_num, row.db_ext_header_tcon_params_connection_type,
                    True if row.db_ext_header_tcon_params_active_est else False,
                    row.db_ext_header_tcon_params_local_tsap_id,
                    row.db_ext_header_tcon_params_rem_staddr, is_remote_addr_external,
                    row.db_ext_header_tcon_params_rem_tsap_id)

        uses_network_blocks = df.loc[(df['ip'] == ip) & (df['uses_communication_block'] == True)]
        if not uses_network_blocks.empty:
            ip_anomaly_found = True
            block_ids = uses_network_blocks.block_id.unique().tolist()
            tcon_params_msg += '\n\t\tThe following blocks uses network functionality: {}'.format(block_ids)

        if ip_anomaly_found:
            result_msg += '\n\tip: {}{}{}'.format(ip, tcon_params_msg, comm_blocks_used_msg)

    if len(result_msg) > 0:
        logger.info('Network usage found:' + result_msg)
    else:
        logger.info('No network usage was found.')


def is_use_communication_blocks(df, ip, used_block):
    if used_block != used_block:  # nan
        return False
    used_block = set(used_block)
    for block in used_block:
        if '[' in block:  # TODO: fix later calling to [..]
            continue
        block_type, block_num = block.split(' ')
        row = df.loc[(df['ip'] == ip) & (df['type'] == block_type) & (df['block_num'] == int(block_num))]
        if not row.empty:
            if row.iloc[0].block_family in ('COMM', 'COM_FUNC'):
                return True
    return False


def address_check(tcon_remote_address):
    conn_remote_address = {'is_private': False}
    try:
        conn_remote_address['is_private'] = ipaddress.ip_address(tcon_remote_address).is_private
    except:
        pass

    return conn_remote_address


def network_check(df, ip_addresses):
    logger.debug('executing block network check')
    conn_params_df = df.loc[df['db_ext_header_tcon_params_block_length'].isnull() == False]

    df.loc[df.index.isin(conn_params_df.index), 'conn_remote_address'] = df[
        'db_ext_header_tcon_params_rem_staddr'].apply(lambda tcon_params: address_check(tcon_params))

    df.loc[
        (df['used_block'].isnull() == False) & (df['used_block'].str.len() > 0), 'uses_communication_block'] = df.apply(
        lambda row: is_use_communication_blocks(df, row['ip'], row['used_block']), axis=1)

    parse_network_results(df, ip_addresses)


def process_dates_results(df, ip_addresses):
    lower_bound_modified_delta = 7
    lower_bound_interface_delta = 7
    result_msg = ''

    for ip in ip_addresses:
        ip_anomaly_found = False
        modified_msg = ''
        interface_msg = ''
        modified_delta_anomaly = df.loc[(df['ip'] == ip) & (
                df['delta_current_time_vs_last_modified'] < datetime.timedelta(days=lower_bound_modified_delta))]
        interface_delta_anomaly = df.loc[
            (df['ip'] == ip) & (df['delta_current_time_vs_last_interface_change'] < datetime.timedelta(
                days=lower_bound_interface_delta))]
        if not modified_delta_anomaly.empty:
            ip_anomaly_found = True
            block_ids = modified_delta_anomaly.block_id.unique().tolist()
            modified_msg += '\n\t\t{} blocks modified in that last {} days: {}'.format(len(block_ids),
                                                                                       lower_bound_modified_delta,
                                                                                       block_ids)
        if not interface_delta_anomaly.empty:
            ip_anomaly_found = True
            block_ids = interface_delta_anomaly.block_id.unique().tolist()
            interface_msg += '\n\t\t{} blocks interfaces modified in that last {} days: {}'.format(len(block_ids),
                                                                                                   lower_bound_interface_delta,
                                                                                                   block_ids)

        if ip_anomaly_found:
            result_msg += '\n\tip: {}{}{}'.format(ip, modified_msg, interface_msg)

    if len(result_msg) > 0:
        logger.info('Date fields anomalies found:' + result_msg)
    else:
        logger.info('No date fields anomalies were found.')


def dates_check(df, ip_addresses):
    logger.debug('executing block dates check')
    current_time = datetime.datetime.now()
    df['delta_current_time_vs_last_modified'] = df['last_modified'].apply(
        lambda t: (current_time - datetime.datetime.fromisoformat(t)))
    df['delta_current_time_vs_last_interface_change'] = df['last_interface_change'].apply(
        lambda t: (current_time - datetime.datetime.fromisoformat(t)))
    df['delta_last_modified_vs_interface_change'] = df.apply(lambda row: (
            datetime.datetime.fromisoformat(row['last_modified']) - datetime.datetime.fromisoformat(
        row['last_interface_change'])), axis=1)

    for ip in tqdm(ip_addresses, desc='dates check'):
        min_last_modified = datetime.datetime.fromisoformat(min(df.loc[df['ip'] == ip]['last_modified']))
        max_last_modified = datetime.datetime.fromisoformat(max(df.loc[df['ip'] == ip]['last_modified']))

        df.loc[df['ip'] == ip, 'delta_to_min_last_modified'] = df['last_modified'].apply(
            lambda last_modified: datetime.datetime.fromisoformat(last_modified) - min_last_modified)
        df.loc[df['ip'] == ip, 'delta_to_max_last_modified'] = df['last_modified'].apply(
            lambda last_modified: max_last_modified - datetime.datetime.fromisoformat(last_modified))

        min_last_interface_change = datetime.datetime.fromisoformat(
            min(df.loc[df['ip'] == ip]['last_interface_change']))
        max_last_interface_change = datetime.datetime.fromisoformat(
            max(df.loc[df['ip'] == ip]['last_interface_change']))

        df.loc[df['ip'] == ip, 'delta_to_min_last_interface_change'] = df['last_interface_change'].apply(
            lambda last_interface_change: datetime.datetime.fromisoformat(
                last_interface_change) - min_last_interface_change)
        df.loc[df['ip'] == ip, 'delta_to_max_last_interface_change'] = df['last_interface_change'].apply(
            lambda last_interface_change: max_last_interface_change - datetime.datetime.fromisoformat(
                last_interface_change))

    process_dates_results(df, ip_addresses)


def process_author_results(df, ip_addresses):
    lower_bound = 3
    upper_bound = 80

    result_msg = ''

    for ip in ip_addresses:
        ip_anomaly_found = False
        lower_bound_msg = ''
        upper_bound_msg = ''
        author_anomaly = df.loc[(df['ip'] == ip) & (df['author_blocks_percentage'] < lower_bound)]
        if not author_anomaly.empty:
            ip_anomaly_found = True
            author_names = author_anomaly.author_name.unique().tolist()
            lower_bound_msg += '\n\t\tless than {}% blocks presence: {} authors found: {}'.format(
                lower_bound, len(author_names), author_names)
        author_anomaly = df.loc[(df['ip'] == ip) & (df['author_blocks_percentage'] > upper_bound)]
        if not author_anomaly.empty:
            ip_anomaly_found = True
            author_names = author_anomaly.author_name.unique().tolist()
            upper_bound_msg += '\n\t\tmore than {}% blocks presence: {} authors found: {}'.format(
                upper_bound, len(author_names), author_names)

        if ip_anomaly_found:
            result_msg += '\n\tip: {}{}{}'.format(ip, lower_bound_msg, upper_bound_msg)

    if len(result_msg) > 0:
        logger.info('Author field anomalies found:' + result_msg)
    else:
        logger.info('No author field anomalies were found.')


def author_check(df, ip_addresses):
    logger.debug('executing block author check')
    agg_ips = df.groupby('author_name')['ip', 'author_name'].agg(['unique'])
    author_names = list(map(lambda e: e[0], agg_ips[('author_name', 'unique')]))
    unique_ips = list(map(lambda e: e, agg_ips[('ip', 'unique')]))
    author_plcs_amount = dict.fromkeys(author_names)
    for i in range(len(author_names)):
        author_plcs_amount[author_names[i]] = unique_ips[i]

    for ip in ip_addresses:
        df_ip = df.loc[df['ip'] == ip]
        ip_blocks_amount = len(df_ip)
        authors_count = Counter(df_ip.author_name)
        # how many blocks share this author for this specific ip (percentage)
        df.loc[df['ip'] == ip, 'author_blocks_percentage'] = df['author_name'].apply(
            lambda author_name: (authors_count[author_name] / ip_blocks_amount) * 100)
        # how many plcs share this author (percentage)
        df.loc[df['ip'] == ip, 'author_plcs_percentage'] = df['author_name'].apply(
            lambda author_name: (len(author_plcs_amount[author_name]) / len(ip_addresses)) * 100)

    process_author_results(df, ip_addresses)


def store_df(df, fpath):
    df.drop(['body', 'data', 'interface', 'seg', 'local_data', 'body_parse'], axis=1, inplace=True)
    df.to_csv(fpath, escapechar='\\')


def start(parsed_devices_data, logic_files_directory, logic_all=False, logic_author=False, logic_dates=False,
          logic_network=False, logic_ob=False):
    logger.info('start executing block logics')
    # dbscan_f = True
    df = pd.DataFrame(parsed_devices_data)
    if df.empty:
        logger.debug('no blocks exist for logic check')
        return
    df['block_id'] = df['type'].astype(str) + "_" + df["block_num"].astype(str)

    ip_addresses = df.ip.unique().tolist()

    if logic_all or logic_author:
        author_check(df, ip_addresses)
    if logic_all or logic_dates:
        dates_check(df, ip_addresses)
    if logic_all or logic_network:
        network_check(df, ip_addresses)
    if logic_all or logic_ob:
        ob_roles_check(df, ip_addresses)



    call_tree(df, ip_addresses,logic_files_directory)

    store_df(df, os.path.join(logic_files_directory, 'blocks_metadata.csv'))
