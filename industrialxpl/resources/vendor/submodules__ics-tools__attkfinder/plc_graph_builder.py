#!/usr/local/bin/python3

# plc_graph_builder.py
# Date: June 2020

__version__ = '1.0.0'
__author__ = 'cpsSecResearcher'

import config
import os
import xml.etree.ElementTree as ET

from DBconn import Block


class CFG_Builder():
    Block_ID = 0
    prev_block = None
    open_blocks = dict()
    block_chain = list()

    def __init__(self, entity):
        prev_block = Block.nodes.order_by('-firstLine').first_or_none()
        self.entity = entity
        self.open_blocks = dict()
        self.block_chain = list()
        if not prev_block is None:
            self.Block_ID = int(prev_block.name[1:])
            prev_block.lastLine = self.Block_ID
            prev_block.save()
        self.prev_block = prev_block

        config.logger.debug(
            "    [!] Reference:: Previous block: {} \n\t open_blocks: {}\n\t \
            Block_chain {}"\
                .format(self.prev_block, self.open_blocks, self.block_chain))

    def new_block(self, line_id):
        self.Block_ID += 1
        config.rewrite_code.info(
            ' [+] Basic block: {}, starts on {}'.format(self.Block_ID, line_id))
        config.logger.debug(
            ' [+] New block: {}, starts on {}'.format(self.Block_ID, line_id))

        last_Block = Block.nodes.order_by('-firstLine').first_or_none()
        tblock = Block.get_or_create({
            'name': 'B' + str(self.Block_ID),
            'entity': self.entity,
            'firstLine': line_id})[0]

        if self.prev_block is None:
            self.prev_block = last_Block
        if not self.prev_block is None:
            self.prev_block.nextBlk.connect(tblock)
            if line_id > 1 and self.prev_block.lastLine is None:
                self.prev_block.lastLine = line_id - 1
            self.prev_block.save()
            config.logger.debug(
                "    [!] New block:: Pushing into DB: {} - Parameters: {}, {}, {}"\
                    .format(self.prev_block, self.prev_block.firstLine, 
                        self.prev_block.lastLine, self.prev_block.entity))

        self.this_block = tblock
        self.prev_block = tblock

    def close_layer(self):
        """
        This function closes the last layer of block nodes pending in the 
        open_blocks dictionary
        """
        open_blocks = self.open_blocks
        tblock = self.this_block
        block_chain = self.block_chain
        config.logger.debug(
            "    [!] Closing layer:: open_blocks: {} \n\t Block_chain: {}"\
                .format(self.open_blocks, self.block_chain))

        if len(open_blocks) == 0:
            return 0

        for lBlk in open_blocks[len(open_blocks)]:
            lBlk.nextBlk.connect(tblock)
            config.logger.debug(
                "    [!] Closing layer:: Linking {}-->{}"\
                    .format(lBlk.name, tblock.name))
            # If there is a common element between open_blocks[-1] and 
            # open_blocks[-2], It replaces the open_blocks[-2]'s element by 
            # tblock. i.e. 'IF ... END_IF' statement
            if len(open_blocks) > 1:
                open_blocks[len(open_blocks) - 1] = [
                    tblock if x == lBlk else x for x in open_blocks[
                        len(open_blocks) - 1]]
        
        del open_blocks[len(open_blocks)]
        if len(block_chain) > 0:
            block_chain = block_chain[:-1]

        if len(open_blocks) > 0:
            self.add_current_block_to_layer()

        self.open_blocks = open_blocks
        self.block_chain = block_chain
        config.logger.debug(
            "    [!] Layer closed:: Block_chain: {}".format(self.block_chain))
        config.logger.debug(
            "    [!] Layer closed:: open_blocks: {}".format(self.open_blocks))

    def add_current_block_to_layer(self):
        tblock = self.this_block
        config.logger.debug(
            "    [!] Adding block {} to open_blocks: {}"\
                .format(tblock.name, self.open_blocks))
        self.open_blocks[len(self.open_blocks)].append(tblock)

    def delete_root_block_in_layer(self):
        '''
        This function process ELSE conditional, it includes this_block into 
        open_blocks and remove root conditional from open_blocks
        '''
        clean_layer = self.open_blocks[len(self.open_blocks)]
        config.logger.debug(
            "    [!] Deleting_root_block:: open_blocks: {} \n\t \
            Block_chain: {}"\
                .format(self.open_blocks, self.block_chain))

        # include this_block into open_blocks
        self.add_current_block_to_layer()
        root_block = self.get_root_block_in_layer()
        clean_layer.remove(root_block)
        self.open_blocks[len(self.open_blocks)] = clean_layer
        config.logger.debug(
            "    [!] Removing root_block: {}". format(root_block))
        config.logger.debug(
            "    [!] Deleting_root_block(post):: open_blocks: {} \n\t \
            Block_chain: {}"\
                .format(self.open_blocks, self.block_chain))

    def add_current_block_to_blockchain(self):
        self.block_chain.append(self.this_block)
        config.logger.debug(
            "    [!] Adding block {} to block_chain: {}"\
                .format(self.this_block, self.block_chain))

    def new_layer(self, empty=False):
        tblock = self.this_block
        if empty:
            self.open_blocks[len(self.open_blocks) + 1] = []
        else:
            self.open_blocks[len(self.open_blocks) + 1] = [tblock]

        config.logger.debug(
            "    [!] Adding new layer to open_blocks: {}"\
                .format(self.open_blocks))

    def get_root_block_in_layer(self):
        root_block = None
        if len(self.open_blocks) > 0:
            root_block = self.open_blocks[len(self.open_blocks)][0]
        return root_block

