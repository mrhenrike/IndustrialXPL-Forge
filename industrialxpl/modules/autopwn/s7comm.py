"""industrialxpl AutoPwn — s7comm segment. # authorized use only"""
from .base import SegmentAutoPwn
class S7commAutoPwn(SegmentAutoPwn):
    def __init__(self, targets, **kw): super().__init__("s7comm", targets, **kw)
