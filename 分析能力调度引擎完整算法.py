####分析能力调度引擎完整算法
import pandas as pd
import numpy as np
from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta
import logging

@dataclass
class AlertInput:
    alert_id: str
    category: str           # 告警类别
    source_ip: str          # 源IP
    dest_ip: str            # 目标IP
    timestamp: datetime     # 时间戳
    payload_hash: str = ""  # payload哈希（用于计算ΔD）
    severity: float = 0.0   # 设备原始严重度

@dataclass
class Decision:
    alert_id: str
    action: str             # BLOCK / ANALYZE_MANUAL / ANALYZE_AUTO / IGNORE / HONEYPOT
    priority: float = 0.0   # 调度优先级（越高越先处理）
    reason: str = ""        # 决策理由
    ttl: int = 0           # 最大等待时间（秒），超时自动降级