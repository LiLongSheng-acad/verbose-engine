####UEBA基线偏离检测
class BaselineDeviationDetector:
    """UEBA基线偏离检测——基于统计信号的原型实现"""
    
    def __init__(self, ledger: pd.DataFrame):
        self.user_baselines = {}  # user_id -> baseline profile
        self.entity_baselines = {}  # entity_id -> baseline profile
    
    def check_deviation(self, alert: AlertInput) -> Tuple[float, str]:
        """返回偏离度和偏离类型。
        偏离度0.0表示完全正常，1.0表示严重偏离基线。"""
        
        # 规则1：非工作时间告警
        hour = alert.timestamp.hour
        if hour < 7 or hour > 20:
            return (0.4, '非工作时间活动')
        
        # 规则2：高严重度告警直接标记
        if alert.severity >= 0.8:
            return (0.6, '高严重度告警')
        
        # 规则3：已知恶意源IP（从威胁情报库查询）
        if self._is_known_malicious(alert.source_ip):
            return (0.9, '已知恶意源IP')
        
        return (0.0, '正常')
    
    def _is_known_malicious(self, ip: str) -> bool:
        """查询威胁情报库——实际部署时对接TI API"""
        return False