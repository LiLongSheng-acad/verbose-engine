####内生噪声过滤器
class EndogenousNoiseFilter:
    """内生噪声过滤器——基于来源IP段和来源属性维度"""
    
    # 内网段（你的手工规则）
    INTERNAL_RANGES = [
        (ipaddress.IPv4Network('10.0.0.0/8'), '内网A类'),
        (ipaddress.IPv4Network('172.16.0.0/12'), '内网B类'),
        (ipaddress.IPv4Network('192.168.0.0/16'), '内网C类'),
    ]
    
    # 业务网段（你的公司业务网段标记）
    BUSINESS_RANGES = []  # 初始化时从台账加载
    
    def __init__(self, ledger: pd.DataFrame):
        self.business_ranges = self._load_business_ranges(ledger)
        self.noise_profile = defaultdict(lambda: {'hit_count': 0, 'stable': False})
    
    def classify_source(self, ip: str) -> Tuple[str, float]:
        """返回来源类型和A值衰减系数。
        内网来源衰减系数接近0，互联网来源保持1.0。"""
        try:
            ip_addr = ipaddress.IPv4Address(ip)
        except ValueError:
            return ('unknown', 1.0)
        
        for net, label in self.INTERNAL_RANGES:
            if ip_addr in net:
                return (label, 0.001)  # 内网告警A值几乎清零
        
        for net, label in self.business_ranges:
            if ip_addr in net:
                return (label, 0.01)   # 业务网段A值大幅衰减
        
        return ('internet', 1.0)       # 互联网来源保持原值
    
    def is_stable_noise(self, category: str) -> bool:
        """检查某类告警是否为稳定内生噪声。
        通过ΔD和ΔN的长期稳定性来判断。"""
        profile = self.noise_profile[category]
        return profile['stable']
    
    def update_stability(self, category: str, payload_hash: str, source_ip: str):
        """每次告警到达时更新稳定性统计"""
        profile = self.noise_profile[category]
        profile['hit_count'] += 1
        
        if profile['hit_count'] >= 100:
            profile['stable'] = True