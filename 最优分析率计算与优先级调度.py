####最优分析率计算与优先级调度
class Engine:
    """分析能力调度引擎"""
    
    def __init__(self, ledger_path: str, total_budget_hours: float = 40):
        self.ledger = pd.read_csv(ledger_path)
        self.total_budget = total_budget_hours
        self.consumed_hours = 0
        self.noise_filter = EndogenousNoiseFilter(self.ledger)
        self.ueba = BaselineDeviationDetector(self.ledger)
        self.classifier = AlertClassifier(self.ledger)
        self.ip_history = defaultdict(list)  # IP -> 历史告警列表
        self.blocked_ips = set()
    
    def decide(self, alert: AlertInput) -> Decision:
        """对单条告警做出裁定"""
        
        # Step 1: 来源分类
        source_type, decay_factor = self.noise_filter.classify_source(alert.source_ip)
        
        # Step 2: 如果是内网或业务网段，直接忽略
        if decay_factor <= 0.01:
            return Decision(
                alert_id=alert.alert_id,
                action='IGNORE',
                priority=0.0,
                reason=f'内生噪声({source_type})'
            )
        
        # Step 3: 告警分类
        category = self.classifier.classify(alert)
        params = self.ledger[self.ledger['category'] == category].iloc[0]
        
        # Step 4: 台账A值（应用衰减）
        A = params['A'] * decay_factor
        kappa = params['s'] * params['t']
        alpha = params['alpha']
        
        # Step 5: UEBA偏离检测
        deviation, dev_reason = self.ueba.check_deviation(alert)
        if deviation > 0.5:
            # 高偏离度→提升A值
            A = A * (1 + deviation)
        
        # Step 6: 同源关联优先
        self.ip_history[alert.source_ip].append(alert)
        if self._has_deterministic_attack(alert.source_ip):
            self.blocked_ips.add(alert.source_ip)
            return Decision(
                alert_id=alert.alert_id,
                action='BLOCK',
                priority=1.0,
                reason='同源关联命中已知攻击'
            )
        
        # Step 7: 最优分析率r*
        if alpha * A > kappa:
            r_star = 1.0
            action = 'ANALYZE_MANUAL' if r_star >= 0.8 else 'ANALYZE_AUTO'
        else:
            r_star = 0.0
            action = 'IGNORE'
        
        # Step 8: 超额削减
        needed = r_star * params['t']
        if self.consumed_hours + needed > self.total_budget:
            # 当前剩余预算
            remaining = self.total_budget - self.consumed_hours
            max_r = remaining / params['t'] if params['t'] > 0 else 0
            r_star = max(0.0, min(r_star, max_r))
            action = 'IGNORE' if r_star < 0.1 else 'ANALYZE_AUTO'
        
        # Step 9: 调度优先级（基于A值和时间紧迫度）
        urgency = self._calc_urgency(alert)
        priority = A * urgency / (kappa + 1e-6)
        
        # Step 10: 最大等待时间（基于类别紧迫度）
        ttl = self._calc_ttl(category, A)
        
        # 更新工时消耗
        if r_star > 0:
            self.consumed_hours += r_star * params['t']
        
        return Decision(
            alert_id=alert.alert_id,
            action=action,
            priority=priority,
            reason=f'r*={r_star:.2f}, A={A:.0f}, dev={deviation:.2f}',
            ttl=ttl
        )
    
    def _has_deterministic_attack(self, ip: str) -> bool:
        """检查同源告警中是否存在决定性攻击证据"""
        history = self.ip_history.get(ip, [])
        high_severity = [a for a in history if a.severity >= 0.9]
        return len(high_severity) > 0
    
    def _calc_urgency(self, alert: AlertInput) -> float:
        """计算时间紧迫度——基于攻击类型和已等待时间"""
        category = self.classifier.classify(alert)
        if '漏洞利用' in category or '代码执行' in category or 'Webshell' in category:
            return 10.0  # 紧急类
        if '暴力破解' in category or 'SQL注入' in category:
            return 5.0   # 高紧迫度类
        if '扫描' in category or '探测' in category:
            return 1.0   # 低紧迫度类
        return 3.0
    
    def _calc_ttl(self, category: str, A: float) -> int:
        """计算最大等待时间，超时自动降级。
        高A值类别的TTL更短，低A值类别可以等更久。"""
        if A >= 1000000:
            return 300   # 高价值告警5分钟内必须处理
        if A >= 100000:
            return 900   # 中价值告警15分钟
        if A >= 10000:
            return 3600  # 低价值告警1小时
        return 7200      # 最低价值告警2小时