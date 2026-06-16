####告警分类与台账映射
class AlertClassifier:
    """告警分类器，将SIEM告警映射到台账类别"""
    
    def __init__(self, ledger: pd.DataFrame):
        self.ledger = ledger
        self.category_map = dict(zip(ledger['category'], ledger.index))
    
    def classify(self, alert: AlertInput) -> str:
        if alert.category in self.category_map:
            return alert.category
        
        # 模糊匹配
        for cat in self.category_map:
            if cat.lower() in alert.category.lower():
                return cat
        
        return '自定义事件'  # 兜底类别