# 初始化引擎
engine = Engine('ledger.csv', total_budget_hours=40)

# 处理告警流
for alert in incoming_alerts:
    decision = engine.decide(alert)
    execute_decision(decision)  # 执行裁定