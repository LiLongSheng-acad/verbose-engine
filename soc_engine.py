import pandas as pd
import random

def main():
    # 配置
    TOTAL_BUDGET_HOURS = 40  # 每天总工时预算（5人×8小时）
    random.seed(42)  # 可选：固定随机种子，让结果可复现

    # 读取台账（指定实际编码，如 GBK）
    ledger = pd.read_csv('ledger.csv', encoding='gbk')
    ledger['kappa'] = ledger['s'] * ledger['t']  # 单条分析成本
    ledger['r_star'] = ledger.apply(
        lambda row: 1.0 if row['alpha'] * row['A'] > row['kappa'] else 0.0,
        axis=1
    )

    print("=== 台账与最优分析率 ===")
    print(ledger[['category', 'N', 'kappa', 'A', 'alpha', 'r_star']])

    # 读取告警流（同样指定编码）
    alerts = pd.read_csv('alerts.csv', encoding='gbk')

    # 统计每类告警实际到达量
    alert_counts = alerts['category'].value_counts().reset_index()
    alert_counts.columns = ['category', 'actual_N']

    # 合并台账
    merged = pd.merge(ledger, alert_counts, on='category', how='left')
    merged['actual_N'] = merged['actual_N'].fillna(0)

    # 初始总工时需求
    merged['needed_hours'] = merged['r_star'] * merged['actual_N'] * merged['t']
    total_needed = merged['needed_hours'].sum()

    # 如果超额，按A值降序削减低价值类别的r*
    if total_needed > TOTAL_BUDGET_HOURS:
        merged = merged.sort_values('A', ascending=False)  # 高价值在前
        remaining_budget = TOTAL_BUDGET_HOURS
        for idx, row in merged.iterrows():
            needed = row['r_star'] * row['actual_N'] * row['t']
            if remaining_budget >= needed:
                remaining_budget -= needed
            else:
                # 削减该类别
                max_possible_hours = remaining_budget
                max_possible_r = (max_possible_hours / (row['actual_N'] * row['t'])
                                  if row['actual_N'] > 0 else 0.0)
                merged.at[idx, 'r_star'] = max(0.0, min(1.0, max_possible_r))
                remaining_budget = 0
        merged = merged.sort_index()

    # 模拟裁定
    results = []
    consumed_hours = 0
    for _, alert in alerts.iterrows():
        cat = alert['category']
        r = (merged.loc[merged['category'] == cat, 'r_star'].values[0]
             if len(merged.loc[merged['category'] == cat]) > 0 else 0.0)
        if random.random() <= r:
            action = 'ANALYZE'
            t_val = (ledger.loc[ledger['category'] == cat, 't'].values[0]
                     if len(ledger.loc[ledger['category'] == cat]) > 0 else 0.01)
            consumed_hours += t_val
        else:
            action = 'IGNORE'
        results.append({'alert_id': alert['alert_id'], 'category': cat, 'action': action})

    results_df = pd.DataFrame(results)

    # 输出
    print("\n=== 裁定统计 ===")
    summary = results_df.groupby(['category', 'action']).size().unstack(fill_value=0)
    print(summary)
    print(f"\n总工时消耗: {consumed_hours:.2f} 小时 / 预算 {TOTAL_BUDGET_HOURS} 小时")
    print(f"剩余工时: {TOTAL_BUDGET_HOURS - consumed_hours:.2f} 小时")

    # 写出裁定结果
    results_df.to_csv('decisions.csv', index=False)

if __name__ == '__main__':
    main()