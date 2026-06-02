import pandas as pd
p = 'reports/siem_report_20260519_090043.csv'
try:
    df = pd.read_csv(p)
except Exception as e:
    print('ERROR reading CSV:', e)
    raise
count = int(df['rule_alert'].sum())
print('rule_alert count:', count)
if count:
    print(df[df['rule_alert']==1].head(20).to_csv(index=False))
else:
    print('No rule alerts found in this report.')
