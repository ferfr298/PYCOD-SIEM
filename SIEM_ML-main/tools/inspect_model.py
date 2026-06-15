import pickle
from pathlib import Path
p = Path(__file__).resolve().parent.parent / 'memory' / 'siem_anomaly_model.pkl'
if not p.exists():
    print('NO_MODEL')
    raise SystemExit(0)
with p.open('rb') as f:
    a = pickle.load(f)
print('SAVED_AT:', a.get('saved_at'))
print('FEATURE_COLS:', a.get('feature_cols'))
print('MODEL_TYPE:', type(a.get('model')))
