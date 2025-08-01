import pandas as pd
import os

def load_conn_log(path):
    if not os.path.exists(path):
        raise FileNotFoundError(f"File not found: {path}")
    
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        lines = [line for line in f if not line.startswith('#')]


    columns = [
        'ts', 'uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p',
        'proto', 'service', 'duration', 'orig_bytes', 'resp_bytes',
        'conn_state', 'local_orig', 'local_resp', 'missed_bytes',
        'history', 'orig_pkts', 'orig_ip_bytes',
        'resp_pkts', 'resp_ip_bytes', 'tunnel_parents', 'ip_proto'
    ]

    data = []
    for line in lines:
        row = line.strip().split('\t')
        if len(row) == len(columns):
            data.append(row)

    if not data:
        raise ValueError("No valid data found in conn.log")

    df = pd.DataFrame(data, columns=columns)
    return df


def analyze_suspicious(df):
    for col in ['orig_bytes', 'resp_bytes', 'duration']:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors='coerce')
        else:
            df[col] = pd.NA

    suspicious1 = df[(df['service'] == '-') & (df['duration'].isna())]
    suspicious2 = df[df['conn_state'].isin(['S0', 'SH', 'REJ', 'RSTO', 'RSTOS0'])]
    suspicious3 = df[(df['orig_bytes'] < 100) & (df['resp_bytes'] > 10000)]

    suspicious = pd.concat([suspicious1, suspicious2, suspicious3]).drop_duplicates()
    return suspicious


def clean_and_save(path='conn.log'):
    df = load_conn_log(path)
    suspicious_df = analyze_suspicious(df)

    if not df.empty:
        df.to_csv('conn_cleaned.csv', index=False)

    if not suspicious_df.empty:
        suspicious_df.to_csv('suspicious_connections.csv', index=False)

    return len(df), len(suspicious_df)


if __name__ == '__main__':
    try:
        total, sus = clean_and_save()
        print(f"✅ Loaded {total} rows - Suspicious: {sus}")
    except Exception as e:
        print(f"❌ Error: {e}")
