import streamlit as st
from langchain_community.embeddings import HuggingFaceEmbeddings
from langchain_community.vectorstores import FAISS
from langchain.llms import Ollama
from langchain.chains import RetrievalQA
from langchain.schema import Document
import pandas as pd
import os
import time
import smtplib
from email.mime.text import MIMEText
from collections import Counter
import subprocess

VECTOR_DB_PATH = "faiss_index"
CSV_PATH = "suspicious_connections.csv"
LAST_TIME_FILE = ".last_log_time"

def load_logs():
    df = pd.read_csv(CSV_PATH)
    texts = [
        f"Connection from {row['id.orig_h']}:{row['id.orig_p']} to {row['id.resp_h']}:{row['id.resp_p']}, "
        f"Protocol: {row['proto']}, Service: {row['service']}, State: {row['conn_state']}, "
        f"Duration: {row['duration']}, Orig_bytes: {row['orig_bytes']}, Resp_bytes: {row['resp_bytes']}."
        for _, row in df.iterrows()
    ]
    documents = [Document(page_content=text) for text in texts]
    return df, documents

def is_new_log(log_path='conn.log'):
    if not os.path.exists(log_path): return False
    mtime = os.path.getmtime(log_path)
    if os.path.exists(LAST_TIME_FILE):
        with open(LAST_TIME_FILE, "r") as f:
            last = float(f.read().strip())
        if mtime == last: return False
    with open(LAST_TIME_FILE, "w") as f:
        f.write(str(mtime))
    return True

@st.cache_resource
def get_vectorstore():
    embed_model = HuggingFaceEmbeddings(
        model_name="intfloat/multilingual-e5-base",
        model_kwargs={"device": "cpu"},
        encode_kwargs={"normalize_embeddings": True}
    )
    if os.path.exists(VECTOR_DB_PATH):
        return FAISS.load_local(VECTOR_DB_PATH, embed_model, allow_dangerous_deserialization=True)
    else:
        _, documents = load_logs()
        vectordb = FAISS.from_documents(documents, embed_model)
        vectordb.save_local(VECTOR_DB_PATH)
        return vectordb

@st.cache_resource
def get_qa_chain():
    llm = Ollama(model="mistral")
    retriever = get_vectorstore().as_retriever()
    return RetrievalQA.from_chain_type(
        llm=llm,
        retriever=retriever,
        return_source_documents=True,
        chain_type_kwargs={"output_key": "answer"}
    )

st.set_page_config(page_title="Cyber Threat RAG Bot", layout="wide")
st.title("🛡️ Cyber Threat Detector with LLM + RAG")
st.markdown("This assistant analyzes Zeek logs and automatically detects anomalies using LLM + FAISS.")

qa_chain = get_qa_chain()

# Detect if new conn.log arrived
if is_new_log():
    st.info("♻️ Detected new conn.log file. Cleaning and updating vector DB...")
    result = subprocess.run(["python", "cleaner.py"], capture_output=True, text=True)

    if result.returncode != 0:
        st.error("❌ Failed to clean logs.")
        st.text(result.stderr)
    else:
        st.success("✅ Logs cleaned.")
        _, documents = load_logs()
        embed_model = HuggingFaceEmbeddings(
            model_name="intfloat/multilingual-e5-base",
            model_kwargs={"device": "cpu"},
            encode_kwargs={"normalize_embeddings": True}
        )
        vectordb = FAISS.from_documents(documents, embed_model)
        vectordb.save_local(VECTOR_DB_PATH)
        st.success("📦 Vector DB updated.")


df_logs, _ = load_logs()
if not df_logs.empty:
    top_ips = Counter(df_logs['id.orig_h']).most_common(5)
    top_proto = Counter(df_logs['proto']).most_common(5)
    st.markdown("### 📊 Traffic Summary Dashboard")
    st.bar_chart(pd.DataFrame(top_ips, columns=["IP", "Count"]).set_index("IP"))
    st.bar_chart(pd.DataFrame(top_proto, columns=["Protocol", "Count"]).set_index("Protocol"))

st.markdown("### 🧠 Auto Network Threat Analysis")
with st.spinner("🤖 Thinking about latest network activity..."):
    auto_query = "Based on the most recent Zeek network log data, is there any suspicious or dangerous activity happening?"
    result = qa_chain.invoke({"query": auto_query})
    st.markdown("### 🔍 LLM Analysis")
    st.write(result['result'])

    with st.expander("📄 Context Used"):
        for doc in result['source_documents']:
            st.markdown(f"- {doc.page_content}")


def send_alert(ip, count, reason="Suspicious activity"):
    msg = MIMEText(f"{reason} detected: IP {ip} triggered {count} events.")
    msg["Subject"] = f"⚠️ Cyber Alert: {reason}"
    msg["From"] = "alert@example.com"
    msg["To"] = "fawziahmed808@gmail.com"
    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login("fawziahmed808@gmail.com", "")
            server.send_message(msg)
        st.warning(f"🚨 Alert sent for {ip} — {reason}")
    except Exception as e:
        st.error(f"Failed to send alert: {e}")

def monitor_for_anomalies():
    if df_logs.empty:
        return
    rej_counts = df_logs[df_logs['conn_state'] == 'REJ']['id.orig_h'].value_counts()
    for ip, count in rej_counts.items():
        if count > 100:
            send_alert(ip, count, "High REJ connections (Port scan?)")
    s0_counts = df_logs[df_logs['conn_state'] == 'S0']['id.orig_h'].value_counts()
    for ip, count in s0_counts.items():
        if count > 50:
            send_alert(ip, count, "Suspicious S0 attempts")
    udp_suspects = df_logs[(df_logs['proto'] == 'UDP') & (df_logs['id.resp_p'].isin([0, 5353]))]
    for _, row in udp_suspects.iterrows():
        send_alert(row['id.orig_h'], 1, f"UDP to uncommon port {row['id.resp_p']}")
    ip_counts = df_logs['id.orig_h'].value_counts()
    for ip, count in ip_counts.items():
        if count > 500:
            send_alert(ip, count, "Possible DDoS")

if st.button("🚨 Run Anomaly Check"):
    monitor_for_anomalies()
