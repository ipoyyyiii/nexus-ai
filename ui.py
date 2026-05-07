import os
import base64
import streamlit as st
from dotenv import load_dotenv
from crewai import Agent, Task, Crew
from custom_tools import baca_log_burp, tembak_payload
from langchain_anthropic import ChatAnthropic
from langchain_openai import ChatOpenAI

load_dotenv()

st.set_page_config(page_title="Pentest OS ", page_icon="🕵️‍♂️", layout="wide")


if "messages" not in st.session_state:
    st.session_state.messages = []

# SIDEBAR
with st.sidebar:
    st.header("⚙️ System Config")
    ant_key = st.text_input("Anthropic Key", value=os.environ.get("ANTHROPIC_API_KEY", ""), type="password")
    or_key = st.text_input("OpenRouter Key", value=os.environ.get("OPENROUTER_API_KEY", ""), type="password")
    
    st.divider()
    # Mode Selector
    pentest_mode = st.radio(
        "🎯 Select Operations Mode",
        ["Sniper Mode (Specific Goal)", "General Mode (Full Recon)"],
        index=0
    )
    
    if pentest_mode == "Sniper Mode (Specific Goal)":
        st.caption("Fokus: Menembak 1 celah spesifik sampai dapat.")
    else:
        st.caption("Fokus: Scanning luas, cari celah apapun yang terbuka.")

    if st.button("🗑️ Clear History"):
        st.session_state.messages = []
        st.rerun()

# --- MAIN INTERFACE ---
st.title("🕵️‍♂️ AI Pentest Interactive OS")
st.caption(f"Mode Aktif: {pentest_mode}")

# History Chat
for message in st.session_state.messages:
    with st.chat_message(message["role"]):
        st.markdown(message["content"])

# --- INPUT AREA (UPLOAD + CHAT) ---
input_container = st.container()
with input_container:
    col_up, col_txt = st.columns([1, 4])
    with col_up:
        uploaded_file = st.file_uploader("📎 Attach Image", type=["png", "jpg", "jpeg"], label_visibility="collapsed")
    
    if prompt := st.chat_input("Apa misi kita hari ini, men?"):
        st.session_state.messages.append({"role": "user", "content": prompt})
        with st.chat_message("user"):
            st.markdown(prompt)

        with st.chat_message("assistant"):
            with st.spinner("Executing Operations..."):
                try:
                    llm_claude = ChatAnthropic(model_name="claude-3-5-sonnet-20240620", anthropic_api_key=ant_key)
                    llm_llama = ChatOpenAI(model="meta-llama/llama-3-70b-instruct", base_url="https://openrouter.ai/api/v1", api_key=or_key)

                    # LOGIC MODE
                    system_context = ""
                    if pentest_mode == "Sniper Mode (Specific Goal)":
                        system_context = "Fokuslah hanya pada GOAL spesifik user. Jangan melebar ke celah lain."
                    else:
                        system_context = "Lakukan analisis menyeluruh. Cari semua potensi celah (XSS, SQLi, IDOR, dll) secara global."

                    analis = Agent(
                        role='Senior Web Traffic Analyzer',
                        goal=f'{system_context} Analisis input dan log.',
                        backstory='Kamu adalah leader red team yang sangat teknis.',
                        llm=llm_claude,
                        tools=[baca_log_burp],
                        verbose=True
                    )

                    eksekutor = Agent(
                        role='Exploit Executer',
                        goal='Eksekusi payload sesuai perintah analis.',
                        backstory='Kamu adalah tangan kanan yang ahli dalam automation exploit.',
                        llm=llm_llama,
                        tools=[tembak_payload],
                        verbose=True
                    )

                    tugas = Task(
                        description=f"Perintah User: {prompt}. Mode: {pentest_mode}. Gunakan tools jika perlu.",
                        expected_output="Hasil analisis/eksekusi mendalam.",
                        agent=analis
                    )

                    crew = Crew(agents=[analis, eksekutor], tasks=[tugas], verbose=True)
                    response = crew.kickoff()

                    st.markdown(response)
                    st.session_state.messages.append({"role": "assistant", "content": str(response)})

                except Exception as e:
                    st.error(f"Error: {e}")