"""VPS Attack Detector Dashboard.

Streamlit dashboard for visualizing security alerts and attack patterns.
"""

import os
from datetime import datetime, timedelta

import pandas as pd
import plotly.express as px
import streamlit as st

DATA_PATH = os.getenv("DATA_PATH", "/app/data")
ALERTS_PATH = os.path.join(DATA_PATH, "gold", "alerts")
IP_STATS_PATH = os.path.join(DATA_PATH, "gold", "ip_stats")
SUMMARY_PATH = os.path.join(DATA_PATH, "gold", "attack_summary")


st.set_page_config(
    page_title="VPS Attack Detector",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


@st.cache_data(ttl=300)
def load_alerts() -> pd.DataFrame:
    """Load alerts from Gold layer."""
    if not os.path.exists(ALERTS_PATH):
        return pd.DataFrame()

    try:
        df = pd.read_parquet(ALERTS_PATH)
        if "timestamp" in df.columns:
            df["timestamp"] = pd.to_datetime(df["timestamp"])
        return df
    except Exception as e:
        st.error(f"Erro ao carregar alertas: {e}")
        return pd.DataFrame()


@st.cache_data(ttl=300)
def load_ip_stats() -> pd.DataFrame:
    """Load IP statistics from Gold layer."""
    if not os.path.exists(IP_STATS_PATH):
        return pd.DataFrame()

    try:
        return pd.read_parquet(IP_STATS_PATH)
    except Exception:
        return pd.DataFrame()


def severity_color(severity: str) -> str:
    """Get color for severity level."""
    colors = {
        "critical": "#FF0000",
        "high": "#FF6600",
        "medium": "#FFCC00",
        "low": "#00CC00",
    }
    return colors.get(severity, "#808080")


def main():
    st.title("🛡️ VPS Attack Detector")
    st.markdown("**Monitoramento de segurança para seu servidor**")

    with st.sidebar:
        st.header("Filtros")

        date_range = st.date_input(
            "Período",
            value=(datetime.now() - timedelta(days=7), datetime.now()),
            max_value=datetime.now(),
        )

        severity_filter = st.multiselect(
            "Severidade",
            options=["critical", "high", "medium", "low"],
            default=["critical", "high", "medium"],
        )

        attack_types = st.multiselect(
            "Tipo de Ataque",
            options=[
                "ssh_brute_force",
                "credential_stuffing",
                "success_after_failure",
                "path_scanning",
                "scanner_detected",
                "rate_spike",
            ],
            default=[],
        )

        st.markdown("---")
        if st.button("🔄 Atualizar Dados"):
            st.cache_data.clear()
            st.rerun()

    alerts_df = load_alerts()

    if alerts_df.empty:
        st.warning(
            "Nenhum dado disponível. Execute o pipeline de ingestão primeiro "
            "ou verifique se há logs nos diretórios configurados."
        )

        st.info(
            """
            **Para começar:**
            1. Certifique-se de que os logs estão em `data/sample_logs/`
            2. Execute o DAG `ingest_and_detect` no Airflow
            3. Aguarde o processamento e retorne aqui
            """
        )
        return

    if "timestamp" in alerts_df.columns and len(date_range) == 2:
        start_date, end_date = date_range
        mask = (alerts_df["timestamp"].dt.date >= start_date) & (
            alerts_df["timestamp"].dt.date <= end_date
        )
        filtered_df = alerts_df[mask]
    else:
        filtered_df = alerts_df

    if severity_filter:
        filtered_df = filtered_df[filtered_df["severity"].isin(severity_filter)]

    if attack_types:
        filtered_df = filtered_df[filtered_df["alert_type"].isin(attack_types)]

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric("Total de Alertas", len(filtered_df))

    with col2:
        critical_count = len(filtered_df[filtered_df["severity"] == "critical"])
        st.metric("Alertas Críticos", critical_count, delta_color="inverse")

    with col3:
        unique_ips = filtered_df["source_ip"].nunique()
        st.metric("IPs Únicos", unique_ips)

    with col4:
        if "country" in filtered_df.columns:
            unique_countries = filtered_df["country"].nunique()
            st.metric("Países", unique_countries)
        else:
            st.metric("Países", "N/A")

    st.markdown("---")

    col1, col2 = st.columns(2)

    with col1:
        st.subheader("🎯 Top 10 IPs Atacantes")

        ip_counts = (
            filtered_df.groupby("source_ip").size().sort_values(ascending=True).tail(10)
        )

        if not ip_counts.empty:
            fig = px.bar(
                x=ip_counts.values,
                y=ip_counts.index,
                orientation="h",
                labels={"x": "Número de Alertas", "y": "IP"},
                color=ip_counts.values,
                color_continuous_scale="Reds",
            )
            fig.update_layout(showlegend=False, height=400)
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("Nenhum dado para exibir")

    with col2:
        st.subheader("📊 Distribuição por Tipo de Ataque")

        type_counts = filtered_df["alert_type"].value_counts()

        if not type_counts.empty:
            fig = px.pie(
                values=type_counts.values,
                names=type_counts.index,
                hole=0.4,
            )
            fig.update_layout(height=400)
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("Nenhum dado para exibir")

    st.markdown("---")

    col1, col2 = st.columns(2)

    with col1:
        st.subheader("📈 Timeline de Alertas")

        if "timestamp" in filtered_df.columns and not filtered_df.empty:
            timeline = (
                filtered_df.set_index("timestamp")
                .resample("1H")
                .size()
                .reset_index(name="count")
            )

            fig = px.line(
                timeline,
                x="timestamp",
                y="count",
                labels={"timestamp": "Hora", "count": "Alertas"},
            )
            fig.update_layout(height=300)
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("Dados de timestamp não disponíveis")

    with col2:
        st.subheader("🌍 Alertas por País")

        if "country" in filtered_df.columns:
            country_counts = (
                filtered_df[filtered_df["country"] != "Unknown"]
                .groupby("country")
                .size()
                .sort_values(ascending=True)
                .tail(10)
            )

            if not country_counts.empty:
                fig = px.bar(
                    x=country_counts.values,
                    y=country_counts.index,
                    orientation="h",
                    labels={"x": "Alertas", "y": "País"},
                    color=country_counts.values,
                    color_continuous_scale="Blues",
                )
                fig.update_layout(showlegend=False, height=300)
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("Dados de país não disponíveis (configure GeoIP)")
        else:
            st.info("Enriquecimento GeoIP não configurado")

    st.markdown("---")

    st.subheader("🚨 Alertas Recentes de Alta Severidade")

    high_severity = (
        filtered_df[filtered_df["severity"].isin(["critical", "high"])]
        .sort_values("timestamp", ascending=False)
        .head(20)
    )

    if not high_severity.empty:
        display_cols = ["timestamp", "alert_type", "severity", "source_ip", "evidence"]
        display_cols = [c for c in display_cols if c in high_severity.columns]

        def highlight_severity(row):
            color = severity_color(row.get("severity", ""))
            return [f"background-color: {color}20"] * len(row)

        st.dataframe(
            high_severity[display_cols].style.apply(highlight_severity, axis=1),
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.success("✅ Nenhum alerta de alta severidade no período selecionado")

    st.markdown("---")

    with st.expander("📋 Todos os Alertas (tabela completa)"):
        if not filtered_df.empty:
            st.dataframe(
                filtered_df.sort_values("timestamp", ascending=False),
                use_container_width=True,
                hide_index=True,
            )
        else:
            st.info("Nenhum alerta para exibir")

    with st.expander("ℹ️ Sobre o Sistema"):
        st.markdown(
            """
            **VPS Attack Detector** é um sistema de detecção de ataques para servidores Linux.

            **Tipos de Detecção:**
            - 🔐 **SSH Brute Force**: Múltiplas tentativas de login falhas
            - 👤 **Credential Stuffing**: Tentativas com usuários inválidos
            - ⚠️ **Success After Failure**: Login bem-sucedido após falhas (crítico!)
            - 🔍 **Path Scanning**: Probing de paths vulneráveis
            - 🤖 **Scanner Detected**: User-agents de ferramentas de scan
            - 📈 **Rate Spike**: Picos anormais de requisições

            **Níveis de Severidade:**
            - 🔴 **Critical**: Requer atenção imediata
            - 🟠 **High**: Ataque ativo em andamento
            - 🟡 **Medium**: Atividade suspeita
            - 🟢 **Low**: Ruído ou baixo risco
            """
        )


if __name__ == "__main__":
    main()
