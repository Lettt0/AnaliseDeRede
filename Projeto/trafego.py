import shutil
import subprocess
import json
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from flask import Flask, render_template, render_template_string, request, send_file, redirect, url_for
from io import BytesIO
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib.utils import ImageReader
from scipy.optimize import linprog
import numpy as np
import networkx as nx
from scipy.stats import entropy

app = Flask(__name__)

# ==============================================
# Rotas Principais
# ==============================================

@app.route("/")
def home():
    """Rota principal que redireciona para a página de apresentação"""
    return redirect(url_for('apresentacao'))

@app.route("/apresentacao")
def apresentacao():
    """Exibe a página de apresentação do projeto"""
    return render_template('apresentacao.html')

@app.route("/analise", methods=["GET", "POST"])
def analise():
    """Rota para a ferramenta de análise de tráfego"""
    if request.method == "POST":
        # Seu código existente de processamento...
        interface = request.form.get("interface", "Wi-Fi")
        qtd = int(request.form.get("qtd", 100))

        tshark_path = shutil.which("tshark") or r"C:\\Program Files\\Wireshark\\tshark.exe"
        command = [tshark_path, "-i", interface, "-c", str(qtd), "-T", "json"]

        proc = subprocess.run(command, capture_output=True, text=True)
        if proc.returncode != 0:
            result = f"Erro ao executar: {proc.stderr}"
            return render_template('analise.html', result=result.strip())
        
        data = json.loads(proc.stdout)
        df = parse_packets(data)
        
        # Preparar dados para o template
        protocol_counts = df['protocol'].value_counts().to_dict()
        avg_size = df.groupby('protocol')['length'].mean().to_dict()
        total_bytes = df['length'].sum()
        
        # Análise do grafo
        unique_src = set(df['src_ip'])
        unique_dst = set(df['dst_ip'])
        graph_nodes = len(unique_src.union(unique_dst))
        graph_edges = df.groupby(['src_ip', 'dst_ip']).ngroups
        avg_degree = 2 * graph_edges / graph_nodes if graph_nodes > 0 else 0
        
        # Entropia
        protocol_dist = df['protocol'].value_counts(normalize=True)
        entropia = entropy(protocol_dist)
        
        # Processar resultados para exibição
        result_data = {
            'df_length': len(df),
            'unique_ips': df['src_ip'].nunique(),
            'entropy': entropia,
            'protocol_counts': protocol_counts,
            'avg_size': avg_size,
            'total_bytes': total_bytes,
            'graph_nodes': graph_nodes,
            'graph_edges': graph_edges,
            'avg_degree': avg_degree,
            'result': "Análise concluída com sucesso",
            'raw_data': df.to_json(orient="records")
        }
        
        return render_template('analise.html', **result_data)

    return render_template('analise.html')

@app.route("/download", methods=["POST"])
def download():
    """Gera e envia o relatório PDF"""
    raw = request.form.get("data")
    df = pd.read_json(raw)

    buf1, buf2, buf3, buf4, buf5, buf6, buf7, entropia = analise_avancada(df)

    buffer = BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter

    # Cabeçalho
    pdf.setFont("Helvetica-Bold", 16)
    pdf.drawString(50, height - 50, "Relatório Completo de Análise de Rede")
    pdf.setFont("Helvetica", 12)
    pdf.drawString(50, height - 70, f"Data: {pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # Métricas básicas
    y = height - 100
    pdf.setFont("Helvetica-Bold", 14)
    pdf.drawString(50, y, "Métricas Básicas:")
    y -= 20
    pdf.setFont("Helvetica", 12)
    pdf.drawString(50, y, f"Total de pacotes: {len(df)}")
    y -= 20
    pdf.drawString(50, y, f"IPs únicos: {df['src_ip'].nunique()}")
    y -= 20
    pdf.drawString(50, y, f"Tamanho total: {df['length'].sum() / 1024:.2f} KB")
    y -= 20
    pdf.drawString(50, y, f"Entropia de protocolos: {entropia:.2f}")
    y -= 30

    # Adicionar gráficos
    def add_image(buf, title, y_offset=220):
        nonlocal y
        pdf.setFont("Helvetica-Bold", 12)
        pdf.drawString(50, y, title)
        y -= 20
        pdf.drawImage(ImageReader(buf), 50, y - y_offset, width=500, height=200)
        return y - y_offset - 20
    
    if buf1:
        y = add_image(buf1, "1. Tráfego Acumulado:")
    if buf2:
        y = add_image(buf2, "2. Taxa de Variação do Tráfego:")
    if buf3:
        y = add_image(buf3, "3. Análise de Componentes Principais:")
    if buf4:
        y = add_image(buf4, "4. Distribuição de Tráfego por IP:")
    if buf5:
        y = add_image(buf5, "5. Grafo de Comunicação entre IPs:")
    if buf6:
        y = add_image(buf6, "6. Distribuição de Protocolos:")
    if buf7:
        y = add_image(buf7, "7. Tamanho Médio por Protocolo:")

    pdf.save()
    buffer.seek(0)
    return send_file(
        buffer,
        as_attachment=True,
        download_name="relatorio_rede_avancado.pdf",
        mimetype="application/pdf"
    )

# ==============================================
# Funções Auxiliares
# ==============================================

def parse_packets(packets):
    """Parseia os pacotes capturados para um DataFrame"""
    dados = []
    for packet in packets:
        layers = packet['_source']['layers']
        frame = layers.get('frame', {})
        eth = layers.get('eth', {})
        ip = layers.get('ip', {})
        tcp = layers.get('tcp', {})
        udp = layers.get('udp', {})

        protocolo = "tcp" if "tcp" in layers else ("udp" if "udp" in layers else ip.get("ip.proto", "outro"))

        dados.append({
            'timestamp': frame.get('frame.time', None),
            'src_mac': eth.get('eth.src', None),
            'dst_mac': eth.get('eth.dst', None),
            'src_ip': ip.get('ip.src', None),
            'dst_ip': ip.get('ip.dst', None),
            'protocol': protocolo,
            'src_port': tcp.get('tcp.srcport', udp.get('udp.srcport', None)),
            'dst_port': tcp.get('tcp.dstport', udp.get('udp.dstport', None)),
            'length': int(frame.get('frame.len', 0))
        })
    return pd.DataFrame(dados)

def analise_avancada(df):
    """Realiza análises avançadas e gera gráficos"""
    plt.close('all')
    
    # Análise básica
    df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
    df = df.dropna(subset=['timestamp'])
    df = df.sort_values('timestamp')
    df['timestamp_seconds'] = (df['timestamp'] - df['timestamp'].min()).dt.total_seconds()
    
    if df.empty:
        return None, None, None, None, None, None, None, 0

    # Cálculo da derivada
    series = df.groupby('timestamp_seconds')['length'].sum().cumsum()
    derivada = series.diff().fillna(0) / series.index.to_series().diff().fillna(1)

    # Entropia de Shannon para protocolos
    protocol_counts = df['protocol'].value_counts(normalize=True)
    entropia_protocolos = entropy(protocol_counts)

    # Gráfico de tráfego acumulado
    fig1, ax1 = plt.subplots(figsize=(10, 6))
    series.plot(title=f'Tráfego Acumulado', ax=ax1)
    ax1.set_xlabel('Tempo (s)')
    ax1.set_ylabel('Bytes')
    buf1 = BytesIO()
    fig1.savefig(buf1, format='png', bbox_inches='tight')
    buf1.seek(0)
    plt.close(fig1)

    # Gráfico da derivada
    fig2, ax2 = plt.subplots(figsize=(10, 6))
    derivada.plot(title='Derivada do Tráfego', ax=ax2)
    ax2.set_xlabel('Tempo (s)')
    ax2.set_ylabel('Variação de Bytes/s')
    buf2 = BytesIO()
    fig2.savefig(buf2, format='png', bbox_inches='tight')
    buf2.seek(0)
    plt.close(fig2)

    # PCA
    features = df[['length', 'src_port', 'dst_port']].fillna(0)
    if len(features) > 1:
        def manual_pca(data, n_components=2):
            data_centered = data - data.mean(axis=0)
            cov_matrix = np.cov(data_centered, rowvar=False)
            eigenvalues, eigenvectors = np.linalg.eig(cov_matrix)
            idx = eigenvalues.argsort()[::-1]
            eigenvectors = eigenvectors[:,idx]
            return data_centered.dot(eigenvectors[:,:n_components])
        
        components = manual_pca(features.values)
        color_map = {'tcp': '#e74a3b', 'udp': '#36b9cc', 'outro': '#858796'}
        colors = df['protocol'].map(color_map)
        
        fig3, ax3 = plt.subplots(figsize=(10, 6))
        scatter = ax3.scatter(components[:, 0], components[:, 1], c=colors, alpha=0.6, edgecolors='w', s=50)
        ax3.set_title('PCA de Características de Tráfego')
        ax3.set_xlabel('Componente Principal 1')
        ax3.set_ylabel('Componente Principal 2')
        
        handles = [plt.Line2D([0], [0], marker='o', color='w', markerfacecolor=color_map[p], 
                   markersize=10, label=p) for p in color_map.keys()]
        ax3.legend(handles=handles, title='Protocolos')
        
        buf3 = BytesIO()
        fig3.savefig(buf3, format='png', bbox_inches='tight')
        buf3.seek(0)
        plt.close(fig3)
    else:
        buf3 = None

    # Gráfico polar
    trafego_por_ip = df.groupby('src_ip')['length'].sum()
    if len(trafego_por_ip) > 0:
        top_ips = trafego_por_ip.nlargest(5)
        angles = np.linspace(0, 2*np.pi, len(top_ips), endpoint=False)
        radii = top_ips.values / top_ips.values.max() * 100
        
        fig4 = plt.figure(figsize=(10, 8))
        ax4 = fig4.add_subplot(111, polar=True)
        bars = ax4.bar(angles, radii, width=0.4, bottom=0.0, alpha=0.7,
                      color=['#4e73df', '#1cc88a', '#36b9cc', '#f6c23e', '#e74a3b'])
        
        for bar, ip, radius in zip(bars, top_ips.index, radii):
            height = bar.get_height()
            ax4.text(bar.get_x() + bar.get_width()/2., height, f"{ip}\n{radius:.1f}%",
                    ha='center', va='bottom', rotation=np.degrees(bar.get_x() + bar.get_width()/2))
        
        ax4.set_title('Distribuição de Tráfego por IP (Top 5)', pad=20)
        ax4.set_theta_offset(np.pi/2)
        ax4.set_theta_direction(-1)
        buf4 = BytesIO()
        fig4.savefig(buf4, format='png', bbox_inches='tight')
        buf4.seek(0)
        plt.close(fig4)
    else:
        buf4 = None

    # Grafo de comunicação
    G = nx.Graph()
    ip_pairs = df.groupby(['src_ip', 'dst_ip']).size().reset_index(name='counts')
    
    for _, row in ip_pairs.iterrows():
        G.add_edge(row['src_ip'], row['dst_ip'], weight=row['counts'])
    
    fig5 = plt.figure(figsize=(12, 10))
    pos = nx.spring_layout(G, k=0.3)
    
    degrees = dict(G.degree())
    node_colors = [degrees[n] for n in G.nodes()]
    
    nx.draw(G, pos, with_labels=True, 
            node_size=[v * 50 for v in degrees.values()],
            node_color=node_colors, 
            cmap=plt.cm.plasma,
            font_size=8, 
            width=[d['weight']*0.1 for u, v, d in G.edges(data=True)],
            edge_color='gray',
            alpha=0.8)
    
    plt.title('Grafo de Comunicação entre IPs')
    sm = plt.cm.ScalarMappable(cmap=plt.cm.plasma, 
                              norm=plt.Normalize(vmin=min(node_colors), 
                              vmax=max(node_colors)))
    sm._A = []
    plt.colorbar(sm, label='Grau do Nó')
    buf5 = BytesIO()
    fig5.savefig(buf5, format='png', bbox_inches='tight')
    buf5.seek(0)
    plt.close(fig5)

    # Gráfico de protocolos
    fig6, ax6 = plt.subplots(figsize=(10, 6))
    df['protocol'].value_counts().plot(kind='bar', color=['#e74a3b', '#36b9cc', '#858796'], ax=ax6)
    ax6.set_title('Distribuição de Protocolos')
    ax6.set_ylabel('Quantidade')
    ax6.set_xlabel('Protocolo')
    buf6 = BytesIO()
    fig6.savefig(buf6, format='png', bbox_inches='tight')
    buf6.seek(0)
    plt.close(fig6)

    # Gráfico de tamanho médio
    fig7, ax7 = plt.subplots(figsize=(10, 6))
    df.groupby('protocol')['length'].mean().plot(
        kind='bar', color=['#e74a3b', '#36b9cc', '#858796'], ax=ax7)
    ax7.set_title('Tamanho Médio dos Pacotes por Protocolo')
    ax7.set_ylabel('Bytes')
    ax7.set_xlabel('Protocolo')
    buf7 = BytesIO()
    fig7.savefig(buf7, format='png', bbox_inches='tight')
    buf7.seek(0)
    plt.close(fig7)

    return buf1, buf2, buf3, buf4, buf5, buf6, buf7, entropia_protocolos

if __name__ == "__main__":
    app.run(debug=True)