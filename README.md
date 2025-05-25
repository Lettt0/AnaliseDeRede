Este programa é uma ferramenta avançada de análise de tráfego de rede, desenvolvida em Python com Flask, que oferece as seguintes funcionalidades:

1. **Captura de Pacotes**:  
   Utiliza o TShark (do Wireshark) para capturar pacotes de rede em interfaces como Wi-Fi ou Ethernet, permitindo configurar a quantidade de pacotes a serem coletados.

2. **Análise de Dados**:  
   - Extrai e organiza informações como endereços IP, MAC, protocolos (TCP/UDP), portas e tamanho dos pacotes.  
   - Calcula métricas como tráfego total, IPs únicos, entropia de protocolos e distribuição de tamanho médio de pacotes.  

3. **Visualização Gráfica**:  
   - Gera gráficos interativos, incluindo tráfego acumulado, derivada do tráfego, PCA para redução de dimensionalidade, gráficos polares e grafos de comunicação entre IPs.  
   - Exibe distribuição de protocolos e tamanho médio dos pacotes.  

4. **Exportação de Relatórios**:  
   Permite exportar os resultados para um PDF completo, contendo todas as métricas e gráficos gerados.  

5. **Interface Web Intuitiva**:  
   Oferece uma interface responsiva e moderna, com painéis de métricas, tabelas e opções para download, facilitando a interpretação dos dados.  

Ideal para monitoramento de rede, identificação de padrões e solução de problemas em ambientes acadêmicos ou profissionais.
