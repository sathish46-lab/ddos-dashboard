import dash
from dash import dcc, html, dash_table
from dash.dependencies import Input, Output
import plotly.graph_objects as go
import time
from collections import deque
from scapy.all import sniff, IP, TCP, UDP, ICMP, conf, get_if_list
import joblib
import random
import traceback

# Define the local server port
LOCAL_SERVER_PORT = 5001

# Set the network interface for Scapy
try:
    available_interfaces = get_if_list()
    print("Available interfaces:", available_interfaces)
    if "lo0" in available_interfaces:
        conf.iface = "lo0"  # Use loopback for localhost on macOS
    else:
        raise ValueError("Loopback interface 'lo0' not found. Available interfaces: " + str(available_interfaces))
except Exception as e:
    print(f"Error setting interface: {e}")
    exit(1)

# Load the pre-trained model
try:
    model = joblib.load('rf_model.pkl')
    print("Model loaded successfully")
except Exception as e:
    print(f"Error loading model: {e}")
    model = None

# Initialize deques for storing traffic history and attack log
time_series = deque(maxlen=20)
bits_sec_history = deque(maxlen=20)
packets_sec_history = deque(maxlen=20)
tcp_mbps_history = deque(maxlen=20)
udp_kbps_history = deque(maxlen=20)
icmp_kbps_history = deque(maxlen=20)
attack_log = deque(maxlen=10)

# Pre-initialize rules deques outside the callback
tcp_rules = deque(maxlen=20)
udp_rules = deque(maxlen=20)
icmp_rules = deque(maxlen=20)

# Simulated DDoS triggers history
abnormal_ips = [
    {'time': '2016-10-10 03:35:48', 'dst': '92.53.121.36', 'bps': '416 Mbps', 'pps': '433 kpps', 'protocol': 'icmp', 'comment': 'ICMP flood'},
    {'time': '2016-10-10 03:34:47', 'dst': '92.53.121.36', 'bps': '476 Mbps', 'pps': '97 kpps', 'protocol': 'icmp', 'comment': 'ICMP flood'},
    {'time': '2016-10-10 03:33:46', 'dst': '92.53.121.36', 'bps': '4.03 Mbps', 'pps': '431 kpps', 'protocol': 'icmp', 'comment': 'ICMP flood'},
    {'time': '2016-10-10 03:32:45', 'dst': '92.53.121.36', 'bps': '5.99 Mbps', 'pps': '6.06 kpps', 'protocol': 'icmp', 'comment': 'ICMP flood'},
    {'time': '2016-10-09 21:16:47', 'dst': '92.53.113.10', 'bps': '722.23 kbps', 'pps': '124 kpps', 'protocol': 'icmp', 'comment': 'ICMP flood'}
]

def capture_packets():
    try:
        # Updated filter to capture traffic to/from the local server port
        filter_str = f"tcp port {LOCAL_SERVER_PORT} or udp port {LOCAL_SERVER_PORT}"
        packets = sniff(filter=filter_str, timeout=1)  # Interface set globally via conf.iface
        print(f"Captured {len(packets)} packets: {[pkt.summary() for pkt in packets]}")
        return packets
    except Exception as e:
        print(f"Packet capture error: {e}")
        return []

def compute_traffic_stats(packets):
    if not packets:
        return {'bits_sec': 0, 'packets_sec': 0, 'tcp_mbps': 0, 'udp_kbps': 0, 'icmp_kbps': 0,
                'tcp_count': 0, 'udp_count': 0, 'icmp_count': 0, 'syn_count': 0}
    duration = 1
    total_bits = sum(len(pkt) * 8 for pkt in packets)
    bits_sec = total_bits / duration
    packets_sec = len(packets) / duration
    tcp_packets = [pkt for pkt in packets if IP in pkt and TCP in pkt]
    udp_packets = [pkt for pkt in packets if IP in pkt and UDP in pkt]
    icmp_packets = [pkt for pkt in packets if IP in pkt and ICMP in pkt]
    syn_packets = [pkt for pkt in tcp_packets if TCP in pkt and pkt[TCP].flags.S]
    tcp_bits = sum(len(pkt) * 8 for pkt in tcp_packets)
    udp_bits = sum(len(pkt) * 8 for pkt in udp_packets)
    icmp_bits = sum(len(pkt) * 8 for pkt in icmp_packets)
    return {
        'bits_sec': bits_sec,
        'packets_sec': packets_sec,
        'tcp_mbps': tcp_bits / duration / 1e6,
        'udp_kbps': udp_bits / duration / 1e3,
        'icmp_kbps': icmp_bits / duration / 1e3,
        'tcp_count': len(tcp_packets),
        'udp_count': len(udp_packets),
        'icmp_count': len(icmp_packets),
        'syn_count': len(syn_packets)
    }

def extract_features(packets):
    if not packets or len(packets) < 2:
        return [0, 0, 0]
    duration = packets[-1].time - packets[0].time if packets[-1].time > packets[0].time else 1
    packet_rate = len(packets) / duration
    unique_ips = len(set(pkt[IP].src for pkt in packets if IP in pkt))
    avg_size = sum(len(pkt) for pkt in packets) / len(packets)
    return [packet_rate, unique_ips, avg_size]

def detect_attack_type(stats):
    if stats['icmp_count'] / (stats['packets_sec'] + 1) > 0.3:
        return "ICMP Flood"
    elif stats['udp_count'] / (stats['packets_sec'] + 1) > 0.2:
        return "UDP Flood"
    elif stats['syn_count'] / (stats['tcp_count'] + 1) > 0.4:
        return "TCP SYN Flood"
    return None

app = dash.Dash(__name__)
app.title = "DDoS Detector Dashboard for Ngrok Website"

app.layout = html.Div([
    html.H1("DDoS Detector Dashboard for Ngrok Website", style={'textAlign': 'center', 'marginBottom': '20px', 'color': '#ffffff'}),
    html.Div(id='detection-status', style={'color': 'white', 'fontSize': 20, 'textAlign': 'center', 'marginBottom': '20px'}),
    html.Div([
        html.H3("Traffic Monitoring", style={'textAlign': 'center', 'color': '#ffffff'}),
        html.Div([
            dcc.Graph(id='traffic-bit-sec', config={'displayModeBar': False}, style={'width': '50%'}),
            dcc.Graph(id='traffic-packet-sec', config={'displayModeBar': False}, style={'width': '50%'}),
        ], style={'display': 'flex', 'justifyContent': 'space-around'}),
        html.Div([
            dcc.Graph(id='tcp-gauge', config={'displayModeBar': False}, style={'width': '33%'}),
            dcc.Graph(id='udp-gauge', config={'displayModeBar': False}, style={'width': '33%'}),
            dcc.Graph(id='icmp-gauge', config={'displayModeBar': False}, style={'width': '33%'}),
        ], style={'display': 'flex', 'justifyContent': 'space-around'})
    ], style={'marginBottom': '40px', 'backgroundColor': '#1a1a1a', 'padding': '10px', 'borderRadius': '5px'}),
    html.Div([
        html.H3("Live Attack Log", style={'textAlign': 'center', 'color': '#ffffff'}),
        dash_table.DataTable(
            id='attack-log-table',
            columns=[
                {'name': 'Time', 'id': 'time'},
                {'name': 'Attack Type', 'id': 'attack_type'},
                {'name': 'Suspicious IPs', 'id': 'suspicious_ips'}
            ],
            data=list(attack_log),
            style_table={'height': '200px', 'overflowY': 'auto'},
            style_header={'backgroundColor': '#333333', 'color': '#ffffff'},
            style_cell={'backgroundColor': '#1a1a1a', 'color': '#ffffff', 'textAlign': 'center'}
        )
    ], style={'marginBottom': '40px', 'backgroundColor': '#1a1a1a', 'padding': '10px', 'borderRadius': '5px'}),
    html.Div([
        html.H3("DDoS Triggers History", style={'textAlign': 'center', 'color': '#ffffff'}),
        dash_table.DataTable(
            id='ddos-history-table',
            columns=[{'name': k, 'id': k} for k in abnormal_ips[0].keys()],
            data=abnormal_ips,
            style_table={'height': '200px', 'overflowY': 'auto'},
            style_header={'backgroundColor': '#333333', 'color': '#ffffff'},
            style_cell={'backgroundColor': '#1a1a1a', 'color': '#ffffff', 'textAlign': 'center'}
        )
    ], style={'marginBottom': '40px', 'backgroundColor': '#1a1a1a', 'padding': '10px', 'borderRadius': '5px'}),
    html.Div([
        html.H3("Rules Monitoring", style={'textAlign': 'center', 'color': '#ffffff'}),
        html.Div([
            html.Div([
                dcc.Graph(id='tcp-rules-bit-sec', config={'displayModeBar': False}),
                dcc.Graph(id='tcp-rules-packet-sec', config={'displayModeBar': False}),
            ], style={'width': '33%'}),
            html.Div([
                dcc.Graph(id='udp-rules-bit-sec', config={'displayModeBar': False}),
                dcc.Graph(id='udp-rules-packet-sec', config={'displayModeBar': False}),
            ], style={'width': '33%'}),
            html.Div([
                dcc.Graph(id='icmp-rules-bit-sec', config={'displayModeBar': False}),
                dcc.Graph(id='icmp-rules-packet-sec', config={'displayModeBar': False}),
            ], style={'width': '33%'})
        ], style={'display': 'flex', 'justifyContent': 'space-around'})
    ], style={'marginBottom': '40px', 'backgroundColor': '#1a1a1a', 'padding': '10px', 'borderRadius': '5px'}),
    dcc.Interval(id='interval-component', interval=5000, n_intervals=0)
], style={'padding': '20px', 'backgroundColor': '#000000'})

def create_traffic_figure(title, x_vals, y_vals, y_label, threshold=None):
    fig = go.Figure()
    fig.add_trace(go.Scatter(x=x_vals, y=y_vals, mode='lines', name=title, line=dict(color='#00ff00')))
    if threshold:
        fig.add_hline(y=threshold, line=dict(color='red', dash='dash'), annotation_text=f"Threshold: {threshold}")
    fig.update_layout(
        title=title,
        xaxis_title='Time',
        yaxis_title=y_label,
        plot_bgcolor='#1a1a1a',
        paper_bgcolor='#1a1a1a',
        font=dict(color='#ffffff'),
        xaxis=dict(gridcolor='#333333'),
        yaxis=dict(gridcolor='#333333')
    )
    return fig

@app.callback(
    [
        Output('traffic-bit-sec', 'figure'),
        Output('traffic-packet-sec', 'figure'),
        Output('tcp-gauge', 'figure'),
        Output('udp-gauge', 'figure'),
        Output('icmp-gauge', 'figure'),
        Output('tcp-rules-bit-sec', 'figure'),
        Output('tcp-rules-packet-sec', 'figure'),
        Output('udp-rules-bit-sec', 'figure'),
        Output('udp-rules-packet-sec', 'figure'),
        Output('icmp-rules-bit-sec', 'figure'),
        Output('icmp-rules-packet-sec', 'figure'),
        Output('detection-status', 'children'),
        Output('attack-log-table', 'data')
    ],
    [Input('interval-component', 'n_intervals')]
)
def update_dashboard(n):
    try:
        packets = capture_packets()
        stats = compute_traffic_stats(packets)
        features = extract_features(packets)
        print(f"Features for prediction: {features}, Number of features: {len(features)}")

        # Update time series data
        current_time = time.strftime('%H:%M:%S')
        time_series.append(current_time)
        bits_sec_history.append(stats['bits_sec'])
        packets_sec_history.append(stats['packets_sec'])
        tcp_mbps_history.append(stats['tcp_mbps'])
        udp_kbps_history.append(stats['udp_kbps'])
        icmp_kbps_history.append(stats['icmp_kbps'])

        # Simulate rules data
        tcp_rules.append(random.randint(500, 3000) / 1000)
        udp_rules.append(random.randint(200, 1000) / 1000)
        icmp_rules.append(random.randint(10, 50))

        # DDoS detection and attack type identification
        prediction = 0 if model is None else model.predict([features])[0]
        print(f"Prediction: {prediction} (1 = DDoS, 0 = Normal)")
        attack_type = detect_attack_type(stats) if prediction == 1 else None
        detection_status = "Normal Traffic"
        if prediction == 1:
            detection_status = f"DDoS Attack Detected: {attack_type if attack_type else 'Unknown Type'}"
            suspicious_ips = set(pkt[IP].src for pkt in packets if IP in pkt)
            print(f"DDoS Detected at {current_time} - Suspicious IPs: {suspicious_ips}")
            attack_log.append({
                'time': current_time,
                'attack_type': attack_type if attack_type else 'Unknown Type',
                'suspicious_ips': ', '.join(suspicious_ips) if suspicious_ips else 'None'
            })
            print(f"Attack Log Entry: {attack_log[-1]}")

        # Create figures
        bit_sec_fig = create_traffic_figure('Traffic bit/sec', list(time_series), list(bits_sec_history), 'Bits/sec', threshold=1000000000)
        packet_sec_fig = create_traffic_figure('Traffic packet/sec', list(time_series), list(packets_sec_history), 'Packets/sec', threshold=1000000)
        
        tcp_gauge_fig = go.Figure(go.Indicator(
            mode="gauge+number", value=stats['tcp_mbps'],
            title={'text': "TCP Traffic (Mbps)", 'font': {'color': '#ffffff'}},
            gauge={'axis': {'range': [0, 2]}, 'bar': {'color': '#00ff00'}, 'bgcolor': '#1a1a1a', 'bordercolor': '#333333'}
        ))
        tcp_gauge_fig.update_layout(paper_bgcolor='#1a1a1a', font=dict(color='#ffffff'))
        
        udp_gauge_fig = go.Figure(go.Indicator(
            mode="gauge+number", value=stats['udp_kbps'],
            title={'text': "UDP Traffic (kbps)", 'font': {'color': '#ffffff'}},
            gauge={'axis': {'range': [0, 500]}, 'bar': {'color': '#00ff00'}, 'bgcolor': '#1a1a1a', 'bordercolor': '#333333'}
        ))
        udp_gauge_fig.update_layout(paper_bgcolor='#1a1a1a', font=dict(color='#ffffff'))
        
        icmp_gauge_fig = go.Figure(go.Indicator(
            mode="gauge+number", value=stats['icmp_kbps'],
            title={'text': "ICMP Traffic (kbps)", 'font': {'color': '#ffffff'}},
            gauge={'axis': {'range': [0, 100]}, 'bar': {'color': '#00ff00'}, 'bgcolor': '#1a1a1a', 'bordercolor': '#333333'}
        ))
        icmp_gauge_fig.update_layout(paper_bgcolor='#1a1a1a', font=dict(color='#ffffff'))
        
        tcp_rules_bit_fig = create_traffic_figure('TCP Rules bit/sec', list(time_series), list(tcp_rules), 'Bits/sec')
        tcp_rules_packet_fig = create_traffic_figure('TCP Rules packet/sec', list(time_series), list(tcp_rules), 'Packets/sec')
        udp_rules_bit_fig = create_traffic_figure('UDP Rules bit/sec', list(time_series), list(udp_rules), 'Bits/sec')
        udp_rules_packet_fig = create_traffic_figure('UDP Rules packet/sec', list(time_series), list(udp_rules), 'Packets/sec')
        icmp_rules_bit_fig = create_traffic_figure('ICMP Rules bit/sec', list(time_series), list(icmp_rules), 'Bits/sec')
        icmp_rules_packet_fig = create_traffic_figure('ICMP Rules packet/sec', list(time_series), list(icmp_rules), 'Packets/sec')

        print(f"Detection Status: {detection_status}")
        return (
            bit_sec_fig, packet_sec_fig, tcp_gauge_fig, udp_gauge_fig, icmp_gauge_fig,
            tcp_rules_bit_fig, tcp_rules_packet_fig, udp_rules_bit_fig, udp_rules_packet_fig,
            icmp_rules_bit_fig, icmp_rules_packet_fig, detection_status, list(attack_log)
        )
    except Exception as e:
        print(f"Callback error: {e}")
        traceback.print_exc()
        default_fig = create_traffic_figure('Error', [], [], 'N/A')
        default_gauge = go.Figure(go.Indicator(mode="gauge+number", value=0, title={'text': "Error"}))
        return [default_fig] * 11 + [f"Error: {str(e)}", list(attack_log)]

if __name__ == '__main__':
    print("Starting DDoS Detector Dashboard for Ngrok Website. Access it at http://127.0.0.1:8050/")
    app.run_server(debug=True)