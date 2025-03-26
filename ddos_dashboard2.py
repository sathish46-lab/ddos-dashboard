import dash
from dash import dcc, html, dash_table
from dash.dependencies import Input, Output
import plotly.graph_objects as go
import time
from collections import deque
import random
import traceback

# Define the local server port (kept for consistency)
LOCAL_SERVER_PORT = 5001

# Initialize deques for storing traffic history and attack log
time_series = deque(maxlen=20)
bits_sec_history = deque(maxlen=20)
packets_sec_history = deque(maxlen=20)
tcp_mbps_history = deque(maxlen=20)
udp_kbps_history = deque(maxlen=20)
icmp_kbps_history = deque(maxlen=20)
attack_log = deque(maxlen=10)
tcp_rules = deque(maxlen=20)
udp_rules = deque(maxlen=20)
icmp_rules = deque(maxlen=20)

# Simulated DDoS triggers history (will be updated dynamically)
abnormal_ips = deque(maxlen=10)

app = dash.Dash(__name__)
app.title = "Fake DDoS Detector Dashboard"

app.layout = html.Div([
    html.H1("Fake DDoS Detector Dashboard", style={'textAlign': 'center', 'color': '#ffffff'}),
    html.Div(id='detection-status', style={'fontSize': 20, 'textAlign': 'center', 'marginBottom': '20px'}),
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
    ], style={'marginBottom': '40px', 'backgroundColor': '#1a1a1a', 'padding': '10px'}),
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
            style_cell={'backgroundColor': '#1a1a1a', 'color': '#ffffff', 'textAlign': 'center'},
            style_data_conditional=[{
                'if': {'column_id': 'suspicious_ips'},
                'color': 'red',
                'fontWeight': 'bold'
            }]
        )
    ], style={'marginBottom': '40px', 'backgroundColor': '#1a1a1a', 'padding': '10px'}),
    html.Div([
        html.H3("DDoS Triggers History", style={'textAlign': 'center', 'color': '#ffffff'}),
        dash_table.DataTable(
            id='ddos-history-table',
            columns=[
                {'name': 'Time', 'id': 'time'},
                {'name': 'Dst IP', 'id': 'dst'},
                {'name': 'bps', 'id': 'bps'},
                {'name': 'pps', 'id': 'pps'},
                {'name': 'Protocol', 'id': 'protocol'},
                {'name': 'Comment', 'id': 'comment'}
            ],
            data=list(abnormal_ips),
            style_table={'height': '200px', 'overflowY': 'auto'},
            style_header={'backgroundColor': '#333333', 'color': '#ffffff'},
            style_cell={'backgroundColor': '#1a1a1a', 'color': '#ffffff', 'textAlign': 'center'},
            style_data_conditional=[{
                'if': {'column_id': 'dst'},
                'color': 'red',
                'fontWeight': 'bold'
            }]
        )
    ], style={'marginBottom': '40px', 'backgroundColor': '#1a1a1a', 'padding': '10px'}),
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
    ], style={'marginBottom': '40px', 'backgroundColor': '#1a1a1a', 'padding': '10px'}),
    dcc.Interval(id='interval-component', interval=2000, n_intervals=0)
], style={'padding': '20px', 'backgroundColor': '#000000'})

def create_traffic_figure(title, x_vals, y_vals, y_label, threshold, is_attack=False):
    fig = go.Figure()
    line_color = 'red' if is_attack else '#00ff00'
    fig.add_trace(go.Scatter(x=x_vals, y=y_vals, mode='lines', name=title, line=dict(color=line_color)))
    fig.add_hline(y=threshold, line=dict(color='red', dash='dash'), 
                 annotation_text=f"Threshold: {threshold:,}", 
                 annotation_position="top right")
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
        Output('attack-log-table', 'data'),
        Output('ddos-history-table', 'data')
    ],
    [Input('interval-component', 'n_intervals')]
)
def update_dashboard(n):
    try:
        current_time = time.strftime('%H:%M:%S')
        time_series.append(current_time)
        
        # Simulate attack traffic exceeding thresholds
        bits_sec = random.uniform(1.5e9, 2.5e9)  # 1.5-2.5 Gbps
        packets_sec = random.uniform(1e6, 2e6)    # 1-2 Mpps
        tcp_mbps = random.uniform(1.5, 2.5)      # 1.5-2.5 Mbps
        udp_kbps = random.uniform(750, 1250)     # 750-1250 kbps
        icmp_kbps = random.uniform(50, 100)      # 50-100 kbps
        
        bits_sec_history.append(bits_sec)
        packets_sec_history.append(packets_sec)
        tcp_mbps_history.append(tcp_mbps)
        udp_kbps_history.append(udp_kbps)
        icmp_kbps_history.append(icmp_kbps)
        
        # Simulate rules data
        tcp_rules.append(random.uniform(1.5, 3.0))  # 1.5-3 Mbps
        udp_rules.append(random.uniform(0.5, 1.5))  # 0.5-1.5 Mbps
        icmp_rules.append(random.uniform(0.05, 0.1))  # 50-100 kbps
        
        # Define thresholds
        bits_threshold = 1e9    # 1 Gbps
        packets_threshold = 5e5 # 500 kpps
        tcp_threshold = 1       # 1 Mbps
        udp_threshold = 500     # 500 kbps
        icmp_threshold = 50     # 50 kbps
        
        # Simulate attack
        is_attack = bits_sec > bits_threshold or packets_sec > packets_threshold
        attack_type = random.choice(['TCP SYN Flood', 'UDP Flood', 'ICMP Flood'])
        suspicious_ips = [f"192.168.1.{random.randint(100, 105)}" for _ in range(random.randint(1, 3))]
        
        # Update detection status
        detection_status = "Normal Traffic"
        if is_attack:
            detection_status = html.Span(
                f"DDoS Attack Detected: {attack_type}",
                style={'color': 'red', 'fontWeight': 'bold'}
            )
            attack_log.append({
                'time': current_time,
                'attack_type': attack_type,
                'suspicious_ips': ', '.join(suspicious_ips)
            })
            abnormal_ips.append({
                'time': current_time,
                'dst': random.choice(suspicious_ips),
                'bps': f"{bits_sec/1e9:.1f} Gbps",
                'pps': f"{packets_sec/1e6:.1f} Mpps",
                'protocol': attack_type.split()[0].lower(),
                'comment': attack_type
            })
            print(f"Fake DDoS Detected at {current_time} - Suspicious IPs: {suspicious_ips}")

        # Create figures
        bit_sec_fig = create_traffic_figure(
            'Traffic bit/sec', list(time_series), list(bits_sec_history), 
            'Bits/sec', bits_threshold, is_attack
        )
        packet_sec_fig = create_traffic_figure(
            'Traffic packet/sec', list(time_series), list(packets_sec_history), 
            'Packets/sec', packets_threshold, is_attack
        )
        
        tcp_gauge_fig = go.Figure(go.Indicator(
            mode="gauge+number", value=tcp_mbps,
            title={'text': "TCP Traffic (Mbps)", 'font': {'color': '#ffffff'}},
            gauge={
                'axis': {'range': [0, 3]}, 
                'bar': {'color': 'red' if tcp_mbps > tcp_threshold else '#00ff00'},
                'bgcolor': '#1a1a1a', 
                'bordercolor': '#333333',
                'threshold': {'line': {'color': "red", 'width': 2}, 'value': tcp_threshold}
            }
        ))
        tcp_gauge_fig.update_layout(paper_bgcolor='#1a1a1a', font=dict(color='#ffffff'))
        
        udp_gauge_fig = go.Figure(go.Indicator(
            mode="gauge+number", value=udp_kbps,
            title={'text': "UDP Traffic (kbps)", 'font': {'color': '#ffffff'}},
            gauge={
                'axis': {'range': [0, 1500]}, 
                'bar': {'color': 'red' if udp_kbps > udp_threshold else '#00ff00'},
                'bgcolor': '#1a1a1a', 
                'bordercolor': '#333333',
                'threshold': {'line': {'color': "red", 'width': 2}, 'value': udp_threshold}
            }
        ))
        udp_gauge_fig.update_layout(paper_bgcolor='#1a1a1a', font=dict(color='#ffffff'))
        
        icmp_gauge_fig = go.Figure(go.Indicator(
            mode="gauge+number", value=icmp_kbps,
            title={'text': "ICMP Traffic (kbps)", 'font': {'color': '#ffffff'}},
            gauge={
                'axis': {'range': [0, 150]}, 
                'bar': {'color': 'red' if icmp_kbps > icmp_threshold else '#00ff00'},
                'bgcolor': '#1a1a1a', 
                'bordercolor': '#333333',
                'threshold': {'line': {'color': "red", 'width': 2}, 'value': icmp_threshold}
            }
        ))
        icmp_gauge_fig.update_layout(paper_bgcolor='#1a1a1a', font=dict(color='#ffffff'))
        
        tcp_rules_bit_fig = create_traffic_figure(
            'TCP Rules bit/sec', list(time_series), list(tcp_rules), 'Mbps', 1, tcp_mbps > tcp_threshold
        )
        tcp_rules_packet_fig = create_traffic_figure(
            'TCP Rules packet/sec', list(time_series), list(tcp_rules), 'Packets/sec', 1, tcp_mbps > tcp_threshold
        )
        udp_rules_bit_fig = create_traffic_figure(
            'UDP Rules bit/sec', list(time_series), list(udp_rules), 'Mbps', 0.5, udp_kbps > udp_threshold
        )
        udp_rules_packet_fig = create_traffic_figure(
            'UDP Rules packet/sec', list(time_series), list(udp_rules), 'Packets/sec', 0.5, udp_kbps > udp_threshold
        )
        icmp_rules_bit_fig = create_traffic_figure(
            'ICMP Rules bit/sec', list(time_series), list(icmp_rules), 'Mbps', 0.05, icmp_kbps > icmp_threshold
        )
        icmp_rules_packet_fig = create_traffic_figure(
            'ICMP Rules packet/sec', list(time_series), list(icmp_rules), 'Packets/sec', 0.05, icmp_kbps > icmp_threshold
        )

        return (
            bit_sec_fig, packet_sec_fig, tcp_gauge_fig, udp_gauge_fig, icmp_gauge_fig,
            tcp_rules_bit_fig, tcp_rules_packet_fig, udp_rules_bit_fig, udp_rules_packet_fig,
            icmp_rules_bit_fig, icmp_rules_packet_fig, detection_status, list(attack_log), list(abnormal_ips)
        )
    
    except Exception as e:
        print(f"Callback error: {e}")
        traceback.print_exc()
        default_fig = create_traffic_figure('Error', [], [], 'N/A', 0)
        default_gauge = go.Figure(go.Indicator(mode="gauge+number", value=0, title={'text': "Error"}))
        return [default_fig] * 11 + [f"Error: {str(e)}", list(attack_log), list(abnormal_ips)]

if __name__ == '__main__':
    print("Starting Fake DDoS Detector Dashboard. Access it at http://127.0.0.1:8050/")
    app.run_server(debug=True)