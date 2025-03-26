# DDoS Detector Dashboard 🚀

This project implements a real-time **DDoS Detection Tool** using machine learning to monitor and detect Distributed Denial of Service (DDoS) attacks on a local server (e.g., an Ngrok website). The tool leverages a Random Forest Classifier (RFC) for attack detection, Scapy for packet capture, and Dash for an interactive web-based dashboard to visualize traffic and attack events. 🛡️

## Features ✨
- **Real-Time Traffic Monitoring** 📊: Captures and analyzes network packets (TCP, UDP, ICMP) using Scapy to compute traffic statistics like bits/sec, packets/sec, and protocol-specific metrics.
- **DDoS Detection** 🔍: Utilizes a pre-trained Random Forest Classifier (`rf_model.pkl`) to detect DDoS attacks by analyzing packet features such as packet rate, unique IPs, and average packet size.
- **Interactive Dashboard** 🖥️: Built with Dash and Plotly, the dashboard provides live visualizations including:
  - Traffic graphs (bits/sec, packets/sec) 📈
  - Protocol-specific gauges (TCP, UDP, ICMP) ⚙️
  - Live attack log and historical DDoS triggers 📜
  - Rules monitoring for TCP, UDP, and ICMP traffic 📋
- **Attack Type Identification** 🚨: Detects specific DDoS attack types (e.g., ICMP Flood, UDP Flood, TCP SYN Flood) based on traffic patterns.
- **User-Friendly Interface** 😊: Displays detection status, suspicious IPs, and attack logs in an intuitive format for easy monitoring.

## Prerequisites 🛠️
Ensure the following are installed before running the project:
- **Python 3.x** 🐍
- **Libraries**:
  ```bash
  pip install dash plotly scapy joblib
  ```
- **Pre-trained Model**: A Random Forest Classifier model (`rf_model.pkl`) must be available in the project directory. You can train your own model using Scikit-Learn or use a pre-existing one. 📂
- **Network Interface**: The code uses the loopback interface (`lo0`) by default for macOS. Adjust `conf.iface` in the code if using a different interface or operating system. 🌐

## Installation ⚙️
1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/ddos-detector-dashboard.git
   cd ddos-detector-dashboard
   ```
2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Ensure the pre-trained model (`rf_model.pkl`) is in the project directory. 📦
4. Run the application:
   ```bash
   python ddos_detector.py
   ```

## Usage 🚀
1. Start the application by running the script:
   ```bash
   python ddos_detector.py
   ```
2. Access the dashboard at `http://127.0.0.1:8050/` in your web browser. 🌍
3. Monitor live traffic, view protocol-specific gauges, and check the attack log for detected DDoS events. 👀
4. The dashboard updates every 5 seconds, displaying real-time traffic stats and attack alerts. ⏱️

## Code Structure 🧩
- **Packet Capture**: Uses Scapy to capture packets on the specified port (`LOCAL_SERVER_PORT = 5001`). 📡
- **Feature Extraction**: Extracts features like packet rate, unique IPs, and average packet size for model prediction. 🔢
- **DDoS Detection**: The Random Forest Classifier predicts whether the traffic indicates a DDoS attack. 🧠
- **Attack Type Detection**: Identifies specific attack types (e.g., ICMP Flood) based on traffic statistics. 🚨
- **Dashboard**: Built with Dash, it includes graphs, gauges, and tables for traffic monitoring, attack logs, and rules visualization. 📊

## Screenshots 📸
*(Add screenshots of the dashboard here, e.g., traffic graphs, attack log table, etc.)*

## Limitations ⚠️
- The tool currently uses the loopback interface (`lo0`), which may need adjustment for different environments.
- Simulated rules data is used for demonstration; real rules would require integration with a firewall or mitigation system.
- The pre-trained model (`rf_model.pkl`) must be provided or trained separately.

## Future Improvements 🌟
- Integrate automated mitigation actions (e.g., IP blocking via firewall rules). 🛡️
- Support for additional network interfaces and operating systems. 🌐
- Enhance the model with more diverse datasets for better detection accuracy. 📈
- Add user authentication and multi-user support for the dashboard. 🔐

## Contributing 🤝
Contributions are welcome! Please fork the repository, create a new branch, and submit a pull request with your changes. Ensure to test your code thoroughly before submitting. 🙌

## License 📜
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Acknowledgments 💡
- Built using [Dash](https://dash.plotly.com/) and [Plotly](https://plotly.com/) for the interactive dashboard. 📊
- Packet capture powered by [Scapy](https://scapy.net/). 📡
- Machine learning model implemented with [Scikit-Learn](https://scikit-learn.org/). 🧠
