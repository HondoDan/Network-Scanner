from nmap import PortScanner
import gradio as gr
from tqdm import tqdm
import matplotlib.pyplot as plt
import io
import plotly.graph_objects as go

def scan_and_display(ip):
    nm = PortScanner()
    nm.scan(ip, arguments='-sn')  # Ping scan
    
    output = []
    for host in tqdm(nm.all_hosts(), desc="Scanning", unit="host"):
        try:
            device_info = {
                'IP': host,
                'MAC': nm[host]['addresses']['mac'],
                'Vendor': nm[host].get('vendor', {}).get(nm[host]['addresses']['mac'], 'Unknown'),
                'Services': []
            }
            for proto in nm[host].all_protocols():
                lport = nm[host][proto].keys()
                for port in lport:
                    try:
                        service_info = {
                            'Port': port,
                            'State': nm[host][proto][port]['state'],
                            'Name': nm[host][proto][port]['name'],
                            'Product': nm[host][proto][port].get('product', ''),
                            'Version': nm[host][proto][port].get('version', '')
                        }
                        device_info['Services'].append(service_info)
                    except KeyError:
                        continue
            output.append(device_info)
        except KeyError:
            continue
    
    return output

def visualize_data(devices):
    if not devices:
        return None
    
    ip_counts = {device['IP']: len(device['Services']) for device in devices}
    
    fig = go.Figure(data=[
        go.Bar(
            x=list(ip_counts.keys()),
            y=list(ip_counts.values()),
            text=[f"{count} services" for count in ip_counts.values()],
            textposition='auto',
            marker_color='skyblue'
        )
    ])
    
    fig.update_layout(
        title='Number of Services per IP Address',
        xaxis_title='IP Address',
        yaxis_title='Number of Services',
        xaxis_tickangle=-45,
        template='plotly_white'
    )
    
    # Save the plot to a bytes buffer
    buf = io.BytesIO()
    fig.write_image(buf, format='png')
    buf.seek(0)
    return gr.Image(value=buf)

iface = gr.Interface(
    fn=lambda ip: (scan_and_display(ip), visualize_data(scan_and_display(ip))),
    inputs="text",
    outputs=["text", "image"],
    title="Network Scanner",
    description="Enter a single IP address to scan and visualize its services"
)

iface.launch()