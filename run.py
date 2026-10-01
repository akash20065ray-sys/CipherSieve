"""
CipherSieve - Master Application CLI
Commands:
  python run.py serve       -> Starts FastAPI server & launches real-time SOC dashboard
  python run.py sniff       -> Launches live network card packet sniffer from terminal
  python run.py replay      -> Replays a standard .pcap capture through the inference engine
  python run.py samples     -> Generates authentic test PCAP benchmark captures
  python run.py benchmark   -> Runs research benchmark suite (RQs, horizons, evasion, latency)
  python run.py train       -> Runs model training across all 5 architectures
  python run.py plot        -> Generates publication-ready figures for documentation
"""

import sys
import os
import time
import argparse
import webbrowser
import uvicorn

# Project root
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

# Ensure safe console encoding on Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def main():
    parser = argparse.ArgumentParser(description="CipherSieve: Payload-Agnostic Encrypted Threat Telemetry")
    parser.add_argument("mode", nargs="?", default="serve",
                        choices=["serve", "sniff", "replay", "samples", "train", "benchmark", "plot"],
                        help="Execution mode (default: serve)")
    parser.add_argument("--port", type=int, default=8000, help="Port to run dashboard server on")
    parser.add_argument("--iface", type=str, default="Wi-Fi", help="Network interface for live sniffing")
    parser.add_argument("--pcap", type=str, default="data/samples/c2_beacon_heartbeat.pcap", help="PCAP file path to replay")
    parser.add_argument("--speed", type=float, default=2.0, help="PCAP replay speed multiplier (default: 2.0x)")

    args = parser.parse_args()

    if args.mode == "train":
        from models.trainer import main as train_main
        train_main()
    elif args.mode == "benchmark":
        from benchmark.runner import run_comprehensive_benchmark
        run_comprehensive_benchmark()
    elif args.mode == "plot":
        from benchmark.plot_results import plot_all_figures
        plot_all_figures()
    elif args.mode == "samples":
        from core.pcap_loader import generate_sample_pcaps
        samples_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "data", "samples"))
        generate_sample_pcaps(samples_dir)
    elif args.mode == "sniff":
        from core.live_sniffer import LiveSniffer
        from server.app import predict_flow, active_model_name

        print("=" * 80)
        print(f"       CIPHERSIEVE: LIVE NETWORK SNIFFER [Interface: {args.iface}]")
        print("=" * 80)

        def on_flow(fstate):
            res = predict_flow(fstate.packets[:20], active_model_name)
            status_symbol = "[ALERT]" if res["is_threat"] else "[OK]"
            print(f"{status_symbol} Flow {fstate.flow_id[:40]} -> {res['classification']} ({res['confidence']*100:.1f}%) | Latency: {res['latency']['total_ms']:.2f}ms")
            if res["is_threat"]:
                for ev in res["evidence"]:
                    print(f"    +-- Physical Evidence: {ev}")

        sniffer = LiveSniffer(observation_window=20, flow_callback=on_flow)
        sniffer.start(args.iface)
        print(f"[*] Sniffing active on {args.iface}. Press Ctrl+C to stop...")
        try:
            while True:
                time.sleep(1)
                st = sniffer.get_status()
                print(f"\r[*] Packets: {st['packets_captured']} | Active Flows: {st['active_flows']} | Rate: {st['pps']} pps ({st['kbps']} kbps)", end="")
        except KeyboardInterrupt:
            print("\n[*] Stopping sniffer...")
            sniffer.stop()
    elif args.mode == "replay":
        from core.pcap_loader import PCAPLoader
        from server.app import predict_flow, active_model_name

        pcap_path = os.path.abspath(args.pcap)
        print("=" * 80)
        print(f"       CIPHERSIEVE: PCAP REPLAYER [{os.path.basename(pcap_path)}]")
        print("=" * 80)
        if not os.path.exists(pcap_path):
            print(f"[!] Error: File not found: {pcap_path}")
            sys.exit(1)

        loader = PCAPLoader(observation_window=20)

        def on_flow(fstate):
            res = predict_flow(fstate.packets[:20], active_model_name)
            status_symbol = "[ALERT]" if res["is_threat"] else "[OK]"
            print(f"\n{status_symbol} Replayed Flow {fstate.flow_id} -> {res['classification']} ({res['confidence']*100:.1f}%) | Latency: {res['latency']['total_ms']:.2f}ms")
            if res["is_threat"]:
                for ev in res["evidence"]:
                    print(f"    +-- Physical Evidence: {ev}")

        print(f"[*] Replaying {pcap_path} at {args.speed}x speed...")
        count = loader.replay_pcap(pcap_path, speed_multiplier=args.speed, flow_complete_callback=on_flow)
        print(f"\n[+] Replay complete. Processed {count} packets.")
    elif args.mode == "serve":
        url = f"http://127.0.0.1:{args.port}/index.html"
        print("=" * 80)
        print("           CIPHERSIEVE: REAL-TIME ENCRYPTED DEFENSE SOC")
        print(f"[*] Dashboard URL: {url}")
        print("=" * 80)
        try:
            webbrowser.open(url)
        except:
            pass
        uvicorn.run("server.app:app", host="127.0.0.1", port=args.port, reload=False)


if __name__ == "__main__":
    main()
