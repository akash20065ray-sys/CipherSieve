"""
CipherSieve - Master Application CLI
Commands:
  python run.py serve       -> Starts FastAPI server & launches real-time SOC dashboard
  python run.py train       -> Runs model training across all 5 architectures
  python run.py benchmark   -> Runs research benchmark suite (RQs, horizons, evasion, latency)
  python run.py plot        -> Generates publication-ready figures for documentation
"""

import sys
import os
import argparse
import webbrowser
import uvicorn


def main():
    parser = argparse.ArgumentParser(description="CipherSieve: Payload-Agnostic Encrypted Threat Telemetry")
    parser.add_argument("mode", nargs="?", default="serve", choices=["serve", "train", "benchmark", "plot"],
                        help="Execution mode (default: serve)")
    parser.add_argument("--port", type=int, default=8000, help="Port to run dashboard server on")

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
