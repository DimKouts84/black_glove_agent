import subprocess
import sys
import time
import os
import threading

def read_output(process, stop_event):
    """Read output from process and print it."""
    while not stop_event.is_set():
        output = process.stdout.read(1)
        if not output:
            break
        sys.stdout.buffer.write(output)
        sys.stdout.buffer.flush()

def run_test():
    # Set environment to ensure session persistence
    env = os.environ.copy()
    env["CHAT_SESSION_ID"] = "e2e_test_session"
    env["PYTHONUNBUFFERED"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONLEGACYWINDOWSSTDIO"] = "utf-8"

    # Use the current python executable
    cmd = [sys.executable, "-m", "agent.cli", "chat"]
    
    print(f"Starting agent: {' '.join(cmd)}")
    process = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=env,
        bufsize=0  # Unbuffered
    )

    # Start reader thread
    stop_event = threading.Event()
    reader = threading.Thread(target=read_output, args=(process, stop_event))
    reader.start()

    # Scenarios
    inputs = [
        "Add google.com as a domain asset",
        "Run a DNS lookup",  # Should prompt for target
        "google.com",        # Provide target
        "Run a DNS lookup on google.com and then check its SSL certificate",
        "What was the IP address from the DNS lookup we just did?",
        "Generate a summary report for google.com",
        "exit"
    ]

    try:
        # Give it time to start and show welcome message
        time.sleep(5)
        
        for inp in inputs:
            print(f"\n\n--- Sending Input: {inp} ---\n")
            process.stdin.write((inp + "\n").encode())
            process.stdin.flush()
            # Wait for processing (simulated user delay + processing time)
            # LLM calls can be slow, so give it generous time
            time.sleep(15) 
            
    except Exception as e:
        print(f"Error: {e}")
    finally:
        stop_event.set()
        if process.poll() is None:
            process.terminate()
        reader.join()

if __name__ == "__main__":
    run_test()
