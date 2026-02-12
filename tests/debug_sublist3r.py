import sublist3r
print("Sublist3r imported successfully")
try:
    sublist3r.main("example.com", 40, savefile=None, ports=None, silent=True, verbose=False, enable_bruteforce=False, engines=None)
except Exception as e:
    print(f"Sublist3r failed: {e}")
