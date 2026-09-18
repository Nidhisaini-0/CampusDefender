from app.detector import monitor_bruteforce
from app.portscan import monitor_portscan
import threading

if __name__ == "__main__":
    t1 = threading.Thread(target=monitor_bruteforce)
    t2 = threading.Thread(target=monitor_portscan)

    t1.start()
    t2.start()

    t1.join()
    t2.join()
