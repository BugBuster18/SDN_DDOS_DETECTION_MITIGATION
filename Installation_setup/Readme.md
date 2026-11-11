## Installation

### Step 1
Install [VirtualBox](https://www.virtualbox.org/wiki/Downloads) or VMware Workstation.

### Step 2
Install [Mininet](https://github.com/mininet/mininet/releases/) or set up Mininet on Ubuntu.

### Step 3
Install [Ubuntu 20.04/22.04](https://ubuntu.com/download/desktop) in the VM.

### Step 4
Install the Ryu SDN controller in Ubuntu:
```bash
pip install ryu
```

### Step 5
Copy the project files to your VM and install Python dependencies:
```bash
cd ddos-project
python3 -m venv ddos-env
source ddos-env/bin/activate
pip install scikit-learn pandas numpy matplotlib ryu
```

---

### Running the Controller (Ubuntu VM)

```bash
# Check your IP address
ifconfig
# Note your IP (e.g., 192.168.X.X)

# Change to controller directory
cd Codes/controller

# Start the Ryu controller
ryu-manager controller.py
```

### Running the Mininet Topology

```bash
# Change to mininet directory
cd Codes/mininet

# Run topology (pass controller IP as argument)
sudo python3 topology.py 192.168.X.X
```

### hping3 DDoS Simulation Commands

```bash
# ICMP flood
hping3 -1 -V -d 120 -w 64 -p 80 --rand-source --flood <target_ip>

# SYN flood
hping3 -S -V -d 120 -w 64 -p 80 --rand-source --flood <target_ip>

# UDP flood
hping3 -2 -V -d 120 -w 64 -p 80 --rand-source --flood <target_ip>
```
