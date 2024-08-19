Suricata Network Intrusion Detection System (NIDS)
Introduction
This project is a Network Intrusion Detection System (NIDS) using Suricata. The system is configured to monitor network traffic on a specified interface and detect potential security threats based on predefined rules.
Project Structure
The project directory is structured as follows:
```
├── configs
│   ├── rules
│   │   └── emerging-threats.rules
│   └── suricata.yaml
├── logs
│   └── eve.json
└── Dockerfile
```
This structure includes configuration files, rules, logs, and a Dockerfile for containerization.
Suricata Configuration
The `suricata.yaml` file contains the main configuration for Suricata. It defines rule files, network interfaces to monitor, logging configurations, and other settings necessary for Suricata to function as an IDS.
Example configuration for `suricata.yaml`:

    %YAML 1.1
    ---
    # Suricata Configuration File

    # Define the rule files to be used by Suricata
    rule-files:
      - emerging-threats.rules  # Path to your custom rule files

    # Address groups to define internal and external networks
    vars:
      address-groups:
        internal-networks: [192.168.1.0/24]  # Define internal networks
        external-networks: [10.0.0.0/8]  # Define external networks (optional)

    # Logging configuration
    logging:
      default-log-level: info  # Logging level (debug, info, notice, warning, error, critical)
      default-log-directory: logs  # Directory to store log files
      outputs:
        - filetype: fast
          filename: logs/eve.json  # EVE JSON output file
        - filetype: alert
          filename: logs/alert.ids  # Alert log file

    # Define network interfaces to be monitored
    af-packet:
      - interface: "Wi-Fi 2"  # Interface to monitor
        threads: 4  # Number of threads for processing

    # Performance settings
    processing:
      # Number of threads for packet processing
      threads: 4

    # Miscellaneous settings
    suppress:
      # Example suppression file
      - file: suppress.rules

    # Define flow settings
    flow:
      # Define the maximum number of flows
      memcap: 128mb  # Memory cap for flow management
      timeout:
        udp: 30s  # UDP flow timeout
        tcp: 1m  # TCP flow timeout

    # Define rules to be loaded
    rule-files:
      - /etc/suricata/rules/emerging-threats.rules  # Example path for rule files
      - /etc/suricata/rules/local.rules  # Local custom rules
    
How to Run the Project
Running on Windows
1. Install Suricata on your Windows machine.
2. Copy the `suricata.yaml` configuration file to `C:\Program Files\Suricata\`.
3. Place the custom rule file `emerging-threats.rules` in the appropriate directory.
4. Open Command Prompt as an Administrator.
5. Run Suricata with the following command:
   ```
   "C:\Program Files\Suricata\suricata.exe" -c "C:\Program Files\Suricata\suricata.yaml" -i "<Your Network Interface>"
   ```
6. Suricata will start monitoring the specified network interface and log activity to the `logs/` directory.
Running on Kali Linux
1. Install Suricata on your Kali Linux machine using `apt-get install suricata`.
2. Copy the `suricata.yaml` configuration file to `/etc/suricata/`.
3. Place the custom rule file `emerging-threats.rules` in the `/etc/suricata/rules/` directory.
4. Open a terminal and run the following command:
   ```
   sudo suricata -c /etc/suricata/suricata.yaml -i <Your Network Interface>
   ```
5. Suricata will begin monitoring the specified network interface and log activity to `/var/log/suricata/`.
Using Docker
You can also run Suricata in a Docker container. Build the Docker image using the provided Dockerfile:
```sh
docker build -t suricata-nids .
```
Run the Docker container with the following command:
```sh
docker run --rm --net=host -v $(pwd)/configs:/etc/suricata suricata-nids -c /etc/suricata/suricata.yaml -i <Your Network Interface>
```
This will launch Suricata in a container and use your configuration files.
Contributing
Contributions are welcome! If you have any suggestions or improvements, please submit a pull request or open an issue.
License
This project is licensed under the MIT License - see the LICENSE file for details.
