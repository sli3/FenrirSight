# FenrirSight
FenrirSight: A versatile and user-friendly Python port scanner. Leveraging `geoip2`, `socket`, `nmap`, and `os`, it offers comprehensive scanning options including all, specific, top, and range-based port checks for insightful network exploration.

## Table of Contents
* [Features](##Features)

* [Prerequisites](##Prerequisites)

* [Installation](##Installation)

* [Usage](##Usage)

* [Output Explanation](##Output Explanation)

* [Contributing](##Contributing)

* [Licence](##Licence)

## Features
FenrirSight provides a robust and interactive command-line interface for network port scanning, offering the following capabilities:

* **Target** Host Validation: Ensures the entered hostname is valid before proceeding.

* **Geographical** Location Data: Displays the continent, country, city, and postal code of the target IP address using GeoIP data.

* **Multiple Scan Options:**

    * **Scan All Ports:** Comprehensive scan of all available ports.

    * **Scan Specific Port:** Check the status of a single, user-defined port.

    * **Scan Top Ports:** Quickly scan the most commonly used ports.

    * **Scan Port Range:** Define a custom range of ports to scan.

* **Detailed Scan Results:** Outputs port number, state, service name, reason, and Common Platform Enumeration (CPE) data.

* **Colour-Coded Output:** Port statuses are visually highlighted for quick identification (green for open, red for closed, yellow for other states).

* **Result Persistence:** All scan results are automatically saved to scan_result.txt for future reference.

* **User-Friendly Menu:** An intuitive menu system guides the user through the scanning process.

## Prerequisites
To run FenrirSight successfully, you need to ensure the following are installed and configured on your system:

1. Python 3.x: FenrirSight is written in Python 3.

    * Download and install from [python.org](https://python.org/).

2. **Nmap:** The network scanning utility. `python-nmap` is just a wrapper; Nmap itself must be installed.

    * **Linux (Debian/Ubuntu):** `sudo apt-get install nmap`

    * **macOS (Homebrew):** `brew install nmap`

    * **Windows:** Download the installer from [nmap.org](https://nmap.org/).

3. Python Libraries: Install these using `pip`:
```
pip install python-nmap geoip2
```
4. **GeoLite2 Database Files:** FenrirSight uses MaxMind's GeoLite2 databases for geographical IP location. These files (`.mmdb`) are not included in the repository due to licensing. You must download them manually:

    * Go to the [MaxMind GeoLite2 Download Page.](https://www.maxmind.com/en/geolite2/downloads/)

    * You will need to create a free MaxMind account to download these databases.

    * Download the GeoLite2-Country and GeoLite2-City databases (look for the `.mmdb` format).

    * Place both `GeoLite2-Country.mmdb` and `GeoLite2-City.mmdb` files in the same directory as the `FenrirSight.py` script.

## Installation
1. Clone the repository:
```
git clone https://github.com/YourUsername/FenrirSight.git

cd FenrirSight
```
(Replace `YourUsername` with your actual GitHub username)

2. **Recommended: Use a Virtual Environment (venv)**

It's highly recommended to use a Python virtual environment to manage project dependencies and avoid conflicts with other Python projects.
```
python3 -m venv venv
source venv/bin/activate  # On Linux/macOS
# venv\Scripts\activate   # On Windows
```
Once activated, your terminal prompt will typically show (`venv`) indicating you are in the virtual environment.

3. **Install Python dependencies:**
```
pip install -r requirements.txt # (assuming you create one, or use the command from Prerequisites)
```
*If you don't have a `requirements.txt` yet, you can create one after installing the libraries:*
```
pip freeze > requirements.txt
```
4. **Download and place GeoLite2 databases:** as described in the Prerequisites section.

## Usage
To run FenrirSight, navigate to the directory where you cloned the repository and execute the script:
```
python FenrirSight.py
```
The script will then guide you through the following steps:

1. **Enter Hostname:** Prompt to enter the target hostname or IP address (e.g., `scanme.org`, `192.168.1.1`).

2. **Select Scan Option:** Choose from the menu (Scan All Ports, Scan Specific Port, Scan Top Ports, Scan Port Range, Exit).

3. **View Results:** The scan results will be displayed in the terminal and saved to `scan_result.txt`.

## Output Explanation
FenrirSight provides detailed output for each scan:

* **Host Information:** Displays the target hostname, IP address, and its geographical location (continent, country, city, postal code).

* **Protocol & State:** Shows the network protocol (e.g., `tcp`) and the overall state of the host (e.g., up).

* **Port Scan Table:**

    * `Port`: The port number.

    * `State`: The status of the port (e.g., `open`, `closed`, `filtered`).

    * `Service Name`: The service running on the port (e.g., `ssh`, `http`).

    * `Reason:` Nmap's reason for determining the port state.

    * `Common Platform Enumeration (CPE):` Provides structured information about the vendor, product, version, and update of the service detected on the port.

* Colour Coding:

    * **Green:** Port is `open`.

    * **Red:** Port is `closed`.

    * **Yellow:** Port is `filtered` or in another state.

### Example Snippet of Output:
```
#########################################################
############# Target host physical location #############
#########################################################
Host name: www.scanme.org
IP address: 45.33.32.156
Continent name: North America
Country name: United States
City name: Fremont
Postal code: 94536
State: up
Protocol: tcp
--------------------------------------------------------------------------------------------------------------------------------------------
Port  State      Service Name         Reason               Common Platform Enumeration
--------------------------------------------------------------------------------------------------------------------------------------------
21    closed     ftp                  conn-refused        
22    open       ssh                  syn-ack              linux linux_kernel
80    open       http                 syn-ack              apache httpd
--------------------------------------------------------------------------------------------------------------------------------------------
```
## Contributing
Contributions are welcome! If you have suggestions for improvements, bug fixes, or new features, please feel free to:

1. Fork the repository.

2. Create a new branch (`git checkout -b feature/YourFeatureName`).

3. Make your changes.

4. Commit your changes (`git commit -m 'Add Your Feature'`).

5. Push to the branch (`git push origin feature/YourFeatureName`).

6. Open a Pull Request.

## Licence
This project is licensed under the **MIT Licence** - see the `LICENCE` file for details.
