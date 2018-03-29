![alt text](https://redacted "TC Build Status Icon")  [![Build Status](http://redacted/status.svg)](http://redacted)

## HPaccess
A Python utility to manage the admin account password and LDAP membership of the OA and the VCM

#### Prerequisites
* Linux Ubuntu 14.04 server
* Python 2.7

#### Installation
```bash
wget -O install.sh https://redacted/install.sh
chmod +x install.sh
sudo ./install.sh [venv]
# Note: venv is optional but recommended - if specified will install all packages in a Python virtual environment
```

#### Usage

Create required environment variables
```bash
export hpaccess_username=<'Your AD User'>
export hpaccess_password=<'Your AD Password'>
export hpaccess_admin_pass=<'New Admin Password for OAs and VCMs'>
```

Create Yaml config file
```bash
cp hpaccess_config.yaml.example ~/hpaccess_config.yaml
vim ~/hpaccess_config.yaml
```

Run the script
```bash
python src/main/python/HPaccess/hpaccess.py
```

#### Development Server Installation

Clone the repository
```bash
git clone https://redacted.git
cd HPaccess
```

Install packages and dependencies
```bash
chmod +x build.sh
sudo ./build.sh
source venv/bin/activate
```

Build the application
```bash
pyb -X
```

Link module for development
```bash
cd target/dist/HPaccess*/
python setup.py develop
```

Run unit tests
```bash
pyb run_unit_tests
```
