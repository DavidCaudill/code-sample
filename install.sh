export http_proxy=redacted
export https_proxy=redacted

apt-get update
apt-get install -y wget git python-dev gcc python-pip

if [ ! -z "$1" ]
then
    pip install virtualenv
    mkdir ~/.virtualenvs
    cd ~/.virtualenvs
    virtualenv hpaccess_venv --distribute
    source hpaccess_venv/bin/activate
    cd hpaccess_venv
fi

pip install pip==9.0.1 --upgrade
pip install setuptools --upgrade
pip install git+https://redacted.git --process-dependency-links
