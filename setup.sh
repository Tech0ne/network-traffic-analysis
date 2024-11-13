#!/bin/bash

echo "== Setting up Virtual environement"
python3 -m venv .venv
source ./.venv/bin/activate

echo "== Installing requirements"
pip3 install -r requirements.txt

echo "== Creating run.sh script"

cat > run.sh << EOF
#!/bin/bash

echo "== Running"
source ./.venv/bin/activate

sudo python3 main.py
EOF

chmod +x run.sh

rm $0
