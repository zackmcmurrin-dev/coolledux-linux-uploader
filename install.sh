#!/usr/bin/env bash
set -e

APP_NAME="coolledux-upload"
INSTALL_DIR="$HOME/.local/bin"
PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "CoolLEDUX Linux GIF Uploader installer"
echo

if ! command -v python3 >/dev/null 2>&1; then
    echo "ERROR: python3 is not installed."
    exit 1
fi

cd "$PROJECT_DIR"

echo "Creating Python virtual environment..."
python3 -m venv .venv

echo "Installing Python dependencies..."
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

echo "Installing command to $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"

cat > "$INSTALL_DIR/$APP_NAME" <<EOF
#!/usr/bin/env bash
source "$PROJECT_DIR/.venv/bin/activate"
python "$PROJECT_DIR/coolledux-upload.py" "\$@"
EOF

chmod +x "$INSTALL_DIR/$APP_NAME"

echo
echo "Install complete."
echo
echo "If the command is not found, run:"
echo '  export PATH="$HOME/.local/bin:$PATH"'
echo
echo "Test with:"
echo "  coolledux-upload --help"
echo
echo "Example:"
echo "  coolledux-upload test.gif --auto --force"
