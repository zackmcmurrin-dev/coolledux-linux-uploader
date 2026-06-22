# CoolLEDUX Linux GIF Uploader

Native Linux uploader for CoolLEDUX BLE LED panels.

This project allows Linux users to upload animated GIF files directly to a CoolLEDUX display without requiring Android emulators, Windows, or the official mobile application.

---

## Features

* Native Linux support
* BLE auto-discovery
* Upload animated GIFs
* Adjustable playback speed
* Brightness control
* Automatic GIF resizing
* Progress percentage display
* Force re-upload option
* Simple installer

---

## Requirements

* Linux
* Python 3.10+
* Bluetooth adapter
* CoolLEDUX LED panel

---

## Installation

Clone or download the project:

```bash
git clone https://github.com/YOURNAME/coolledux-linux-uploader.git
cd coolledux-linux-uploader
```

Run the installer:

```bash
chmod +x install.sh
./install.sh
```

If the command is not found after installation:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

Permanent fix:

```bash
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

---

## Finding Your Panel

Scan nearby BLE devices:

```bash
coolledux-upload --scan
```

Example:

```text
01:00:00:54:EC:17  CoolLEDUX
BE:67:00:40:0E:87  ELK-BLEDOM07
```

---

## Basic Usage

Upload a GIF using automatic panel detection:

```bash
coolledux-upload myanimation.gif --auto
```

Upload quietly:

```bash
coolledux-upload myanimation.gif --auto --quiet
```

---

## Force Re-Upload

The panel will skip uploads if it already contains the same animation.

To force an upload:

```bash
coolledux-upload myanimation.gif --auto --force
```

---

## Playback Speed

Double speed:

```bash
coolledux-upload myanimation.gif --auto --speed 2
```

Half speed:

```bash
coolledux-upload myanimation.gif --auto --speed 0.5
```

---

## Brightness

Brightness range is 0–15.

```bash
coolledux-upload myanimation.gif --auto --brightness 15
```

Medium brightness:

```bash
coolledux-upload myanimation.gif --auto --brightness 8
```

---

## Specify Device Address

If automatic detection fails:

```bash
coolledux-upload myanimation.gif \
    --address 01:00:00:54:EC:17
```

---

## Help

```bash
coolledux-upload --help
```

---

## Example Session

```bash
coolledux-upload test.gif --auto --force
```

Output:

```text
found CoolLEDUX: 01:00:00:54:EC:17

frames:              40
first delay:         418 ms
compressed size:     26098
chunks:              26

sending chunk 1/26 (3%)
sending chunk 2/26 (7%)
...
sending chunk 26/26 (100%)

done, watch panel
```

---

## Current Status

Working:

* BLE communication
* Authentication/login
* Program upload
* GIF animation upload
* Auto panel discovery
* Playback speed adjustment
* Brightness control
* Linux command installation

Planned:

* GitHub releases
* Package builds
* Additional panel support
* GUI frontend

---

## License

Open source.

See LICENSE file for details.

---

## Credits

Development Notes

This project was developed through a combination of manual reverse engineering, testing on real CoolLEDUX hardware, and AI-assisted coding/documentation.

The CoolLEDUX protocol was reverse engineered by analyzing the Android application, capturing BLE traffic, examining protocol behavior, and validating discoveries on actual hardware.

All protocol discoveries, packet validation, testing, and Linux compatibility verification were performed on real CoolLEDUX panels.

This project was created to make these inexpensive LED matrix displays easier to use from Linux without requiring Android devices, Windows software, or emulation.

License

Open source.

See LICENSE file for details.

Credits
Protocol Reverse Engineering, Testing, and Project Direction

Zachary McMurrin

AI-Assisted Development

OpenAI ChatGPT

Used for code generation assistance, debugging assistance, documentation writing, installer creation, and general development support.

Acknowledgements

## Acknowledgements

Thanks to the open-source community and everyone who shares technical knowledge, documentation, and tools.
