# CoolLEDUX Linux GIF Uploader

Native Linux uploader for CoolLEDUX BLE LED panels.

This project allows Linux users to upload animated GIF files directly to a CoolLEDUX display without requiring Android emulators, Windows software, or the official mobile application.

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

### Known Limitation

`--force` works by modifying the first frame timing so the panel treats the upload as a new animation.

For some seamless looping GIFs (such as Matrix rain effects), this may introduce a visible stutter at the loop point.

If smooth playback is important, upload normally:

```bash
coolledux-upload myanimation.gif --auto
```

or make a small edit to the GIF before uploading.

Static images are generally unaffected.

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

## Notes and Known Behavior

### Frame Limits

Testing has shown:

* 40 frames is the safest and most compatible limit.
* The official CoolLED1248 app appears to use a 40-frame limit.
* The panel hardware can accept more than 40 frames.
* Uploads up to approximately 55 frames have been successfully tested.
* Uploads of 56 frames and higher may be rejected by the panel.

For maximum compatibility with both the Linux uploader and the official mobile application, 40 frames is recommended.

### Panel Discovery

The panel may occasionally stop advertising while connected to another device.

If auto-discovery fails:

* Close the mobile app.
* Disconnect any existing BLE connections.
* Try again using `--auto`.
* Or specify the address manually using `--address`.

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

* Additional protocol research
* JT file investigation
* Additional panel support
* GUI frontend
* Packaging for major Linux distributions

---

## License

Open source.

See LICENSE file for details.

---

## Credits

CoolLEDUX protocol reverse engineering performed on Linux using:

* Python
* Bleak
* Pillow

Thanks to the maker community for testing, feedback, and experimentation with these inexpensive BLE LED panels.
