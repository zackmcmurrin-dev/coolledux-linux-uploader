# CoolLEDUX Linux Uploader

Native Linux uploader and control toolkit for CoolLEDUX BLE LED panels.

This project allows Linux users to upload animated GIFs, create native live clock programs, synchronize panel time, control brightness, and change persistent panel orientation without requiring Android emulators, Windows software, or the official mobile application.

Development is currently focused on reverse engineering the CoolLEDUX BLE protocol and making useful panel features available directly from Linux.

---

## Features

* Native Linux support
* BLE auto-discovery
* Animated GIF upload
* Multiple GIF upload with automatic cycling
* Automatic GIF resizing
* Adjustable GIF playback speed
* Progress percentage display
* Force re-upload option
* Native live clock programs
* 12-hour and 24-hour clock modes
* Custom native clock fonts
* Custom clock colon bitmaps
* External clock-face folders
* Custom clock colors and geometry
* Panel RTC time synchronization
* Brightness control
* Persistent panel orientation control (`none`, `x`, `y`, `xy`)
* Simple command-line installer
* Protocol experiment tools for development

---

## Requirements

* Linux
* Python 3.10+
* Bluetooth adapter
* CoolLEDUX LED panel

---

## Installation

Clone the repository:

```bash
git clone https://github.com/zackmcmurrin-dev/coolledux-linux-uploader.git
cd coolledux-linux-uploader
```

Run the installer:

```bash
./install.sh
```

The installer creates a Python virtual environment, installs the required
dependencies, and creates the `coolledux-upload` command in `~/.local/bin`.

If `coolledux-upload` is not found after installation:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

To add that directory to your Bash PATH permanently:

```bash
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

Verify the installation:

```bash
coolledux-upload --version
coolledux-upload --help
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

You can also specify the panel BLE address directly:

```bash
coolledux-upload myanimation.gif --address 01:00:00:54:EC:17
```

### Multiple GIFs

Multiple animations can be uploaded as one cycling program set:

```bash
coolledux-upload --multi first.gif second.gif third.gif --auto
```

A panel address can also be specified directly:

```bash
coolledux-upload --multi first.gif second.gif third.gif \
  --address 01:00:00:54:EC:17
```

The GIF order determines the playback order. All programs are configured
during one BLE session, matching the behavior of the official CoolLEDUX
application.

If a program is already stored on the panel, the uploader reuses the cached
copy instead of retransmitting its animation data. Missing programs are
uploaded normally and then included in the cycling set.

`--multi` requires at least two GIF files. `--force` is intentionally not
supported with multi-GIF uploads because forcing animated GIF programs
changes first-frame timing and may introduce a visible pause at the loop point.

### Brightness

Brightness can be set from 5 to 255 without uploading a GIF:

```bash
coolledux-upload --address 01:00:00:54:EC:17 --brightness 128
```

### Synchronize Panel Time

Synchronize the panel's real-time clock with the Linux system time:

```bash
coolledux-upload --address 01:00:00:54:EC:17 --sync-time
```

### Panel Orientation

The panel orientation setting is persistent and can be changed without
uploading new content:

```bash
coolledux-upload --address 01:00:00:54:EC:17 --flip none
coolledux-upload --address 01:00:00:54:EC:17 --flip x
coolledux-upload --address 01:00:00:54:EC:17 --flip y
coolledux-upload --address 01:00:00:54:EC:17 --flip xy
```

The available orientation modes are `none`, `x`, `y`, and `xy`.

---

## Native Live Clock

CoolLEDUX panels support native live clock programs. Unlike a pre-rendered
GIF, the panel maintains and displays the clock using its own real-time clock.

Upload a native clock:

```bash
coolledux-upload --clock --auto
```

Use 24-hour time:

```bash
coolledux-upload --clock --24-hour --auto
```

Choose a clock color:

```bash
coolledux-upload --clock --color green --auto
```

Colors can also be specified as RGB hex values:

```bash
coolledux-upload --clock --color '#00ff00' --auto
```

### Custom Clock Faces

Custom native clock faces can define digit artwork, colon artwork, color,
and geometry while retaining the panel's native live clock behavior.

Load a clock face by name or folder path:

```bash
coolledux-upload --clock --clock-face FACE_NAME --auto
```

Clock faces can also be customized with individual options such as:

```text
--custom-font
--custom-colon
--hour-x
--colon-x
--minute-x
--clock-y
--colon-w
```

Use `coolledux-upload --help` for the current list of clock options.

### Clock Preview

A custom clock can be rendered locally to a PNG without connecting to the
panel:

```bash
coolledux-upload --render-clock --render-text 12:34 --save preview.png
```

The uploader also includes `--upload-render-clock` for uploading a rendered
clock as static panel content. This is separate from the native live clock
mode.

---

## Force Re-Upload

The panel may skip an upload if it already contains the same program.

Force an animation upload:

```bash
coolledux-upload myanimation.gif --auto --force
```

Force a native clock upload:

```bash
coolledux-upload --clock --clock-face pipboy --auto --force
```

For GIF animations, `--force` changes the first-frame timing so the panel
treats the animation as a different program. This can introduce a visible
stutter at the loop point of some seamless animations.

For native clocks, `--force` changes an otherwise unused program-header byte.
Hardware testing shows this changes the program CRC and forces a fresh upload
without changing the clock's appearance or native live-clock behavior.

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
* Native program upload
* Animated GIF upload
* Multiple GIF upload and automatic cycling
* Cached-program reuse in multi-GIF sets
* Auto panel discovery
* Automatic GIF resizing
* Playback speed adjustment
* Brightness control
* Panel RTC time synchronization
* Persistent panel orientation control
* Native live clock programs
* 12-hour and 24-hour native clock modes
* Custom native clock digit fonts
* Custom native clock colon bitmaps
* External clock-face loading
* Custom clock colors and geometry
* Local clock preview rendering
* Linux command installation

Experimental / under investigation:

* Multiple content blocks in a single native program
* Additional CoolLEDUX BLE commands and protocol behavior
* Additional panel models and compatibility
* JT file format / protocol behavior

Possible future work:

* Additional panel controls
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
