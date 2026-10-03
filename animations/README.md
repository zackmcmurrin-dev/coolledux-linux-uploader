# Animations

This directory contains GIF animations known to work on CoolLEDUX / CoolLED1248 LED matrix displays.

Upload an animation using automatic panel detection:

```bash
coolledux-upload animations/matrixGreen.gif --auto
```

Use `--force` when the panel already contains the same program and you need to resend it:

```bash
coolledux-upload animations/matrixGreen.gif --auto --force
```

Some seamless looping animations may show a small stutter when uploaded with
`--force` because force re-upload changes the first-frame timing. For the
smoothest loop, upload normally when possible.
