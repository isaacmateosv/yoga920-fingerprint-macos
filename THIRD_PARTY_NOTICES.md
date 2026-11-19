# Third-party notices

yoga-fp is © 2026 isaacmateosv and contributors, released under the MIT License (see `LICENSE`).

The installer package bundles or builds on the following components. Each remains under its own license.

| Component | Use | License |
|---|---|---|
| [python-validity](https://github.com/uunicorn/python-validity) (patched copy in `vendor/`) | Sensor protocol, TLS pairing, flash layout | MIT (`vendor/LICENSE.python-validity`) |
| [CPython](https://www.python.org) 3.x (private runtime in the package) | Runs the daemon | Python Software Foundation License |
| [NumPy](https://numpy.org) | Image arrays | BSD 3-Clause |
| [OpenCV](https://opencv.org) (`opencv-python-headless`) | SIFT features, RANSAC | Apache License 2.0 |
| [cryptography](https://cryptography.io) | AES-256-GCM template encryption | Apache License 2.0 / BSD 3-Clause |
| [cffi](https://cffi.readthedocs.io), [pycparser](https://github.com/eliben/pycparser) | Dependencies of cryptography | MIT / BSD 3-Clause |
| [PyUSB](https://pyusb.github.io/pyusb/) | USB access | BSD 3-Clause |
| [libusb-package](https://github.com/pyocd/libusb-package) (bundles [libusb](https://libusb.info)) | USB backend library | Apache 2.0 (package), LGPL-2.1 (libusb) |

**Not included:** Lenovo/Synaptics firmware (`6_07f_Lenovo.xpfwext`). Download Lenovo's official driver package
`n1cgn08w.exe` (support page DS120491); the installer verifies its SHA-512 and extracts the file. Packages built
with `--fwext` for personal recovery contain it and must not be redistributed.

The libusb shared library is used unmodified as a separate dynamic library; its source is available at
https://github.com/libusb/libusb. Full license texts of the bundled Python packages are installed alongside
them in the private runtime (`*.dist-info/LICENSE*`).
