# FY4 DAT Decoder CLI

English | [Simplified Chinese](README.zh-CN.md)

## Install

### Forgejo/GitHub releases

Pre-built binaries and packages are available on the Releases page.

### Package manager

### APT

#### Supported distributions:

- Debian 13 (Trixie)

- Debian Forky

- Ubuntu 24.04 LTS (Noble)

Add APT repository:

```shell
curl -o /usr/share/keyrings/yzynet.asc https://sth.yzynetwork.org:8443/yzynet.asc
echo "deb [signed-by=/usr/share/keyrings/yzynet.asc] https://apt.yzynetwork.org:8443/ trixie main" | sudo tee /etc/apt/sources.list.d/yzynetwork.list
sudo apt update
```

Install:

```bash
sudo apt install fy4dec
```

### Build from source

#### Build dependencies

- OpenSSL development libraries (`libssl-dev` on Debian)

#### Build a binary file

```shell
cc fy4dec.c -o fy4dec -lcrypto
```

#### Build a .deb package

```bash
dpkg-buildpackage -us -uc -b
```

## Basic usage

Using a binary key file:

```shell
fy4dec -k fy4b_lrit_key.bin FY4B-XXX.DAT
```

Using a ASCII (text) hex key file:

```bash
fy4dec -h fy4b_lrit_key.hex FY4B-XXX.DAT
```

## License

This program is licensed under the GNU General Public License v3.0 or later.

See [COPYING](COPYING) for the full license text.
