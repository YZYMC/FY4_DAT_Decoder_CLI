# FY4 DAT Decoder CLI

[English](README.md) | Simplified Chinese

## 安装

### Forgejo/GitHub 上的发布页

预构建的包和二进制文件可以在发布页面获取。

### 包管理器

### APT

#### 支持的发行版：

- Debian 13 (Trixie)

- Debian Forky

- Ubuntu 24.04 LTS (Noble)

添加 APT 仓库：

```shell
curl -o /usr/share/keyrings/yzynet.asc https://sth.yzynetwork.org:8443/yzynet.asc
echo "deb [signed-by=/usr/share/keyrings/yzynet.asc] https://apt.yzynetwork.org:8443/ trixie main" | sudo tee /etc/apt/sources.list.d/yzynetwork.list
sudo apt update
```

安装：

```bash
sudo apt install fy4dec
```

### 从源码构建

#### 依赖项

- OpenSSL 开发包 (Debian 上的 `libssl-dev`)

#### 构建一个二进制文件

```shell
./build.sh
```

#### 构建一个 .deb 包

```bash
dpkg-buildpackage -us -uc -b
```

## 基础使用方法

使用二进制密钥文件：

```shell
fy4dec -k fy4b_lrit_key.bin FY4B-XXX.DAT
```

使用十六进制文本密钥文件：

```bash
fy4dec -h fy4b_lrit_key.hex FY4B-XXX.DAT
```

## 许可证

此程序使用了 GNU 通用公共许可证 3.0 版本。

完整许可证可在 [COPYING](COPYING) 页面查看。
