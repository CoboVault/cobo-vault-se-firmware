# Cobo Vault Secure Element firmware

Cobo Vault is an air-gapped & open source hardware wallet that uses completely transparent QR code data transmissions.Visit [Cobo Vault official website]( https://cobo.com/hardware-wallet/cobo-vault)  to know more information about Cobo Vault.

Follow [@Cobo Vault](https://twitter.com/CoboVault) on Twitter.

<div align=center><img src="https://cobo.com/_next/static/images/intro-2b5b0b44cc64639df4fcdd9ccc46fd4b.png"/></div>

## Table of Contents

- [Clone](#clone)
- [Build](#build)
- [Code Structure](#code-Structure)
- [Core Dependencies](#core-dependencies)
- [issues-and-prs](#issues-and-prs)
- [License](#license)

## Clone

    git clone git@github.com:CoboVault/cobo-vault-SE-firmware.git

## Build
    currently the source can only be compiled on windows
    you can build with ARM IDEs like "RealView MDK V4.x"    

## Code Structure
Modules:

`Listings`: the configuration files for compiling  secure element source code

`source` : Source files for Secure Element firmware

`*.bat`: script file for compiling

`uvproj and uvproj`: project files for MDK IDE

## issues and PRS
any issues please submit at [issues](https://github.com/CoboVault/cobo-vault-cold/issues). and PRS are welcome!

## License
[![GPLv3 License](https://img.shields.io/badge/License-GPL%20v3-green.svg)](https://opensource.org/licenses/)
This project is licensed under the GPL License - see the [LICENSE](LICENSE) file for details
