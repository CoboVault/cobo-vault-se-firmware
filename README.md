# Cobo Vault Secure Element Firmware

Cobo Vault is an air-gapped, open source hardware wallet that uses completely transparent QR code data transmissions. Visit the [Cobo Vault official website]( https://cobo.com/hardware-wallet/cobo-vault)  to learn more about Cobo Vault.

You can also follow [@CoboVault](https://twitter.com/CoboVault) on Twitter.

<div align=center><img src="https://cobo.com/_next/static/images/intro-2b5b0b44cc64639df4fcdd9ccc46fd4b.png"/></div>

## Table of Contents

- [Clone](#clone)
- [Build](#build)
- [Code Structure](#code-Structure)
- [Issues and PRs](#issues-and-prs)
- [License](#license)

## Clone

    git clone git@github.com:CoboVault/cobo-vault-se-firmware.git

## Build
    Currently, the source can only be compiled on Windows.
    You can build with ARM IDEs like "RealView MDK V4.x".    

## Code Structure
Modules:

`Listings`: Configuration files for compiling Secure Element source code

`source` : Source files for Secure Element firmware

`upgrade` : Python script for verifying update package

`*.bat`: Script file for compiling

`uvproj`: Project files for MDK IDE

## Issues and PRs
Please submit any issues  [here](https://github.com/CoboVault/cobo-vault-SE-firmware/issues). PRs are also welcome!

## License
[![GPLv3 License](https://img.shields.io/badge/License-GPL%20v3-green.svg)](https://opensource.org/licenses/)
This project is licensed under the GPL License. See the [LICENSE](LICENSE) file for details.
