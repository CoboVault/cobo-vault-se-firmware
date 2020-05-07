
# Cobo Vault Secure Element Firmware Update Package Verification
## Instruction

The Cobo Vault offer a method to verifying official release update package. You can compare the version package compiled from GITHUB source code with the official release update package.

The python script `upgrade/make_update_package.py` is for verifying secure element Firmware update package.
Refer the following steps below:

## Download official release update package
- [Cobo Value offical firmware website](https://cobo.com/hardware-wallet/firmware)

## Unzip official release update package
  Use the public key [] to unzip update package.
  Update package consists of the following parts:
- `app_*.apk` : Cobo Vault cold update version package
- `manifest.json` : Update package digest information
- `serial_*.bin` : Cobo Vault secure element update version package
- `signed.rsa` : Signature for update package

## Download source code
- [Cobo Value secure element source code website](https://github.com/CoboVault/cobo-vault-se-firmware)
`git clone git@github.com:CoboVault/cobo-vault-se-firmware.git`
  The commit ID of source code should be same as official release update package.

## Build version package
  Build with ARM IDEs like "RealView MDK V4.x".

## Make update package
  Use python script to make a update package from build hex file.
  Command is "make_update_package.py -t TARGET_VERSION", "TARGET_VERSION" should be same as official release update package. You can find in [version_def.h](https://github.com/CoboVault/cobo-vault-se-firmware/blob/master/source/version_def.h).
  Such as `Python upgrade/make_update_package.py -t 0.3.5.000001`. `app.0.3.5.000001.bin` is the update package.

  `app.0.3.5.000001.bin` is consist of the following parts:
| Index | Part | Length | Description
|:-------:|:-----------------:|:-----------------:|:-----------------
1 | Header | 128Bytes   | version info and signature for verifying
2 | Body   | 528Bytes*n | version package encrypted and checksum

Update Package Header's length is 128 bytes. It is consist of the following parts:
| Index | Item | Length | Description
|:-------:|:-----------------:|:-----------------:|:-----------------
1 | ver            | 4Bytes     | version BCD encode
2 | ver_checksum   | 4Bytes     | front 4 bytes of ver sha256
3 | reserve        | 24Bytes    | reserve
4 | body_hash      | 32Bytes    | sha256 value of entire body
5 | signature      | 64Bytes    | signature of body_hash

Update Package Body has several 528 bytes blocks. Each block is consist of the following parts:
| Index | Item |  Sub Item| Length | Description
|:-------:|:-----------------:|:-----------------:|:-----------------:|:-----------------
1 | block_content  |  block_addr   | 8Bytes   | flash address of block (3des encrypt)
2 | block_content  |  block_bin    | 512Bytes | package bin of block (3des encrypt)
2 | bloc_checksum  |  /            | 8Bytes   | front 8 bytes of block_content(3des encrypt) sha256

More information about "make_update_package.py" , you can execute `make_update_package.py -h`

## Verify update package
After compare the update package with the `serial_*.bin` unziped from official release update package,
You will find the "signature" in update Package Header is different.

Beyond that, the other parts should be same.
It could prove the official release update package was built by GITHUB source code.



