## Apology (from original author)
Due to my oversight in code review, sensitive information was exposed, causing inconvenience and confusion for other developers. I apologize to the other developers([APOLOGY.md](APOLOGY.md)), refer to [#3](https://github.com/KujouRinka/mhws_beta_server/issues/3) and [#4](https://github.com/KujouRinka/mhws_beta_server/pull/4).

由于本人审查代码疏忽导致出现了敏感信息而给其他开发者造成了不便于困惑，在这里向其他开发者致歉([APOLOGY.md](APOLOGY.md))，请参考 [#3](https://github.com/KujouRinka/mhws_beta_server/issues/3) 与 [#4](https://github.com/KujouRinka/mhws_beta_server/pull/4)

I hope everyone can learn from my example and avoid making such stupid mistakes out of negligence.

希望大家以我为戒，不要因为疏忽做出这么愚蠢的事

## mhws_beta_server

This is a project that simulates server requests for the Monster Hunter Wilds Beta Test.

## Disclaimer

This project is intended solely for educational and learning purposes and must not be used for commercial purposes. Please delete this software within 24 hours of downloading. We do not take any responsibility for any illegal usage or distribution of this software.

## Usage

### Edit hosts file

**Important: The changes made to the hosts file should be reverted when the full game comes out, otherwise it might prevent you from connecting to the official Capcom servers.**

1. Navigate to `C:\Windows\System32\drivers\etc`
2. Open the `hosts` file with any text editor.
3. Add these new lines at the bottom of the file:
   - `127.0.0.1 hjm.rebe.capcom.com`
   - `127.0.0.1 40912.playfabapi.com`
4. Save the file.

### Install the Go programming language and run the server

1. Install the Go programming language by going [here](https://go.dev/dl/) and choosing the correct version for your system.
2. Open a terminal window in this project's root directory by doing right-click > Open in Terminal
   - Optional, but convenient: Create a .bat file in the project's root directory and paste the command below.
3. Run the following command: `go run mhws_beta_server`
4. Install the certificate by going to the cert folder and double-clicking `root.crt` > Install Certificate... > Local Machine > Place all certificates in the following store > Browse > Trusted Root Certification Authorities > OK > Next > Finish
5. Run the game and you should be able to play!

## Thanks
[@EdLovecraft](https://github.com/EdLovecraft)

[@Evilmass](https://github.com/Evilmass)

[@pangliang](https://github.com/pangliang)

[@KujouRinka](https://github.com/KujouRinka)
