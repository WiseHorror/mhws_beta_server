## mhws_beta_server
### Updated for OBT2 compatibility

This is a project that simulates server requests for the Monster Hunter Wilds Beta Test.

## Disclaimer

This project is intended solely for educational and learning purposes and must not be used for commercial purposes. Please delete this software within 24 hours of downloading. We do not take any responsibility for any illegal usage or distribution of this software.

## Usage

### Edit hosts file

> [!WARNING]
> **Do not forget to revert the changes made to the hosts file when the full game comes out, otherwise it might prevent you from connecting to the official Capcom servers.**

1. Navigate to `C:\Windows\System32\drivers\etc`
2. Open the `hosts` file with any text editor.
3. Add these new lines at the bottom of the file:
   - `127.0.0.1 hjm.rebe.capcom.com`
   - `127.0.0.1 40912.playfabapi.com`
   - `127.0.0.1 obt-api.wilds.monsterhunter.com`
4. Save the file.

### Install the Go programming language and run the server

1. Install the Go programming language by going [here](https://go.dev/dl/) and choosing the correct version for your system.
2. Open a terminal window in this project's root directory by doing right-click > Open in Terminal
> [!NOTE]  
> Optional but convenient: Create a .bat file in the project's root directory and paste the command below.
3. Run the following command: `go run mhws_beta_server`
4. Install the certificate by going to the cert folder and double-clicking `root.crt` > Install Certificate... > Local Machine > Place all certificates in the following store > Browse > Trusted Root Certification Authorities > OK > Next > Finish
5. Run the game and you should be able to play!

## Thanks
[@EdLovecraft](https://github.com/EdLovecraft)

[@Evilmass](https://github.com/Evilmass)

[@pangliang](https://github.com/pangliang)

[@KujouRinka](https://github.com/KujouRinka)
