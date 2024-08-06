# Backend server for decoding Secure Unique NFC Message (SUN)

An example of Flask application which can decrypt data contained in NDEF "mirrors" and validate their AES-CMAC cryptographic signature. Implemented according to _AN12196 "NTAG 424 DNA and NTAG 424 DNA TagTamper features and hints"_.

**Pull requests welcome.**

*Note: NTAG — is a trademark of NXP B.V.*

*Note: This GitHub project is not affiliated with NXP B.V. in any way. Product names are mentioned here in order to inform about compatibility.*

## Demo
Check out the demo at [sdm.nfcdeveloper.com](https://sdm.nfcdeveloper.com/). This server is using blank authentication keys (all-zeros, factory default). You can use this server for testing and should work fine until you change the default factory keys on your tags.

## How to configure the tags?
We suggest using [NFC Developer App](https://nfcdeveloper.com/tag-app/tutorial/) for Android/iOS in order to configure the tags. This application will do most things "under the hood" and your tags will work out-of-the-box with this project.

<a href="https://nfcdeveloper.com/tag-app/tutorial/"><img src="https://raw.githubusercontent.com/nfc-developer/sdm-backend/33afbc8ca7abe33326d947610556315e5ba5e842/.github/nfcdeveloperapp-ad.png" title="NFC Developer App Information"></a>

## Contact
Feel free to reach me at hello@nfcdeveloper.com if you have any questions concerning this topic.

## How to test?
### Manual installation
1. Clone the repository
   ```
   apt install -y git
   git clone https://github.com/Asadler1/sdm-backend-forked-public.git
   cd sdm-backend
   ```
2. Setup the virtualenv
   ```
   apt install -y python3 python3-pip python3-venv
   python3 -m venv fork
   source fork/bin/activate
   ```
3. Install the required dependencies and copy example config:
   ```
   pip3 install -r requirements.txt
   cp config.dist.py config.py
   ```
4. Run Flask development server:
   ```
   python3 app.py --host 0.0.0.0 --port 5111
   ```

Note: If you are running production instance, the `MASTER_KEY` should be an unique 16 byte value (hex encoded). However, all-zeros key is perfectly fine for testing.

## Authors

* Michał Leszczyński (hello@nfcdeveloper.com)

Feel free to contact if you have any questions.
