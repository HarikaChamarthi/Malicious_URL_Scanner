🛠️ Requirements
--------------------------------------------------------------------------------------------------
Python 3.x (preferably Python 3.8+ for best compatibility)

Install dependencies with:

pip install -r requirements.txt


Libraries / Tools Used
-------------------------------------------------------------------------------------------------

Tkinter (or customtkinter) – for the GUI

requests – to call the VirusTotal API or other web-services

validators – to validate URL formats

smtplib / email – for sending OTP through email (authentication part)

sqlite3 (or your chosen DB) – if you store user data / logs

os, sys, subprocess – for operating system operations (like editing the Windows hosts file)

Operating System Note:

The “block/unblock malicious websites via the hosts file” feature is designed for Windows environments (modifying C:\Windows\System32\drivers\etc\hosts).


Hardware
-------------------------------------------------------------------------------------------------

No special hardware required. A standard desktop/laptop suffices.

Internet connection required to query the VirusTotal API.

Use with caution: modifying the hosts file requires administrative privileges.


📂 Dataset / API Information
---------------------------------------------------------------------------------------------

This project does not use a classic image/text dataset but relies on the VirusTotal API (or similar threat intelligence services) to scan and classify URLs as malicious or benign.

Data flow / sources:

User inputs a URL in the GUI.

The program validates the URL format using validators.

The URL is sent to the VirusTotal API (or other configured endpoint).

The API returns a result (malicious / suspicious / clean).

Based on the result, the program offers to block the URL (by adding an entry in the Windows hosts file) or unblock if previously blocked.

Classes:

Benign / Clean URL

Malicious URL

Possibly Suspicious / Undetermined (depending on API response)

Dataset size / thresholds:

Because the classification relies on live API responses rather than a fixed dataset, there is no fixed “number of URLs” in training.

You can document approximate usage, e.g.:

Over 1,000 URLs were tested in our internal evaluation: ~900 benign, ~100 malicious. (You can update with your actual counts.)

User Authentication:

The project includes OTP-via-email authentication: user enters email → receives OTP → gains access to the scanning interface.

This adds a layer of access control / logging that improves usability in an internal team or organisational setting.
