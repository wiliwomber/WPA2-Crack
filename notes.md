# Questions

- It looks like the python makes use of some native linux commands, e.g. ***iwconfig***. Where and how can we get a linux VM.
- What are the leaning goals of the workshop we prepare?
    (Is this one time for our group or a separate Workshop?)
- How much time should the workshop take?
- Which language for the workshop?
  - Deutsch
- What attack to conduct?
- Can we use a real router to do the hack?

# Ideas

- Agenda Workshop
  - Theorie WPA2 -> 4-Way Handshake (IEEE 802.11i-2004)
    <https://en.wikipedia.org/wiki/IEEE_802.11i-2004>
  - Theorie Schwachstellen
  - Angriff
    - Social Engineering (Nachbar)
    - Wordlist erstellen
    - Capture Handshake
    - Crack PWD
  - Härtungsmaßnahmen -> Überleitung zu Gruppe

# Notes

-> Produktive Arbeitszeit, 4 volle Tage 2-5 Januar

- Wie funktioniert der Schlüsselaustausch
- SCAPI für Pcap um Packete analysieren (PKTF gruppenschlüssel berechnen)
- PCAP backup

- WSL mit ubuntu
- Oder VBox mit ubuntu

-> Bonus: Gegenmaßnahmen (Verbesserungen WPA3)

Dot11 fields: <https://scapy.readthedocs.io/en/latest/api/scapy.layers.dot11.html#id3>

The EAPOL (Extensible Authentication Protocol over LAN) frames are primarily used in Wi-Fi networks for secure authentication. The EAPOL frames include different types, each serving a specific purpose in the authentication process. Here are the main EAPOL frame types:

EAPOL-Start (Type 1):

This frame is sent by the supplicant (client) to initiate the EAP authentication process with the authenticator (AP or switch).
EAPOL-Key (Type 3):

The EAPOL-Key frame is a crucial part of the WPA and WPA2 authentication process. It is used for key exchange during the four-way handshake. This frame type includes various key-related information.
EAPOL-Logoff (Type 2):

Sent by the supplicant to terminate the EAP authentication session.
The EAPOL-Key frame (Type 3) is particularly important, and it has different codes within the frame that define its specific purpose. The EAPOL-Key frame includes the following codes:

Key Information Field (Key Info):

Bits within the Key Info field indicate the purpose of the EAPOL-Key frame. For example, it may indicate whether the frame is part of the four-way handshake, a group key update, or an individual key update.
Key Descriptor Version (Key Descriptor):

Specifies the version of the key descriptor. For example, WPA uses Key Descriptor Version 1, while WPA2 uses Key Descriptor Version 2.
Key Length Field:

Indicates the length of the Key Data field.
Key Data Field:

Contains different types of information, including cryptographic material used for securing the communication.
Understanding the specific bits and fields within the EAPOL-Key frame requires a deeper understanding of the IEEE 802.11 and EAPOL standards. The interpretation may vary depending on the specific context and security protocols in use (WPA, WPA2, etc.).

If you're working with EAPOL frames in a specific implementation, I recommend consulting the relevant standards documentation or specifications for detailed information on the frame types and their interpretations.
