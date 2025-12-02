# WPA3-Attack
WPA3 Attack

Here are the scripts translated into English. The attacks were implemented 100% based on scientific studies.

I recommend the following attacks:

1. cookie_guzzler (script: orchestator_enhanced_plus_en.py) (5 GHz and 2.4 GHz)

2. double_decker (script: orchestator_final_mit_allen_details_en.py) (5 GHz and 2.4 GHz)

3. amplification (script: orchestator_final_mit_allen_details_en.py) (only 2.4 GHz) 

4. “case6_radio_confusion”: Confuses dual-band drivers. Purpose: Crashes the 5 GHz band. Broadcom.
 “case6_radio_confusion_reverse”: Inverse logic of Case 6. Purpose: Crashes the 2.4 GHz band. Broadcom.
 “case13_radio_confusion_mediatek”: Confuses MediaTek drivers. Purpose: Crashes the 2.4 GHz band.
 “case13_radio_confusion_mediatek_reverse”: Inverse logic of Case 13. Purpose: Crashes the 5 GHz band.
With this attack, it is possible to crash any band of the router. I managed to crash the 2.4 GHz band on a Broadcom router, but with an attack for Mediatek routers: case13_radio_confusion_mediatek!


Router-specific attacks may require forensic preparatory work:

See: Broadcom Qualcomm Mediatek chipset find out.txt.
Most attacks require valid 

SAE_SCALAR_HEX/SAE_FINITE_ELEMENT_HEX = values. See: Wireshark settings.txt

If you have any questions, please do not hesitate to contact me.
