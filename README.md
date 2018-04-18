# SUTD ISTD Term 5 Programming Assignment 2
- Author: Valerene Goh Ze Yi
- ID: 1002457   
- Date: 18/04/2018

## Purpose of this program
To provide a secure and reliable file upload from the client to an Internet file server, using standard TCP sockets. The program is implemented using Java Cryptography Extension (JCE) and can handle arbitrary files (e.g. binary files instead of say ASCII texts only).

By secure, these two properties are ensured:
-	By implementing an authentication protocol (AP), file server (*SecStore*) is authenticated so data is guaranteed to not leak to random malicious entities.
-	By implementing a confidentiality protocol (CP), confidentiality of uploaded data is protected against eavesdropping by any curious adversaries.
By reliable, the server will store exactly what the client sent, without any loss, reordering or duplication of data.
Two cryptographic methods (asymmetric and symmetric-key algorithm) will be implemented and their performance will be compared at the end of this report.

## Specifications for the protocols
**AP (Authentication Protocol):** To ensure IP address is trusted by a CA (certificate authority) such as VerSign & IDA. In this case, we will be using CSE-CA service as our trusted CA. 
Hence, we will be ensuring that both client and server are the intended sender and recipient by authenticating both the server to the client and vice versa.
</br>
**CP (Confidentiality Protocol):** To avoid theft of data in transmission by using encryption methods.
Hence, we will be ensuring that the file is securely transmitted from the client to the authenticated server, by implementing either one of the following methods:
</br>
**CP-1:** A secure method uses RSA (asymmetric encryption algorithm) for data confidentiality. Ensures that the message is authentically from the sender and not an imposter.
</br>
**CP-2:** A faster method that uses AES (symmetric encryption algorithm) for data confidentiality. It negotiates a confidential shared session key between client and server after a connection is established. 

## Further Explanation
The figure below gives the basis of a possible authentication protocol. There’s one problem with the protocol, however: there is the possibility of a playback attack on the client. Further, the identity of the client is not verified by the server and can be easily spoofed by an imposter (ServerWithoutSecurity.java, ClientWithoutSecurity.java).

<img width="361" alt="performance" src="https://user-images.githubusercontent.com/23626462/38912976-f25601a6-430a-11e8-806f-b2226f388797.png">

The fixed version of the AP protocol is implemented on top of the file upload program.

![corrected](https://user-images.githubusercontent.com/23626462/38912967-ec0c6376-430a-11e8-9b2f-338998dd470d.png)

## How to run the program
Running on IntelliJ:
1.	Download and extract the program.
2.	Change the file paths of the privateServer.der file (contains private key) and server.crt file (certificate that contains public key) in CP1SecStoreServer.java and CP2SecStoreServer.java manually.
3.	There are two sets of client-server program. For each pair, run the server first before running the client. Before running the client (either CP1SecStoreClient.java or CP2SecStoreClient.java), under Run > Edit Configurations > Program arguments field, add in the list of files you wish to upload (space delineated) and click “Apply” then “OK”. For example:
rr.txt small.txt medium.txt large.txt large-image.jpg small-image.png
4.	The runtime for decryption will be output into an csv (excel) file for tabulation.

Points to note while running:
1.	If a socket error occurs, check to make sure no other servers are running. If error persists, try changing the port number (must be the same within a client-server pair) to another four-digit number. Alternatively, wait a while before running again.
2.	Always check that your edit configurations are set as specified above before running. You may need to run CP1 twice before the results get written into the csv file.

## Plots of achieved data throughput
The runtime for uploading files of various sizes (small, medium and large) for the two different CPs are computed and compared below.

CP-1

| File size                 | Time Taken (in ms) |
| :-----------------------: | :----------------: |
| rr.txt (1.93 MB)          | 20239              |
| small.txt (1.15 KB)       | 42                 |
| medium.txt (1.50 MB)      | 16477              |
| large.txt (1.50 MB)       | 30706              |
| large-image.jpg (9.70 MB) | 60273              |
| small-image.png (43.6 KB) | 50                 |

CP-2

| File size                 | Time Taken (in ms) |
| :-----------------------: | :----------------: |
| rr.txt (1.93 MB)          | 382                |
| small.txt (1.15 KB)       | 5                  |
| medium.txt (1.50 MB)      | 77                 |
| large.txt (1.50 MB)       | 257                |
| large-image.jpg (9.70 MB) | 624                |
| small-image.png (43.6 KB) | 5                  |

Comparison of performance:

<img width="502" alt="wrong" src="https://user-images.githubusercontent.com/23626462/38912968-ec851a32-430a-11e8-8e4f-0e032ef97484.png">
