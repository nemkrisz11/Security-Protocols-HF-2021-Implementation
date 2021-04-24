# BPHF-2021-Implementation

<h1> Basic information </h1>

The developed application is a secure file transfer application. It consists of a client program and a server program
that communicate with each other securely.

The client interacts with the user via a console interface.
The user can type in commands, which are sent to the server by the client.
The server executes the received commands, and provides feedback to the user about the result of the operation.
Using these commands, users can manage their own secure remote directory. The commands are related to file operations
such as uploading files to and downloading files from the server, creating folders, listing the content of a folder, etc.

The server is able to handle the folders and files of multiple users. Users have access only to their own folders and
files. The server is able to handle multiple parallel connections with different clients at a time.
The client is able to authenticate the server through a digital certificate. The users are authenticated by their
username and password. A session lasts until the user logs out, or until the server closes the session due to inactivity.

<h1> Changes compared to design document </h1>

- Due to implementation reasons, we prepend the network identifier of the sender to the message. This way, the server
  can know which address it received a message from. In a real TCP/IP environment, this would be unnecessary.

- We use secrets.token_bytes for generating random values, instead of os.urandom.
  Our chosen crypto library (cryptography 3.4.7) does not have its own pseudo-random generator function.

- In the first server -> client message of the session initialization protocol, which contains the server certificate,
  we sign the whole message using the long term private key of the server, instead of just signing the client random.

- The auth_success field in the server response message in the client authentication process can now take 3 different
  values instead of two. The possible values are 0x00 (authentication failed), 0x01 (success), and 0x02 (timeout).

- The argon2 library does not require us to store the salt for the passwords in a separate field, so we only store
  the argon2 hashes themselves.

<h1> How to use </h1>

The application supports Windows and Linux operating systems.
We have not tested the application on MAC-OS.

Before running the application, it is required to install and run a local mongo-db client for the server to work.
The application can be started either by:
 - Using the provided run.sh bash script.
 - Running the .py scripts in order:
   1. Run network.py
   2. Run run_server.py
   3. Run run_client.py

On first run, the server will set the server password to the provided password.
The test user's credentials are: "TestUser", "TesPass"

After logging in, the "help" command will list all the available commands and how to use them.