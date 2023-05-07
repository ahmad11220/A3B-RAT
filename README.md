# A3B Red Teaming RAT Tool

## The  A3B RAT tool is a remote access Trojan (RAT) designed for red teaming and penetration testing purposes. The tool provides a suite of features for remote control and monitoring of a target system, including keylogging, password stealing, screenshot capture, PowerShell execution, and file transfer.
## The tool is composed of two parts: A Client and A Server, communicate using Sockets for several reasons : <br>
### 1- Flexibility: Sockets provide a lot of flexibility in terms of the type of data that can be sent and received over the network. By using sockets, malware authors can design their own custom protocols that are tailored for their specific needs.<br>
### 2- Stealth: Using a custom protocol over sockets can make it harder for network security tools to detect and block the communication between the malware and its command-and-control (C&C) server. If the malware used a standard protocol like TCP or HTTP, it would be easier for network security tools to detect and block the communication.<br>
### 3- Encryption: Sockets can be used to implement encryption and other security measures to protect the communication between the malware and its C&C server. This can make it harder for security researchers to analyze the communication and extract useful information.<br>
### 4- Resource usage: TCP and HTTP are higher-level protocols that require more resources than sockets. By using sockets, malware authors can reduce the resource usage of their malware and make it harder to detect and analyze.<br>

## Keylogger using Hooking<br>
### The keylogger  uses hooking to intercept keystrokes from the target system's keyboard. The keylogger can capture keystrokes from any application running on the system and send the data back to the attacker's server.

## Password Stealer from Chrome Browser using SQLite and AES Decryption<br>

### 1- Get master key , reads the encrypted master key from the local state file of the Chrome browser. The master key is used by Chrome to encrypt and decrypt sensitive data like passwords. The function decodes the encrypted master key using Base64 and then decrypts it. This allows the function to obtain the key needed to decrypt the encrypted passwords stored in the browser's database.<br>

### 2- Retrieve login credentials:  opens the database SQLlite file of a specified browser (e.g., Google Chrome), prepares a SELECT statement to retrieve login credentials from the logins table, and iterates over the rows of the table. For each row, the function extracts the website, login URL, user name, and encrypted password blob. The password blob is encrypted using the master key obtained in step 1.<br>

### 3- Decrypt password blob:  decrypts the password blob using the Advanced Encryption Standard (AES) in Galois/Counter Mode (GCM) using the master key obtained in step 1. This allows the function to obtain the plaintext password.<br>

### 4- Write decrypted data into log file and send it to attacker server: The function writes the extracted login credentials (website, login URL, user name, and plaintext password) to a log file and sends it to an attacker-controlled server. This allows the attacker to obtain the stolen credentials.<br>

## Screen captures of the target system's desktop <br>
### by  taking a screenshot of the primary monitor and saves it to a file using the Windows API. It first retrieves the dimensions of the primary monitor, creates a device context for the entire screen, creates a bitmap for the screenshot, and then copies the screen contents to the bitmap. Finally, it saves the bitmap to a file using the GDI+ library.and sends it back to the attacker's server. This  can be used to monitor the target system's activity and gather valuable information.<br>
## PowerShell Execution<br>
### The PowerShell execution function allows the attacker to run PowerShell commands on the target system. This function can be used to perform various actions on the target system, such as downloading and executing additional malware, or gathering system information.<br>
## Get File from Victim<br>

### The Get File function allows the attacker to download files from the target system. This function can be used to gather sensitive information from the target system, such as documents, passwords, or other data.<br>

## Send File to Victim<br>

### The Send File function allows the attacker to upload files to the target system. This function can be used to deploy additional malware or tools to the target system, or to plant fake documents or data.

## Evasion Techniques :<br>
### To avoid detection by antivirus software and other security measures. The  A3B RAT  uses several techniques to make it more difficult for security software to detect and block its activities.<br>

### 1-RATA3B uses is a multi-stage infection process.<br>
#### The malware consists of two stages, where the first stage only contains code to retrieve the second stage from the server at runtime.<br>
#### The second stage of the malware is the fully functional malware in the form of shellcode. By splitting the malware into two stages, the attacker can make it harder for security software to detect the presence of the malware on the victim's machine.<br>
#### The first stage of the malware is designed to be lightweight and stealthy, with minimal functionality. Its main purpose is to retrieve the second stage of the malware from the server and inject it into memory. This makes it harder for security software to detect the presence of the malware, since the majority of the malicious code is not present on the victim's machine until runtime.<br>
#### The second stage of the malware, which is injected into memory at runtime, is the fully functional malware that contains all of the keylogging, password stealing, screenshot, PowerShell execution, and file transfer functionality. By using a multi-stage infection process, the attacker can make it more difficult for security software to detect and remove the malware from the victim's machine.<br>
#### Overall By splitting the malware into multiple stages, the attacker can make it harder for security software to detect the presence of the malware on the victim's machine and increase the overall stealthiness of the malware.<br>
 
### 2- To further enhance its evasion capabilities, the shellcode is encrypted using a custom encryption algorithm. This encryption helps to prevent antivirus software from detecting the RAT  based on its signature or behavior. The encryption key for the shellcode is generated dynamically at runtime, making it more difficult for security software to detect.<br>

### 3- In addition to encryption, the  A3B RAT  also uses runtime Process injection technique to inject the shellcode into memory at runtime. This technique allows the RAT tool to operate without leaving any traces on the target system's hard drive, making it more difficult for antivirus software to detect and block it.<br>

### 4- The WinAPI function calls used by the TEAM A3B RAT  are String obfuscated to avoid detection by signature-based antivirus engines. String Obfuscation is the process of intentionally making senstive functions names  more difficult to read and understand, without changing its functionality.<br>
### 5- TEAM A3B RAT doesn't use WINAPI functions directly but it use Code Obfuscation which creates function pointers and uses GetProcAddress and GetModuleHandle to dynamically retrieve the address of the function at runtime, which avoids importing function names into the Import Address Table (IAT). This makes it harder for security software to detect the presence of the malware, since the functions that it uses do not appear in the IAT. The use of custom Windows API calls is a common evasion technique used by malware authors to avoid detection by security software and make it harder for security researchers to reverse-engineer the malware.<br>
### Overall, the TEAM A3B RAT tool uses a combination of encryption, runtime injection, and obfuscation techniques to make it more difficult for security software to detect and block its activities. These techniques help to ensure that the RAT tool remains undetected and effective during red teaming and penetration testing engagements.<br>

## Presistence Technique:<br>
### The persistence technique used is adding a new value to the HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run registry key. This registry key contains a list of programs that are automatically launched when the current user logs into Windows.<br>

### By adding a new value to this key with the /D option pointing to a malware executable file, the malware will be executed automatically every time the current user logs into Windows, without the user's knowledge or consent. This technique is commonly used by malware authors to ensure that their programs are executed every time the system starts up, even if the malware file itself is removed or the system is restarted.<br>


## Disclaimer <br>

### The TEAM A3B RAT tool is intended for ethical use only, such as red teaming and penetration testing engagements. The use of this tool for any illegal or malicious purposes is strictly prohibited. The author of this tool is not responsible for any damages or legal issues that may arise from the use of this tool.<br>
