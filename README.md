# Introduction
DripLoaderNG is based on the project ["DripLoader"](https://github.com/xuanxuan0/DripLoader), which was created by **xuanxuan0**. This variant has the evasion features such as .node sideloading and indirect syscalls.

This project was developed for my blog ["DripLoader: A Case Study on Shellcode Execution & Evasion"](https://www.coreycburton.com/blog/driploader-case-study) 

# Capability
DripLoaderNG can only be used on Windows (10/11) hosts.

DripLoaderNG by default is currently configured for the Slack .node file "keymapping.node" 

In development testing, HTTPS payloads were the most evasive. 

# Usage
1. Generate a .bin file with the desired shellcode.
2. Run the script lzms_compress.py. (Keep this file within the project folder, shellcode.h will generate)
    - Usage: ``python3 lzms_compress.py path/to/.bin``
3. Rename the original *keymapping.node* file to *nativebindings.node*.
4. Drop the payload compiled from this project in the same folder.
5. Run the application. 

# Guidance
[Reference to configuring DripLoaderNG to other .node files](https://www.coreycburton.com/notes/driploaderng-node-guide)

# References
- [DripLoader by xuanxuan0](https://github.com/xuanxuan0/DripLoader)
- [An Introduction to Bypassing User Mode EDR Hooks - Marcus Hutchins](https://malwaretech.com/2023/12/an-introduction-to-bypassing-user-mode-edr-hooks.html)
- [Windows X86-64 System Call Table (XP/2003/Vista/7/8/10/11 and Server)](https://j00ru.vexillium.org/syscalls/nt/64/)

- [NODEin60seconds - Outflank](https://vimeo.com/856314414)










