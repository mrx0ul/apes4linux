# apes4linux

## Introduction
Automatic privilege escalation is done by enumerating the system with scripts produced by security experts. However, these scripts are considered daunting and hard to use for students and non-security-based system administrators to use. This project focuses on the development of a user-friendly automated privilege escalation enumeration and execution tool for Linux. The project is aimed to increase the interactiveness, readability, and cleanliness of output from the enumeration process, so that cyber security novices can learn the art of privilege escalation in a better way.

## Objectives
1. To study Linux privilege escalation methods and how to identify and enumerate the privilege escalation vectors automatically with a command line tool.
2. To develop a command line tool which can perform automatic and complete privilege escalation enumeration and execution in a Linux system.
3. To encourage the ethical hacking learning process by providing a privilege escalation enumeration script which is interactive and user-friendly. This means that the output of the script must be summarized and easy to read, as well as being well-sorted and eye catching.
4. To provide general IT professionals with low ethical hacking skills a simple way to perform checks on their systems for potential vulnerabilities. 
5. To test the capabilities and thoroughness of the command line tool in enumerating and exploiting privilege escalation vectors.

## Deliverables
1. Allow users to access and run the tool in a simple manner.
2. Allow users to specify options to customize and fine-tune the enumeration process and result display.
3. Display the enumeration result in a summarized and easy to read form.
4. Automatically attempt to execute privilege escalation in vulnerable systems.
5. Automatically direct the user to a certain website or resource page if the tool is unable to directly obtain privileged user access.

## Implementation
apes4linux is an automatic privilege escalation assistance tool which is developed in Python. It is developed as a command line utility which can be easily obtained and executed with a simple command in the local machine. To further customize their search, the user is also able to specify arguments to control the enumeration and execution. For maximum user experience, the enumeration output is processed and displayed in the terminal with attractive colour codes and organized formatting.
