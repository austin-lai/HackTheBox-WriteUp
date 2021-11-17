
# HackTheBox(HTB) - Easy Phish - WriteUp

> Austin Lai | November 17nd, 2021

---

<!-- Description -->

![EasyPhish](img/EasyPhish.png)

Difficulty: Easy

The room is completed on November 02nd, 2021

```text
Customers of secure-startup.com have been receiving some very convincing phishing emails, can you figure out why?

- Enumeration
- DNS
- Python - checkdmarc
```

<!-- /Description -->

## Table of Contents

<!-- TOC -->

- [HackTheBox(HTB) - Easy Phish - WriteUp](#hacktheboxhtb---easy-phish---writeup)
    - [Table of Contents](#table-of-contents)
    - [Let's Begin Here !!!](#lets-begin-here-)
        - [To get the flag](#to-get-the-flag)

<!-- /TOC -->

---

## Let's Begin Here !!!

DMARC can stop spoofed spam and phishing from reaching you and your customers, protecting your information security and your brand.

As the task mentioned, secure-startup.com have been receiving some very convincing phishing emails might due to DMARC incorrect configuration.

[`checkdmarc`](https://github.com/domainaware/checkdmarc) is a Python 3 module and command line parser for SPF and DMARC DNS records

You can install using:

```bash
sudo -H pip3 install -U git+https://github.com/domainaware/checkdmarc.git
```

### To get the flag

```
checkdmarc secure-startup.com
```

<br />

---

> Do let me know any command or step can be improve or you have any question you can contact me via THM message or write down comment below or via FB

