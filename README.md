# Hello and welcome to the Wifi crack workshop

In this workshop you are mostly self responsible for your learnings. The workshop you provide you with a structure to study and understand the 4-Way-Handshake in WPA2. Yet, you are responsible for diving into the topic and gather the knowledge. After you learned about the handshake, you can proceed to apply your new knowledge in practice, and conquer a Wifis password. Enjoy!

## Theory part
The main target of the hack is the authentication process of a client with an access point. This process is described in IEEE_802.11i-2004. At the heart of the authorization process lies the 4-Way-Handshake. Your first task is to understand this process.

Have fun researching and reading. To get you startet, here are two usefull links you can start with:
<https://en.wikipedia.org/wiki/IEEE_802.11i-2004>
<https://medium.com/wifi-testing/four-way-handshake-32356fbec1b5> (Sometimes medium puts an article behind a paywall, but that should be easier cracked than Wifi)
   
## Knowledge check
While getting familliar with the topic, you should answer following questions. It's up to you in how much detail you do this:)

- What is the purpose of the 4-Way-Handshake?
- What is an EAPOL message?
- What are the components that are exchanged in the 4 messages?
- What are nonces and why are they needed?
- What is the PSK, PMK, PTK, and how do you get from PSK to PTK?
- Why do we need a PTK and don't use the actuall wifi password instead?
- What is the purpose of the MIC and how is it composed?
- Can you already to see how to (mis)use the MIC to do some brute forcing..?


# Let's hack 
Enough of all the reading and question, now lets start with the fun part. 

## Requirements
You need to have python 3 installed on your system.

Open a terminal at this route folder.

It is advisable but not mandatory to work with a python virtual environment.
-> <https://www.freecodecamp.org/news/how-to-setup-virtual-environments-in-python/>

Install requirements via: 
```bash
pip install -r ./requirements.txt
```

Now your are set up. The file `example_solution.py` contains an example of how the code could look like. STOP! Don't take a look yet. This should serve as a last resort if you are not able to do it yourself. In the folder `excercises` you will find 3 files. Quite selfexplanatory. Choose your level and have fun! To run your code:

```bash
# make sure you use the correct filename depending on your level
python3 excercises/1_easy.py
```

To run the example code you need to run the follwing command:

```bash 
python3 example_solution.py AP-NAME assets/handshake.cap assets/password_list.txt
```


