## Secure Chatting - Android Application

### Table of Content
1. [Requirements](#Req)
2. [How to Run](#run)
3. [Project description](#motivation)
4. [Prove of Concept](#poc)

## Requirements<a name="Req"></a>
There are 3 requirements that need to be satisfied before run this application:
1. Download mysql server or mariadb server in linux server.
2. Download python3.10 in linux server.
3. Download flask,flask_alchemy,pymsql,nmpuy,pandas,sklearn.

**The project applications should run in linux server.**

## How to Run<a name="run"></a>

To launch this application:
* Application setup
  * First Import Database Setting:
    ```
    mysql -u username -p projDB << IDS\exported.sql
    ```
  * Second, Run the Web app application:
    ```
    python3 IDS\app.py
    ```
  * Third in new terminal, Run the ML application
    ```
    python3 Project_F\main.py , Note you should change the network adapter in main.py to match the one in your machine.
    ```
  * Access http://127.0.0.1:5000 , register then login.


## Project description<a name="motivation"></a>

this project aimed to have a secure home network by implementing an IDS to detect any anomay traffic.

## Prove of Concept<a name="poc"></a>
* Found in Video2.mp4
