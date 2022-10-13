https://simpleisbetterthancomplex.com/series/2017/09/04/a-complete-beginners-guide-to-django-part-1.html#introduction

#check version
python3 --version

sudo apt-get install 
python3-pip install virtualenv 
pip3 install virtualenv
virtualenv venv -p python3
source venv/bin/activate

![[Pasted image 20221013151936.png]]

## Starting a new project

`django-admin startproject myproject`
![[Pasted image 20221013152215.png]]

-   **manage.py**: a shortcut to use the **django-admin** command-line utility. It’s used to run management commands related to our project. We will use it to run the development server, run tests, create migrations and much more.
-   **__init__.py**: this empty file tells Python that this folder is a Python package.
-   **settings.py**: this file contains all the project’s configuration. We will refer to this file all the time!
-   **urls.py**: this file is responsible for mapping the routes and paths in our project. For example, if you want to show something in the URL `/about/`, you have to map it here first.
-   **wsgi.py**: this file is a simple gateway interface used for deployment. You don’t have to bother about it. Just let it be for now.

## Run the test server
`python3 manager.py runserver`

## Add boards

`django-admin startapp boards`

## Side note: Django concept App vs project

-   **app**: is a Web application that does something. An app usually is composed of a set of models (database tables), views, templates, tests.
-   **project**: is a collection of configurations and apps. One project can be composed of multiple apps, or a single app.`


Directory structure as of right now. 
```bash
total 20
4989607 drwxr-xr-x 3 kali kali 4096 Oct 13 14:44 myproject
4989606 -rwxr-xr-x 1 kali kali  665 Oct 13 14:44 manage.py
4989617 -rw-r--r-- 1 kali kali    0 Oct 13 14:44 db.sqlite3
4989619 drwxr-xr-x 3 kali kali 4096 Oct 13 14:49 boards
4989474 drwxr-xr-x 4 kali kali 4096 Oct 13 14:44 ..
4989605 drwxr-xr-x 4 kali kali 4096 Oct 13 14:49 .

./myproject:
total 28
4989612 -rw-r--r-- 1 kali kali  395 Oct 13 14:44 wsgi.py
4989611 -rw-r--r-- 1 kali kali  751 Oct 13 14:44 urls.py
4989608 -rw-r--r-- 1 kali kali 3230 Oct 13 14:44 settings.py
4989613 drwxr-xr-x 2 kali kali 4096 Oct 13 14:44 __pycache__
4989610 -rw-r--r-- 1 kali kali    0 Oct 13 14:44 __init__.py
4989609 -rw-r--r-- 1 kali kali  395 Oct 13 14:44 asgi.py
4989605 drwxr-xr-x 4 kali kali 4096 Oct 13 14:49 ..
4989607 drwxr-xr-x 3 kali kali 4096 Oct 13 14:44 .

./myproject/__pycache__:
total 24
4989618 -rw-r--r-- 1 kali kali  575 Oct 13 14:44 wsgi.cpython-310.pyc
4989616 -rw-r--r-- 1 kali kali  947 Oct 13 14:44 urls.cpython-310.pyc
4989615 -rw-r--r-- 1 kali kali 2300 Oct 13 14:44 settings.cpython-310.pyc
4989614 -rw-r--r-- 1 kali kali  168 Oct 13 14:44 __init__.cpython-310.pyc
4989607 drwxr-xr-x 3 kali kali 4096 Oct 13 14:44 ..
4989613 drwxr-xr-x 2 kali kali 4096 Oct 13 14:44 .

./boards:
total 32
4989622 -rw-r--r-- 1 kali kali   63 Oct 13 14:49 views.py
4989623 -rw-r--r-- 1 kali kali   60 Oct 13 14:49 tests.py
4989625 -rw-r--r-- 1 kali kali   57 Oct 13 14:49 models.py
4989626 drwxr-xr-x 2 kali kali 4096 Oct 13 14:49 migrations
4989624 -rw-r--r-- 1 kali kali    0 Oct 13 14:49 __init__.py
4989621 -rw-r--r-- 1 kali kali  144 Oct 13 14:49 apps.py
4989620 -rw-r--r-- 1 kali kali   63 Oct 13 14:49 admin.py
4989605 drwxr-xr-x 4 kali kali 4096 Oct 13 14:49 ..
4989619 drwxr-xr-x 3 kali kali 4096 Oct 13 14:49 .

./boards/migrations:
total 8
4989627 -rw-r--r-- 1 kali kali    0 Oct 13 14:49 __init__.py
4989619 drwxr-xr-x 3 kali kali 4096 Oct 13 14:49 ..
4989626 drwxr-xr-x 2 kali kali 4096 Oct 13 14:49 .
```
-   **migrations/**: here Django store some files to keep track of the changes you create in the **models.py** file, so to keep the database and the **models.py** synchronized.
-   **admin.py**: this is a configuration file for a built-in Django app called **Django Admin**.
-   **apps.py**: this is a configuration file of the app itself.
-   **models.py**: here is where we define the entities of our Web application. The models are translated automatically by Django into database tables.
-   **tests.py**: this file is used to write unit tests for the app.
-   **views.py**: this is the file where we handle the request/response cycle of our Web application.


On Setting.py under INSTALLED_APPS variable

![[Pasted image 20221013154450.png]]


Go to boards/views.py
![[Pasted image 20221013155707.png]]
```python
from django.shortcuts import render
from django.http import HttpResponse

def home(request):
    return HttpResponse('Hello, World')
```

 Update urls.py

![[Pasted image 20221013162218.png]]


Then ERRORS
![[Pasted image 20221013162503.png]]