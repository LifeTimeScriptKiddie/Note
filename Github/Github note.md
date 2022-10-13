
# Goal

Learn how to use github as a note storage. 
Learn how to upload and modify documents from github. 


# env
Kali 2022.2
Obsidian 


# Note 1. Understand Github
Goal:  Create a repository via web interface
Follow the below resource page. 
Resource : https://docs.github.com/en/get-started/quickstart/hello-world

-   Created an open source repository
-   Started and managed a new branch
-   Changed a file and committed those changes to GitHub
-   Opened and merged a pull request



# Note 2. Use git from command line. 

git from command line
```
#Check git version
git --version

#Setting username and email
git config --global user.name "your_username"
git config --global user.email "your_email_address@example.com"

#verify config 
git config --global --list

```

## Clone a respository
ssh vs HTTPS

SSH syntax --> requires authentication
git clone git@gitlab.com:gitlab-tests/sample-project.git

HTTPS syntax --> Authentication may not be needed if respository is public.
git clone https://gitlab.com/gitlab-tests/sample-project.git

If repository is private, recommend using Personal Access Token,
git clone https://<username>:<token>@gitlab.example.com/tanuki/awesome_project.git



## Note 2.1  Create Personal Access Tokens from web


Create Personal Access Token
Go to https://github.com/settings/tokens


From your GitHub account, go to **Settings** => **Developer Settings** => **Personal Access Token** => **Generate New Token** (Give your password) => **Fillup the form** => click **Generate token** => **Copy the generated Token**, it will be something like `ghp_sFhFsSHhTzMDreGRLjmks4Tzuzgthdvfsrta`

Resource 1 : https://stackoverflow.com/questions/68775869/message-support-for-password-authentication-was-removed-please-use-a-personal
Resource 2:  https://docs.gitlab.com/ee/gitlab-basics/start-using-git.html



# Note 3. Pull, Stage, Push

```
#initialize
git init 

git remote add origin git@gitlab.com:<username>/projectpath.git
git remote -v
git pull <remote> <name-of-branch>
git pull origin main


git add <file or folder>
git commit -m <comments>
git checkout -b <name-of-branch>

#Switch to a branch
git checkout <name-of-branch>
git checkout main

# view differences
git diff

#view status
git status
git add <file or folder>
git status
git commit -m "Comment"

#send changes to gitlab
git push <remote> <name of branch>
git push origin main


# Delete all Changes in the branch
git checkout .

Unstage all changes that have been added to the staging area
git reset


#Merge a Branch with default branch

git checkout <default-branch>
git merge <feature-branch>





git remote set-url origin https://<githubtoken>@github.com/<username>/<repositoryname>.git


git push

git pull -v

git status

```
