# Understand Docker

Resource: https://docker-curriculum.com/


What is Docker: Docker is a tool that allows developers, sys-admins etc. to easily deploy their applications in a sandbox (called _containers_) to run on the host operating system i.e. Linux. The key benefit of Docker is that it allows users to **package an application with all of its dependencies into a standardized unit** for software development. Unlike virtual machines, containers do not have high overhead and hence enable more efficient usage of the underlying system and resources.

VM vs Docker
VM: Full process Isolation --> Expensive (Computational Overhead)

Docker Containers : Offers a logical packaing mechanism in which applications can be abstracted from the environment in which they actually run. 
This decoupling allows container-based applications to be deployed easily and consistently, regardless of whether the target environment is a private data center, the public cloud, or even a developer’s personal laptop. This gives developers the ability to create predictable environments that are isolated from the rest of the applications and can be run anywhere.

![[Pasted image 20221012165552.png]]



# Installation

sudo apt install docker
docker run hello-world   #requires root priviliege dont' know why. 
![[Pasted image 20221012170617.png]]

