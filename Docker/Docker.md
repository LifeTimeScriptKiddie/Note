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

```
 271  sudo apt install docker.io
  272  docker run hello-world
  273  sudo docker run hello-world
  274  docker run hello-world
  275  docker run --help
  276  docker run hello-world
  277  systemctl stop docker
  278  system start docker
  279  systemctl start docker
  280  docker run hello-world
  281  sudo docker run hello-world
  282  ls
  283  docker pull busybox
  284  sudo docker pull busybox
  285  sudo docker images
  286  docker run busybox
  287  sudo docker run busybox
  288  sudo docker run busybox echo "hello from busybox"
  289  docker ps
  290  sudo docker ps
  291  sudo docker ps -a
  292  sudo docker run -it busybox sh
    293  history
  294  sudo docker ps -a
  295  docker rm 2af97bbdbcfc c20e22547309 753edfb5d3e8
  296  sudo docker rm 2af97bbdbcfc c20e22547309 753edfb5d3e8
  297  sudo docker container prune
  298  docker rmi
  

```

# Terminology

### Terminology

In the last section, we used a lot of Docker-specific jargon which might be confusing to some. So before we go further, let me clarify some terminology that is used frequently in the Docker ecosystem.

-   _Images_ - The blueprints of our application which form the basis of containers. In the demo above, we used the `docker pull` command to download the **busybox** image.
-   _Containers_ - Created from Docker images and run the actual application. We create a container using `docker run` which we did using the busybox image that we downloaded. A list of running containers can be seen using the `docker ps` command.
-   _Docker Daemon_ - The background service running on the host that manages building, running and distributing Docker containers. The daemon is the process that runs in the operating system which clients talk to.
-   _Docker Client_ - The command line tool that allows the user to interact with the daemon. More generally, there can be other forms of clients too - such as [Kitematic](https://kitematic.com/) which provide a GUI to the users.
-   _Docker Hub_ - A [registry](https://hub.docker.com/explore/) of Docker images. You can think of the registry as a directory of all available Docker images. If required, one can host their own Docker registries and can use them for pulling images.

