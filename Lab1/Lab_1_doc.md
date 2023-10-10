# 网络空间安全导论实验

## 实验一 配置Linux环境、熟悉Linux
姜俊彦 2022K8009970011 2023年9月18日

### 摘要：

本次实验目的搭建Linux环境、熟悉Linux基本常识和操作，为以后实验打下基础。本次实验主要采用调查研究与实践相结合的方式，通过网络搜索、与ChatGPT沟通等方式解决在实验中遇到的问题，找到解决问题的方法，并且在Linux环境中实现要求的功能。

### 实验环境：

本次实验笔者使用的Linux环境为在VMware Workstation 17 Pro平台下搭建的Ubuntu22.04的64位版本。

详细配置见下表：

| 项目         | 配置 |
| ------------ | ---- |
| 内存         | 8GB  |
| 处理器       | 8    |
| 硬盘（SCSI） | 50GB |
| 网络适配器   | NAT  |

### 实验步骤、现象与结果分析：

**Linux基本操作：**

1. **创建lab1目录**：

   代码如下：

   ```
   sudo mkdir lab1
   ```

   `mkdir`是创建目录的指令，语法为`mkdir`+`[option]`+`[directory_name]`

   `sudo`“是以系统管理者的身份执行指令，也就是说，经由`sudo`所执行的指令就如同**root**亲自执行，作前缀，常常在根目录下操作文件、执行指令时使用。

   > 由于笔者的lab1目录位于根目录下的子目录，故下文指令中可能会存在`sudo`滥用。

2. **进入lab1目录：：**

   代码如下：

   ```
   cd lab1
   ```

   `cd`是用于改变当前工作目录的命令，可切换到指定的路径。语法为`cd `+`[path]`

   `cd`指令还有几个常见用法如下：

   ```
   # 切换到根目录
   cd /
   # 切换到用户主目录
   cd ~
   # 切换到上一级目录
   cd ..
   # 切换到上上级目录
   cd ../../
   # 切换到上次访问的目录
   cd -
   ```

3. **创建一个C源码，编译并运行一个hello，world:**

   创建文件使用的代码：

   ```
   sudo gedit hello.c
   ```

   `gedit`是用于打开gedit编辑器，在当前目录下创建一个空文件。语法为`gedit`+`[filename]`

   同时为了编译运行C源码，需要安装`gcc`。

   ```
   sudo apt install gcc
   ```

   `apt`为在 Debian 和 Ubuntu 中的 Shell 前端软件包管理器，想要执行`apt`指令必须root（超级管理员）权限。其使用语法为`apt`+`[options]`+`[command]`+`[package_name]`

   编译：

   ```
   sudo gcc hello.c -o hello
   ```

   运行：

   ```
   ./hello
   ```

   输出结果：

   ![Lab1-1](https://github.com/jiuhao47/UCAS-ICS-Share/blob/main/Lab1/Pic/Lab1-1.png?raw=true)

   使用的C源码：

   ```C
   # include <stdio.h>
   int main()
   {
   	printf("hello,world!\n");
   	return 0;
   }
   ```

4. **用Python算第100个斐波那契数并存储到文件中：**

   操作步骤：

   ```
   # 安装python3包
   sudo apt install python3
   # 创建python脚本文件
   sudo gedit solve.py
   # 运行程序并将输出重定向
   python solve.py > answer.txt
   ```

   `>`是以附加的方式，将命令的正确输出输出到指定的文件或者设备当中。

   输出结果：

   ```
   # answer.txt
   354224848179261915075
   ```

   使用的Python源码：

   ```python
   #!/usr/bin/env python3
   
   a1 = 1
   a2 = 1
   
   def solve(a1, a2):
       a3 = a1 + a2
       return a3
   
   for i in range(98):
       a3 = a2
       a2 = solve(a1, a2)
       a1 = a3
   print(a2)
   ```

5. **拷贝/etc/os-release文件到当前目录：**

   代码如下：

   ```
   sudo cp /etc/os-release ./
   ```

   `cp`是主要用于复制文件或目录的命令，语法为`cp `+`[options]`+`[source]`+`[dest]`

   输出结果：

   ![Lab1-2](https://github.com/jiuhao47/UCAS-ICS-Share/blob/main/Lab1/Pic/Lab1-2.png?raw=true)

6. **将/etc/fstab的base64编码写入文件：**

   代码如下：

   ```
   sudo base64 /etc/fstab > fstab_base64.txt
   ```

   Base64是一种二进制到文本的编码方式，`base64`是将文件以base64编码的形式输出。

   输出结果：

   ```
   # fstab_base64.txt
   # 省略
   dHlwZT4gIDxvcHRpb25zPiAgICAgICA8ZHVtcD4gIDxwYXNzPgojIC8gd2FzIG9uIC9kZXYvc2Rh
   MyBkdXJpbmcgaW5zdGFsbGF0aW9uClVVSUQ9ZTBmZmQyNDUtOTBhYS00Y2NkLTk1NmMtMjhlYmJh
   ZDdiNzdhIC8gICAgICAgICAgICAgICBleHQ0ICAgIGVycm9ycz1yZW1vdW50LXJvIDAgICAgICAg
   MQojIC9ib290L2VmaSB3YXMgb24gL2Rldi9zZGEyIGR1cmluZyBpbnN0YWxsYXRpb24KVVVJRD1G
   # 省略
   ```

7. **查看/proc/self/maps并将结果保存到文件中：**

   代码如下：

   ```
   sudo cat /proc/self/maps | tee maps.txt
   ```

   `cat`是用于连接文件并打印到标准输出设备上的指令。

   `tee`是用于读取标准输入的数据，并将其内容输出成文件。

   输出结果：

   ```
   # maps.txt
   55604356e000-556043570000 r--p 00000000 08:03 1835156                    /usr/bin/cat
   556043570000-556043574000 r-xp 00002000 08:03 1835156                    /usr/bin/cat
   
   # 省略
   
   7ffeb55f6000-7ffeb55f8000 r-xp 00000000 00:00 0                          [vdso]
   ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0                  [vsyscall]
   ```

8. **将/bin/sh的十六进制数据存储到文件中：**

   代码如下：

   ```
   sudo hexdump -C /bin/sh > sh_hexdump.txt
   ```

   `hexdump`是一个Linux下的一个二进制文件查看工具，他可以将二进制文件转换为ASCII、八进制、十进制、十六进制格式进行查看

   输出结果

   ```
   # sh_hexdump.txt
   # 省略
   000000c0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
   000000d0  48 34 00 00 00 00 00 00  48 34 00 00 00 00 00 00  |H4......H4......|
   000000e0  00 10 00 00 00 00 00 00  01 00 00 00 05 00 00 00  |................|
   000000f0  00 40 00 00 00 00 00 00  00 40 00 00 00 00 00 00  |.@.......@......|
   # 省略
   ```

9. **返回上一级目录并打包lab1目录：**

   代码如下：

   ```
   tar -czvf lab1-jiangjunyan.tar.gz lab1/
   ```

   `tar`是用来建立、还原备份文件的工具程序，它可以加入、解开备份文件内的文件。

   输出结果：

   ![Lab1-3](https://github.com/jiuhao47/UCAS-ICS-Share/blob/main/Lab1/Pic/Lab1-3.png?raw=true)

**Linux问题探究：**

1. **问题一：Ubuntu下的文件权限是什么样的？如何对文件权限进行操作？**

   研究过程：通过查阅资料，我在[《Linux文件权限详解》](https://blog.csdn.net/lv8549510/article/details/85406215)这篇博客中找到了对应的解答。

   >Linux系统中不仅是对用户与组根据UID,GID进行了管理，还对Linux系统中的文件，按照用户与组进行分类，针对不同的群体进行了权限管理，用他来确定谁能通过何种方式对文件和目录进行访问和操作。

   >**文件的权限针对三类对象进行定义：**
   >
   >| 对象                          | 缩写 |
   >| ----------------------------- | ---- |
   >| owner                         | u    |
   >| group                         | g    |
   >| other                         | o    |
   >| all（等同于同时声明以上三者） | a    |
   >
   >**每个文件针对每类访问者定义了三种主要权限：**
   >
   >| 权限    | 缩写 | 数字表示 |
   >| ------- | ---- | -------- |
   >| Read    | r    | 4        |
   >| Write   | w    | 2        |
   >| Execute | x    | 1        |
   >
   >对于root用户，其不受文件的读写限制，执行权受限制
   >
   >**对于文件和目录来说，r，w，x有着不同的作用和含义：**
   >
   >| 权限 | 文件                                       | 目录                                                         |
   >| ---- | ------------------------------------------ | ------------------------------------------------------------ |
   >| r    | 读取文件内容                               | 查看目录下的文件列表                                         |
   >| w    | 修改文件内容                               | 删除和创建目录下的文件                                       |
   >| x    | 执行权限对除二进制程序以外的文件没什么意义 | 可以cd进入目录，能查看目录中文件的详细属性，能访问目录下的文件内容（基础权限） |
   >
   >**用户获取文件权限的顺序：**
   >
>先看是否为所有者，如果是，则后面权限不看，在看是否为所属组，如果是则后面权限不看。

从该篇文章中我还了解到了修改文件访问权限的方法，并进行实际操作。

**`chmod`修改权限**

代码如下：

```
   # 创建一个名为hello.c的C程序，前文已展示源码。
   gedit hello.c
   # 查看当前文件详细权限
   ls -al
```

终端输出：

![Lab1-4](https://github.com/jiuhao47/UCAS-ICS-Share/blob/main/Lab1/Pic/Lab1-4.png?raw=true)

可知owner与group用户拥有**hello.c**的读取与写入权限，other用户只具有读取权限，且三者都不具备执行权限。如果强行执行该文件则会报错。

![Lab1-5](https://github.com/jiuhao47/UCAS-ICS-Share/blob/main/Lab1/Pic/Lab1-5.png?raw=true)

```
   # 更改hello.c的权限为-rwx-rwx-rwx
   # 有两种做法
   # 方法一
   sudo chmod -c a+rwx hello.c
   # 方法二
   sudo chmod -c 777 hello.c
```

   输出结果：

![Lab1-6](https://github.com/jiuhao47/UCAS-ICS-Share/blob/main/Lab1/Pic/Lab1-6.png?raw=true)

![Lab1-7](https://github.com/jiuhao47/UCAS-ICS-Share/blob/main/Lab1/Pic/Lab1-7.png?raw=true)
2. **问题二：什么是Ubuntu中的用户组？什么是用户权限？如何进行用户组与用户权限管理？**

   研究过程：通过查阅资料，我在[Ubuntu/Linux用户管理与权限管理](https://blog.csdn.net/yl19870518/article/details/100776136)这篇博客中找到了对应的解答。

   > **用户与用户组：**
   > 根用户——root用户
   > 在Ubuntu下，终端提示符里`$`表示普通管理员，`#`表示系统管理员（也就是root用户），root用户默认是没有密码的，启用root用户，就需要给root用户设置密码，命令如下：
   >
   > ```
   > sudo passwd root
   > ```
   >
   >
   > 系统会先验证当前普通管理员的密码，然后要求输入两次root用户的密码，之后就可以进入root用户了，关于用户和权限的管理，最好是在root用户下操作。进入root用户下的命令如下：
   >
   > ```
   > su root
   > ```
   >
   > 输入密码后就进入root用户了。

   实际操作：

   ```
   sudo passwd root
   sudo root
   ```

   输出结果：

   ![Lab1-8](https://github.com/jiuhao47/UCAS-ICS-Share/blob/main/Lab1/Pic/Lab1-8.png?raw=true)

   > **用户组创建与删除**
   > 很多时候在创建新用户的时候，希望把一些用户归为一个组，以便后续的管理，在Ubuntu中，一个用户是可以同时在几个组里面的，会指定一个主要组。
   >
   > 1.查看用户所在组情况
   > 可以通过id命令查看当前用户或通过id user1来查看用户user1的用户组情况，例如：
   >
   > ```
   > id user1
   > ```

   实际操作：

   ```
   id jiuhao
   ```

   输出结果：

   ![Lab1-9](https://github.com/jiuhao47/UCAS-ICS-Share/blob/main/Lab1/Pic/Lab1-9.png?raw=true)

   > 2.创建用户组
   > 创建用户组的命令是groupadd，普通管理员需要加sudo来执行，root用户不用。
   >
   > ```
   > # 语法
   > sudo groupadd [options] GroupName
   > ```
   >
   > 3.删除用户组
   > 删除用户组的命令语法如下：
   >
   > ```
   > # 语法
   > sudo groupdel [GroupName]
   > ```
   >
   > 4.修改用户组信息
   > 修改用户组的命令语法如下：
   >
   > ```
   > 语法
   > sudo groupmod [options] [GroupNameOld]
   > ```
   >
   > 5.用户组管理
   > 用户组管理的命令是`gpasswd`，通常用来给用户组添加或移除用户。
   >
   > ```
   > # 语法
   > gpasswd [option] [GroupName]
   > ```

   通过`groupmod` `--help`发现其中常用的有如下两个`[option]`：

   ```
   # 为GroupNameOld用户组指定新的组id
   -g NewID
   # 为GroupNameOld用户组指定新的组名称
   -n NewGroupName
   ```

   且通过`gpasswd` `--help`发现其中常用的有如下两个`[option]`：

   ```
   # 添加用户到该用户组
   -a
   # 从用户组移除用户
   -d
   ```

   实际操作：

   ```
   sudo groupdel testgroup
   sudo groupadd testgroup
   sudo gpasswd -a jiuhao testgroup
   id jiuhao
   sudo gpasswd -d jiuhao testgroup
   id jiuhao
   sudo gpasswd -a jiuhao testgroup
   sudo groupmod -g 114514 testgroup
   sudo groupmod -n changedname testgroup
   id jiuhao
   sudo groupdel changedname
   ```

   输出结果：

   ![Lab1-10](https://github.com/jiuhao47/UCAS-ICS-Share/blob/main/Lab1/Pic/Lab1-10.png?raw=true)

**Linux综合应用**

~（虽然任务要求选择一个完成但是基本把想做的好玩的都做了，剩下的要么是时间原因没做，要么是很纯粹的不会做没做出来。）~

1. **编译Linux内核：**

   > 任务要求：你需要下载 Linux 内核源代码，配置编译环境，并成功编译和安装自定义的 Linux 内核。
   >
   > 实验报告推荐内容：描述你下载、配置和编译 Linux 内核的过程，包括遇到的问题和解决方案。同时展示你成功编译和安装自定义内核的成果。
   >
   

【时间原因没做】：据网络搜索与同学告知，我知悉此任务耗时巨大，考虑要做其他实验就暂时搁置。

2. **安装Docker并运行Hello World：**

   > 任务要求：你需要在 Linux 系统上安装 Docker，并成功运行一个 Hello World 容器
   >
   > 实验报告推荐内容：描述你安装 Docker 的过程，包括配置和启动 Docker 服务。同时展示你成功运行的 Hello World 容器，并解释你对 Docker 的理解。
   >
   

【完成】：本实验参考了[Ubuntu安装 Docker](https://blog.csdn.net/qq_44732146/article/details/121207737)这篇博客

操作步骤：

```
   # 卸载旧版本
   sudo apt remove docker docker-engine docker.io
   # 安装使用HTTPS传输的软件包及CA证书 
   sudo apt install apt-transport-https
   sudo apt install ca-certificates
   sudo apt install curl
   sudo apt install gnupg
   sudo apt install lsb-release
   # 确认所下载软件包的合法性，添加软件源的GPG密钥
   curl -fsSL https://mirrors.aliyun.com/docker-ce/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
   # 向sources.list中添加Docker软件源
   echo \
     "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://mirrors.aliyun.com/docker-ce/linux/ubuntu \
     $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
   # 更新apt软件包缓存
   sudo apt update
   # 安装docker-ce
   sudo apt install docker-ce docker-ce-cli containerd.o
   # 启动Docker
   sudo systemctl enable docker
   sudo systemctl start docker
   # 建立docker用户组
   sudo groupadd docker
   # 将当前用户加入docker组
   sudo gpasswd -a jiuhao docker
   # 退出当前终端并重新登陆
   # 拉取hello-world镜像
   sudo docker pull hello-world
   # 运行hello-world镜像
   sudo docker run hello-world
```

输出结果：

![Lab1-11](https://github.com/jiuhao47/UCAS-ICS-Share/blob/main/Lab1/Pic/Lab1-11.png?raw=true)

   对Docker的理解：

   ​	Docker是一个可以方便快捷的创建容器的开源项目。容器是一种沙盒技术，主要目的在于将应用运行在制定环境当中，并与外界隔离。Docker可以将程序以及程序的所有依赖都打包到一个容器（container）中，从而使得你的程序在任何其他环境下都会有一致的表现。容器技术具有轻量化的特点。相比于庞大笨重的操作系统，容器技术占用资源更少，使得我们可以在同样规格的硬件上部署更多的容器且提高了启动速度。

   容器是一种通用技术。Docker只是其中一种实现。

3. **安装 libc 的符号表与源码，安装 GDB 插件，调试程序并查看 libc 源码：**

   > 任务要求：你需要安装 libc 的符号表和源码，安装 GDB 插件，并使用 GDB 调试一个程序（如 bash），从而能够查看 libc 源码。
   >
   > 实验报告推荐内容：描述你安装 libc 符号表和源码的过程，以及安装和使用 GDB 插件的步骤。同时展示你成功调试程序并查看 libc 源码的截图，并解释你对调试器界面的理解。
   >
   
   【未完全实现】：笔者通过网络查阅资料，成功实现了安装libc的符号表，安装了GDB插件，并且可以使用GDB调试一个程序，但是在安装和查看libc源码上出了问题。
   

操作步骤：

```
   # 安装带有调试符号的libc
sudo apt install libc-dbg
   # 安装GDB插件
   sudo apt install gdb
   # 使用GDB调试一个程序
   gcc hello.c -g -o hello
   gdb hello
```

   输出结果

![Lab1-12](https://github.com/jiuhao47/UCAS-ICS-Share/blob/main/Lab1/Pic/Lab1-12.png?raw=true)

对调试界面的理解：

​	GDB为程序设计者提供了一个可以动态调试程序、检查错误、分析程序运行状况、剖析系统内核的平台。程序设计者可以在这里运行程序，设置断点，检查变量值，查看源码逻辑等。

（因为没有涉及到源码查看所以理解较浅）

4. **在 Linux 下运行一个 HTTP 服务器，并创建静态博客：**

   > 任务要求：你需要在 Linux 系统上搭建并运行一个 HTTP 服务器，并创建一个文章页面。
   >
   > 实验报告推荐内容：描述你搭建和配置 HTTP 服务器的过程，包括选择的服务器软件和相关设置。同时展示你成功运行的 HTTP 服务器，并解释你对 Web 服务器的理解.
   >
   

【完成】：本实验参考了[Ubuntu搭建简单http服务器](https://blog.csdn.net/qq_30624591/article/details/118573780)、[Ubuntu查看本机IP地址的两种方法](https://blog.csdn.net/qq_34626094/article/details/113113380)这两篇博客。

操作步骤：

```
   # 安装apache2工具
   sudo apt install apache2
   # 重启apache2服务
   sudo /etc/init.d/apache2 restart
   # 安装net-tools工具
   sudo apt install net-tools
   # 执行ifconfig查看ip
   ifconfig
   # 使用浏览器访问该ip地址
   # 替换/var/www/html/目录下的index.html文件就成功搭建自己的静态博客了
   # 这里我使用的是我在2022-2023春季学期计算机科学技术导论课程中制作的HTML网站
```

输出结果：

![image-20230918135159228](https://github.com/jiuhao47/UCAS-ICS-Share/blob/main/Lab1/Pic/Lab1-16.png?raw=true)

对Web服务器的理解：

​	Web服务器是指驻留于因特网上某种类型计算机的程序。当Web浏览器连到服务器上并请求文件时，服务器将处理该请求并将文件发送到该浏览器上，附带的信息会告诉浏览器如何查看该文件。Web服务器不仅能够存储信息，还能在用户通过Web浏览器提供的信息的基础上运行脚本和程序。Web服务器可以解析HTTP协议。当Web服务器接收到一个HTTP请求,会返回一个HTTP响应,例如送回一个HTML页面。为了处理一个请求Web服务器可以响应一个静态页面或图片，进行页面跳转或者把动态响应的产生委托给一些其它的程序例如JavaScript，或者委托给一些其它的服务器端技术。

5. **手工制作一个 chroot 沙箱来运行一个 C 语言写的 a+b 程序：**

   > 任务要求：你需要手工制作一个 chroot 沙箱，并在其中运行一个 C 语言编写的 a+b 程序。
   >
   > 实验报告推荐内容：描述你制作 chroot 沙箱的过程，包括创建沙箱环境和设置必要的限制。同时展示你成功运行的 a+b 程序，并解释你对沙箱设置的理解。

   【完成】：本实验参考了[linux chroot 命令](https://www.cnblogs.com/sparkdev/p/8556075.html#:~:text=sh - 4.2%23,exit switch_root%3A %2F%23 reboot)、[使用 chroot 建立沙盒环境](https://www.cnblogs.com/lost-melody/p/11721514.html)、[chroot, busybox和搭建沙盒](https://blog.csdn.net/largetalk/article/details/9073625)、[使用chroot构建linux沙盒](https://blog.csdn.net/jollyjumper/article/details/12624735)这四篇博客

   操作步骤：

   ```
   # 建立chroot沙箱文件夹
   mkdir tmp
   cd tmp
   mkdir bin
   mkdir lib
   mkdir lib64
   # 拷贝沙箱资源
   cp /bin/* /home/tmp/bin -r
   cp /lib/* /home/tmp/lib -r
   cp /lib64/* /home/tmp/lib64 -r
   cp /mnt/hgfs/UbuntuShare/ICS/Lab1/plus /home/tmp
   # 建立dev目录下的必要节点
   mkdir /home/tmp/dev
   cd /home/tmp/dev
   mknod -m 666 null c 1 3
   mknod -m 666 tty c 5 0
   mknod -m 666 zero c 1 5
   mknod -m 666 random c 1 8
   # 进入chroot沙箱环境
   sudo chroot /home/tmp /bin/sh
   # 更改环境变量
   export Home=/
   export Path=/bin
   # 执行a+b程序
   ./plus
   ```

   用到的C程序：`plus.c`

   ```C
   #include <stdio.h>
   int main()
   {
   	int a,b;
   	printf("Please enter 2 numbers:\n");
   	printf("e.g. 5,7\n");
   	scanf("%d,%d",&a,&b);
   	printf("%d+%d=%d\n",a,b,a+b);
   	return 0;
   }
   ```

   输出结果：

   ![Lab1-13](https://github.com/jiuhao47/UCAS-ICS-Share/blob/main/Lab1/Pic/Lab1-13.png?raw=true)

   对沙箱设置的理解：

   ​	沙箱目的在于隔离系统环境运行程序，目的是在保障系统安全的前提下测试运行程序。所以首先需要设置沙箱位置，拷贝沙箱资源，设置关键节点。而`bin`、`lib`、 `lib64`是Ubuntu程序运行的必须资源。拷贝完成后启动沙箱。由于未指定系统的环境变量位置，所以要手动设置系统环境变量。而这些是独立于主系统之外的，如果沙箱本体文件受到破坏，不会影响到主系统运行。

6. **使用 QEMU 开启一个虚拟机：**

   > 任务要求：你需要使用 QEMU 创建一个虚拟机，包括创建文件系统、编译或下载内核，并成功运行虚拟机。
   >
   > 实验报告推荐内容：描述你使用 QEMU 创建虚拟机的过程，包括创建文件系统、编译或下载内核的步骤。同时展示你成功运行的虚拟机，并解释你对以上操作的理解。

   【完成】：本实验参考了[Ubuntu使用qemu搭建ARM64架构虚拟机](https://blog.csdn.net/weixin_51760563/article/details/119935101#:~:text=Ubuntu18.04使用qemu搭建ARM64架构虚拟机 (方法一) 1 1. 安装qemu-system-aarch64 2 2. 下载UEFI固件,4. 创建虚拟硬盘 5 5. 虚拟机创建 6 6. 编写虚拟机启动脚本，方便下次启动虚拟机)这篇博客。

   操作步骤：

   ```
   # 安装qemu-system-aarch64
   sudo apt install -y qemu-system-arm
   # 下载UEFI固件:QEMU_EFI.fd
   # 创建虚拟机工作目录
   sudo mkdir qemu_system
   sudo cp /mnt/hgfs/UbuntuShare/QEMU_EFI.fd qemu_system
   # 下载操作系统并拷贝
   sudo cp /mnt/hgfs/UbuntuShare/ubuntu-18.04-server-arm64.iso qemu_system
   # 创建虚拟硬盘
   qemu-img create ubuntuimg.img 30G
   # 创建虚拟机
   sudo qemu-system-aarch64 -m 2048 -cpu cortex-a57 -smp 2 -M virt -bios QEMU_EFI.fd -nographic -drive if=none,file=ubuntu-18.04-server-arm64.iso,id=cdrom,media=cdrom -device virtio-scsi-device -device scsi-cd,drive=cdrom -drive if=none,file=ubuntuimg.img,id=hd0 -device virtio-blk-device,drive=hd0
   # 依照步骤安装
   # 创建虚拟机启动脚本
   sudo gedit run.sh
   ```

   启动脚本：

   ```
   # run.sh
   sudo qemu-system-aarch64 -m 2048 -cpu cortex-a57 -smp 2 -M virt -bios QEMU_EFI.fd -nographic  -device virtio-scsi-device -drive if=none,file=ubuntuimg.img,format=raw,index=0,id=hd0 -device virtio-blk-device,drive=hd0
   ```

   资源下载地址：

   [QEMU_EFI.fd](http://releases.linaro.org/components/kernel/uefi-linaro/16.02/release/qemu64/QEMU_EFI.fd)、[ubuntu-18.04-server-arm64.iso](ubuntu-18.04-server-arm64.iso)

   输出结果：

   ![Lab1-14](https://github.com/jiuhao47/UCAS-ICS-Share/blob/main/Lab1/Pic/Lab1-14.png?raw=true)

   理解：

   ​	首先要理解虚拟机运行需要哪些东西。启动BIOS运行在16位模式，其寻址空间小，运行较慢，所以现在x86、ARM架构都采用了UEFI的启动方式。因此我们想要找到引导设备，进一步安装aarch64架构的系统，先需要下载对应架构的UEFI固件，也就是`QEMU_EFI.fd`。然后需要下载操作系统，这里笔者采用的是arm64架构的Ubuntu18.04版本，即`ubuntu-18.04-server-arm64.iso`。最后虚拟机文件存储需要一块虚拟硬盘，笔者使用`qemu-img` `create`指令创建了30G的虚拟硬盘。

   ​	这样虚拟机运行需要的资源条件就备齐了，接下来就是配置虚拟机参数，将上述资源联系起来。下面说明了其中主要的几条参数的含义。

   ```
   # 虚拟机的RAM大小
   -m 
   # CPU模型
   -cpu
   # CPU个数
   -smp
   # 模拟主机类型
   -M
   # BIOS启动文件
   -bios
   # 禁用图形界面支持
   -nographic
   ```

7. **使用 Xephyr 开启一个新的 X 会话:**

   > 任务要求：你需要使用 Xephyr 开启一个新的 X 会话，并在其中运行各种程序。
   >
   > 实验报告推荐内容：描述你使用 Xephyr 开启新的 X 会话的过程，包括配置和启动 Xephyr。同时展示你成功运行的 X 会话，并解释你对 X 窗口系统以及新的 X 会话与旧的 X 会话之间关系的理解。

   【未实现】：笔者未能完成本实验要求，进度停滞在安装完毕了所需包。

8. **使用 Wine 运行 Windows 程序：** 

   > 任务要求：你需要在 Linux 系统上安装 Wine，并成功运行一个 Windows 程序。
   >
   > 实验报告推荐内容：描述你安装 Wine 的过程，包括配置和启动 Wine。同时展示你成功运行的Windows程序，并解释你对 Wine 功能、应用场景以及优势劣势的理解。

   【完成】：本实验参考了[Ubuntu 下 Wine的安装与使用](https://blog.csdn.net/plokm789456/article/details/130210571)这篇博客。

   操作步骤：

   ```
   # 验证是否为64位架构
   dpkg --print-architecture
   # 查看是否安装了32位架构
   dpkg --print-foreign-architectures
   # 下载并添加 WineHQ 存储库密钥
   sudo wget -O /etc/apt/keyrings/winehq-archive.key https://dl.winehq.org/wine-builds/winehq.key
   # 添加国内的镜像源
   sudo gedit /etc/apt/sources.list.d/winehq-jammy.sources
   # 更新数据库
   sudo apt update
   # 安装Wine
   sudo apt install winehq-stable
   # 运行Windows程序
   wine DiskMark64.exe
   ```

   国内镜像源：

   ```
   Types: deb
   URIs: https://mirrors.tuna.tsinghua.edu.cn/wine-builds/ubuntu
   Suites: jammy
   Components: main
   Architectures: amd64 i386
   Signed-By: /etc/apt/keyrings/winehq-archive.key
   ```

   输出结果：

   ![Lab1-15](https://github.com/jiuhao47/UCAS-ICS-Share/blob/main/Lab1/Pic/Lab1-15.png?raw=true)

   理解：
   
   ​	Wine相当于在Linux上搭建了一个可以兼容运行Windows程序的环境，是运用API转换技术实做出Linux对应到Windows相对应的函数来调用DLL以运行Windows程序。Wine主要应用于将Windows上刚性需求的应用程序迁移到类Linux系统上运行，或者将Windows程序置于类Linux环境下运行再发布。Wine的优势我认为在于其相对便捷地打通了Windows与类Linux的界限，实现了"兼容性"。但是由于Windows应用程序运行环境的复杂性，Wine也不能照顾到所有的应用程序，大量的报错与闪退在Wine运行Windows程序时出现，某种程度上也限制了其使用环境与便捷性。

### 讨论与总结

**实验中遇到的困难及解决方案**

1. Ubuntu官方源下载速度缓慢，需要更换国内源

   【解决】：通过网络查询，笔者找到了更换国内源的方法

   操作步骤：

   ```
   # 拷贝系统源
   sudo cp /etc/apt/sources.list /mnt/hgfs/UbuntuShare/
   # 打开系统源文件，将其中的内容替换为国内源，保存
   sudo gedit /etc/apt/sources.list
   # 更新
   sudo apt update
   ```

   这里笔者使用的是[清华源](https://mirrors.tuna.tsinghua.edu.cn/help/ubuntu/)，等待更新后就可以使用了。

2. Ubuntu虚拟机与Windows主系统之间的文件通信不便。

   【解决】：通过网络查询，笔者采用“共享文件夹”的方式，实现了Ubuntu虚拟机与Windows系统的文件通信。其中操作参考了[Vmware设置共享文件夹](https://blog.csdn.net/baidu_16271159/article/details/131725020)这篇博客。

   操作步骤：

   ```
   # VMware WorkStation界面下，选中需要共享文件夹的虚拟机，右键，设置
   # 在设置界面顶端，选项-共享文件夹-总是启用
   # 在共享文件夹标签下，添加共享文件夹路径，启用，不勾选只读
   # 启动虚拟机
   # 在/mnt目录下建立子目录/hgfs
   cd /mnt
   sudo mkdir hgfs
   # 将共享文件夹挂载到/mnt/hgfs目录下，并将其权限设置为用户权限
   sudo /usr/bin/vmhgfs-fuse .host:/ /mnt/hgfs -o allow_other -o uid=1000 -o gid=1000 -o umask=022
   # 注意这里的uid与gid需要根据用户的id来决定，可以使用id命令查看
   ```

   这样我们就实现了共享文件夹这一功能，但是到这里该操作还有缺陷，每当虚拟机重新启动，挂载的共享文件夹会解挂，需要重新挂载。

   于是笔者考虑能否开机运行挂载指令，经过网络查询，在[Ubuntu20.04开机自动运行脚本(命令)](https://blog.csdn.net/feiying0canglang/article/details/124695749)这篇博客中笔者找到了具体操作。

   操作步骤：

   ```
   # 创建rc-local.service文件
   sudo cp /lib/systemd/system/rc-local.service /etc/systemd/system
   # 修改/etc/systemd/system/rc-local.service
   sudo gedit /etc/systemd/system/rc-local.service
   # 创建rc.local文件，写入挂载命令
   sudo gedit /etc/rc.local
   # 给rc.local加上可执行权限
   sudo chmod +x /etc/rc.local
   # 重启虚拟机检查共享文件夹目录
   ```

   `rc.local`文件：

   ```bash
   #!/bin/sh
    
   sudo /usr/bin/vmhgfs-fuse .host:/ /mnt/hgfs -o allow_other -o uid=1000 -o gid=1000 -o umask=022
    
   exit 0
   ```

   笔者在加入了开机运行挂载指令后，`/mnt/hgfs`目录下就一直存在与Windows系统实时通信的文件夹`/UbuntuShare`了，同时`/UbuntuShare`文件夹也在我的VScode工作目录下，一定程度上提高了我的学习与工作效率。

   ### 参考文献与附录

**参考的网页**

1. [《Linux文件权限详解》](https://blog.csdn.net/lv8549510/article/details/85406215)

2. [Ubuntu/Linux用户管理与权限管理](https://blog.csdn.net/yl19870518/article/details/100776136)

3. [Ubuntu安装 Docker](https://blog.csdn.net/qq_44732146/article/details/121207737)

4. [Ubuntu搭建简单http服务器](https://blog.csdn.net/qq_30624591/article/details/118573780)

5. [Ubuntu查看本机IP地址的两种方法](https://blog.csdn.net/qq_34626094/article/details/113113380)

6. [linux chroot 命令](https://www.cnblogs.com/sparkdev/p/8556075.html#:~:text=sh - 4.2%23,exit switch_root%3A %2F%23 reboot)

7. [使用 chroot 建立沙盒环境](https://www.cnblogs.com/lost-melody/p/11721514.html)

8. [使用chroot构建linux沙盒](https://blog.csdn.net/jollyjumper/article/details/12624735)

9. [Ubuntu使用qemu搭建ARM64架构虚拟机](https://blog.csdn.net/weixin_51760563/article/details/119935101#:~:text=Ubuntu18.04使用qemu搭建ARM64架构虚拟机 (方法一) 1 1. 安装qemu-system-aarch64 2 2. 下载UEFI固件,4. 创建虚拟硬盘 5 5. 虚拟机创建 6 6. 编写虚拟机启动脚本，方便下次启动虚拟机)

10. [QEMU_EFI.fd](http://releases.linaro.org/components/kernel/uefi-linaro/16.02/release/qemu64/QEMU_EFI.fd)
11. [ubuntu-18.04-server-arm64.iso](ubuntu-18.04-server-arm64.iso)

12. [Ubuntu 下 Wine的安装与使用](https://blog.csdn.net/plokm789456/article/details/130210571)

13. [清华源](https://mirrors.tuna.tsinghua.edu.cn/help/ubuntu/)

14. [Vmware设置共享文件夹](https://blog.csdn.net/baidu_16271159/article/details/131725020)

15. [Ubuntu20.04开机自动运行脚本(命令)](https://blog.csdn.net/feiying0canglang/article/details/124695749)