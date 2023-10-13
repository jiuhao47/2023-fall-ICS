#  网络空间安全导论实验

## 实验二 软件安全：逆向工程、漏洞挖掘与利用
姜俊彦 2022K8009970011 2023年10月10日

### 摘要：

本实验旨在通过实际运用逆向工程、漏洞挖掘与利用的基础技能，让同学们加深对软件安全的理解与体会。

### 实验步骤、现象与结果分析：

**基础操作：**

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

   ![Lab2-1](E:\VSCODE\UbuntuShare\ICS\Pic\Lab2\Lab2-1.png)

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

   

