# 网络空间安全导论实验

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

   1. **C源码**
      
      ```C
      printf("Error: division by zero\n");
```
      
       **伪C代码**
      
      ```C
puts("Error: division by zero");
      ```
      
      **汇编代码** 
      
      ```assembly
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
      
      ---
      
   2. **C源码**
      
      ```C
      if (operand2 == 0)
   ```
      
      **伪C代码**
      
      ```C
   if (local_18 == 0)
      ```
      
      **汇编代码**
      
      ```assembly
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
      TEST指令的操作是将目的操作数和源操作数按位与，运算结果不送回目的操作数，然后根据结果设置SF,ZF,PF标志位，并将CF和OF标志位清零，一般下面会跟跳转，根据ZF标志位是否为零来决定是否跳转，即，这句意思就是判断EAX是否为零
      */
      ```
      
   
2. **逆向工程：**

   > 逆向工程中，调整变量的名称和类型有助于提高代码的可读性和可维护性。选择 `auth `程序中的两个函数，在反编译器的界面中，调整它们各个变量的名称和类型，使代码更合理易于理解

   `auth`-`view`

   

