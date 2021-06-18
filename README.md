@[TOC](目录)
# 1.使用说明
本程序利用eclipse使用Java语言编写。使用该程序可利用eclipse打开源代码文件夹，然后运行RSA.java即可根据默认的明文和密钥输出加密、解密结果。默认使用的密钥由文件读出的1024位大素数产生，也可以更改参数使用自定义算法产生指定位的大素数。同时为保证安全性以及照顾到算法加密、解密时间，两个大素数强制规定必须在1024位及以上，公钥指数为最常用的65537。
# 2.运行截图
 ![在这里插入图片描述](https://img-blog.csdnimg.cn/20210617144659786.png)
# 3.总体设计
## 3.1类和函数
本程序只有一个RSA.java类。
- （1）public RSA(BigInteger e, int generateKeyFlag, int pqLength) throws RSA.pqException，该构造函数根据传入的形参公钥指数e、大质数p和q的产生方式标识generateKeyFlag、q和p的长度（比特数）pqLength，来调用函数generateKey来产生密钥（公钥和私钥）。
- （2）public static void main(String[] args) throws RSA.pqException，主函数指定明文等参数并调用函数encryption和decryption来进行加密、解密。
- （3）自定义内部类private class pqException extends Exception，只有一个构造函数传入形参message，用于输出由于大素数p、q不符合要求所产生的异常。
- （4）private void generateKey(int generateKeyFlag, int pqLength) throws RSA.pqException，密钥产生函数，形参分别是大质数p和q的产生方式标识（0：文件读入；1：随机产生）generateKeyFlag、p和q的长度（比特数）pqLength。
- （5）private BigInteger[] encryption(String plainText)RSA加密函数，形参传入String类型的明文plainText，返回加密后的BigInteger类型的数组。
- （6）private String decryption(BigInteger[] c)RSA解密函数，形参传入BigInteger数组类型表达的密文c，返回String类型的new String(result)解密结果。
- （7）private static BigInteger[] extdGcd(BigInteger e, BigInteger φn) 利用扩展欧几里得算法求出私钥d，使得de = kφ(n)+1，k为整数。形参分别是公钥e、φn （=(p-1)(q-1)），返回BigInteger数组形式返回最大公约数、私钥d、k（gdk）。
- （8）private static boolean isPrime(BigInteger p) 利用米勒·罗宾算法判断一个数是否是质数，形参是要判断的数，返回true/false。
- （9）private static BigInteger generateNBitRandomPrime(int n)，随机产生n比特的素数，形参数比特数n，返回产生的素数。
- （10）private static BigInteger expMod(BigInteger base, BigInteger exponent, BigInteger module) 蒙哥马利快速幂模运算，返回base^exponent mod module的结果，形参分别是底数base、指数exponent、模数module，返回结果result。
## 3.2结构说明
RSA算法的具体描述如下：
- （1）任意选取两个不同的大素数p和q计算乘积n=pq，φ(n)=(p-1)(q-1)；
- （2）任意选取一个大整数e，满足gcd(e, φ(n))=1且1<e<φ(n)，e用做加密钥；
- （3）确定的解密钥d，满足(de)modφ(n)=1，即de=kφ(n)+1，k>=1且为整数；
- （4）公开整数n和e，秘密保存d；
- （5）将明文m（m<n，是一个整数）加密成密文c，加密算法为c=E(m)=memodn；
- （6）将密文c解密为明文m，解密算法为m=D(c)=cdmodn。
根据如上所示的RSA算法的基本流程，结合本实例来说明一下程序结构。公钥e直接使用通用的65537，在generateKey函数中可使用文件读入或随机的方式产生p、q，随机产生的方式会利用到函数generateNBitRandomPrime和isPrime产生指定位的素数，然后利用extdGcd函数计算出私钥d。接着在encryption加密函数中会根据m<n的原则进行分组逐组加密，利用expMod进行快速幂模运算，解密函数decryption中同样逐组利用expMod函数进行幂模运算。
# 4.详细设计
RSA.java类中定义三个变量，分别是两个大质数乘积n、公钥指数e、私钥指数d，以及一个常量PQMINLENGTH表示质数q和p最小长度（比特数）。
- （1）public RSA(BigInteger e, int generateKeyFlag, int pqLength) throws RSA.pqException，该构造函数根据传入的形参公钥指数e、大质数p和q的产生方式标识generateKeyFlag、q和p的长度（比特数）pqLength，来调用函数generateKey来产生密钥（公钥和私钥）。
 - （2）public static void main(String[] args) throws RSA.pqException，主函数定义变量generateKeyFlag、pqLength（p和q长度，比特数）、公钥指数e、以及要加密的原文originalText。利用指定参数初始化对象，然后调用函数encryption并传入原文进行加密同时返回密文数组，并输出密文。再将密文数组传进decryption函数来进行解密并返回明文。
-  （3）自定义内部异常类private class pqException extends Exception，该自定义异常类很简单，只有一个构造函数传入形参字符串类型的形参message，用于输出由于大素数p、q不符合要求所产生的异常。
- （4）private void generateKey(int generateKeyFlag, int pqLength) throws RSA.pqException，密钥产生函数，形参分别是大质数p和q的产生方式标识（0：文件读入；1：随机产生）generateKeyFlag、p和q的长度（比特数）pqLength。首先定义两个大素数和φ（n），也就是大素数分别减一的乘积。判断素数产生的标识，如果为0则代表由文件读入。利用FileReader和BufferedReader对象，利用循环和后者的readline逐行读物出两个素数并赋值（文件中的两个素数按行存取，每一行代表一个素数），然后利用close方法关闭输入流。
- 接着逐个两个两个数是否是质数（利用函数isPrime判定）、长度是否大于所规定的，如果不满足其中一个则直接抛出异常，程序结束。如果是随机产生两个大素数，首先对参数pqLength判断是否小于规定的最小长度，如果小于，则抛出指定的自定义异常，程序结束；否则调用函数generateNBitRandomPrime传入素数长度这个产生两个素数。
- 接着分别求出n和φ（n），并利用自定义的扩展欧几里得算法extdGcd求出私钥d，如果求出的私钥小于0，则加上φ（n）即可。
- （5）private BigInteger[] encryption(String plainText)RSA加密函数，形参传入String类型的明文plainText，返回加密后的BigInteger类型的数组。利用getByte函数将String类型的明文转化为byte数组类型，指定编码为UTF-8，然后这里每个字节利用3为整数来表示，不够则在前面补0，因此循环遍历字节数组将每位和0xff（16进制数，10进制为255）进行与操作得到一个非负整数，然后添加到字符串上。
- 之后利用BigInteger的构造函数将这字符串转化为BigInteger类型保存在m上，判定该数是否小于n，若小于n则为mArray数组分配一个BigInteger大小的空间并将m保存到该数组上；如果大于n，由于算法的规定，因此需要进行分组加密，每组的长度规定为n的字符串的长度-1，这样是避免分组后大小依然超过n。同时也由于前面的每个字节是由3位整数保存的，因此分组的长度也应该为3的整数，避免恢复时出错。
- 因此判读此时的每组长度是否为3的整数，如果不是，则减一。然后判断明文数字形式字符串长度模上每组的长度是否为0，如果补是则明文数组mArray应该为明文数字字符串长度除每组长度加1，否则就不用加1。接着利用循环分割明文数字形式字符串保存在BigInteger数组中，然后再次利用循环调用expMod快速幂模函数逐组加密保存到数组上并返回。
- （6）private String decryption(BigInteger[] c)RSA解密函数，形参传入BigInteger数组类型表达的密文c，返回String类型的new String(result)解密结果。对密文BigInteger数组利用快速幂模函数expMod进行逐组解密,由于解密出来的每组的数字可能由于最前面的数字为0而缺失，导致转化为byte数组时出错，因此这里需要判断 是否为3的整数，如果不是则在最前面补0直到为3的整数倍，然后将每组所得的结果组合成一个长的数字字符串，利用循环每3为代表一个字节逐段截取并强化转为byte类型(byte) (Integer.parseInt(cPadding.substring(i * 3, i * 3 + 3)))，并保存到byte数组上，然后利用String构造方法将次byte数组转化为明文。
- （7）private static BigInteger[] extdGcd(BigInteger e, BigInteger φn) 利用扩展欧几里得算法求出私钥d，使得de = kφ(n)+1，k为整数。形参分别是公钥e、φn （=(p-1)(q-1)），返回BigInteger数组形式返回最大公约数、私钥d、k（gdk）。7~10涉及到的数学原理就不再过多介绍，因为我们的重点并不在这里。定义3个BigInteger大小的数组用来保存最大公约数g、私钥d、k，如果φ(n)为0，为将公钥指数e赋给g，1赋给d,0赋给k，并返回gdk；否则将传入φ（n）,e % φ(n)递归调用该函数，然后临时保存k，k为d-e/φ(n)*k，将临时保存的k赋给d，最后返回。
- （8）private static boolean isPrime(BigInteger p) 利用米勒·罗宾算法判断一个数是否是质数，形参是要判断的数，返回true/false。如果小于2则返回false，又不为2且可以整除2也直接返回false，否则利用如下代码BigInteger p_1 = p.subtract(BigInteger.ONE);BigInteger m = p_1;int q = m.getLowestSetBit();m = m.shiftRight(q); 找到q和m使得p = 1 + 2^q * m。然后在1~p区间上生成均匀随机数，将下面步骤的利用循环判断5轮（判断的轮数，精度、轮数和时间三者之间成正比关系），BigInteger z = RSA.expMod(b, m, p);while (!((j == 0 && z.equals(BigInteger.ONE)) || z.equals(p_1))) {if ((j > 0 && z.equals(BigInteger.ONE)) || ++j == q) {return false;}z = RSA.expMod(z, BigInteger.TWO, p);}，若通过了米勒·罗宾算法则代表是素数，返回true。
- （9）private static BigInteger generateNBitRandomPrime(int n)，随机产生n比特的素数，形参数比特数n，返回产生的素数。这里主要的思想是先算出在该比特数下的最小数，也就是2^（n-1）,然后先随机生成一个1-100的整数用于确定0和1出现的比率，保证生成的01的概率都是50%，然后除了最高位（最高位肯定是1），逐位产生01并根据所在位置计算值和最小值相加，也就是二进制转化为10进制，最后便得到一个指定位的整数，然后利用前面的素数判断函数判断该数是否是素数，如果是则直接返回否则继续生成，直到是素数为止。
- （10）private static BigInteger expMod(BigInteger base, BigInteger exponent, BigInteger module) 蒙哥马利快速幂模运算，返回base^exponent mod module的结果，形参分别是底数base、指数exponent、模数module，返回结果result。Result为1，tmp = base.mod(module)。循环条件为指数不为0，然后判断指数和1进行与操作的值是否为0，如果不是则result = result.multiply(tmp).mod(module);出if语句，然后tmp = tmp.multiply(tmp).mod(module);，指数右移1位，继续进行循环，循环结束返回结果即可。
# 5.源码
[https://gitee.com/zhz000/rsa](https://gitee.com/zhz000/rsa)
[https://github.com/zhz000/rsa](https://github.com/zhz000/rsa)
