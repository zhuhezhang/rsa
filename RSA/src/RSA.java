import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.util.Random;

/**
 * RSA算法实现。
 * 
 * @author zhz
 */
public class RSA {

	private BigInteger n;// = p * q，两个大质数的乘积
	private BigInteger e;// 公钥指数
	private BigInteger d;// 私钥指数
	private final int PQMINLENGTH = 1024;// p、q最小的长度（比特数）

	/**
	 * 根据传入参数产生密钥（公钥、私钥）。
	 * 
	 * @param e               公钥指数
	 * @param generateKeyFlag 大质数p、q的产生方式，0：文件读入；1：随机产生
	 * @param pqlLength       p、q的长度（比特数）
	 * @throws RSA.pqException
	 */
	public RSA(BigInteger e, int generateKeyFlag, int pqLength) throws RSA.pqException {
		this.e = e;
		generateKey(generateKeyFlag, pqLength);// 产生密钥
	}

	public static void main(String[] args) throws RSA.pqException, UnsupportedEncodingException {
		int generateKeyFlag = 0;// 大质数p、q的产生方式，0：文件读入；1：随机产生
		int pqLength = 1024;// p、q长度（比特数）
		String e = "65537";// 公钥指数
		String originalText = "永远相信美好的事情即将发生";// 原文

		System.out.println("加密前：" + originalText);
		RSA rsa = new RSA(new BigInteger(e), generateKeyFlag, pqLength);
		BigInteger[] c = rsa.encryption(originalText);// 加密
		System.out.print("加密后：");
		for (int i = 0; i < c.length; i++) {
			System.out.println(c[i]);
		}
		System.out.println("解密后：" + rsa.decryption(c));// 解密
	}

	/**
	 * 自定义异常内部类，用于输出由于大素数p、q不符合要求所产生的异常。
	 */
	private class pqException extends Exception {
		private static final long serialVersionUID = -7777566816579144864L;

		public pqException(String message) {
			super(message);
		}
	}

	/**
	 * 密钥产生。
	 * 
	 * @param generateKeyFlag 大质数p、q的产生方式，0：文件读入；1：随机产生
	 * @param pqLength        p、q的长度（比特数）
	 * @throws RSA.pqException
	 */
	private void generateKey(int generateKeyFlag, int pqLength) throws RSA.pqException {
		BigInteger p = BigInteger.ZERO;// 两个大素数
		BigInteger q = BigInteger.ZERO;
		BigInteger φn;// = (p-1)(q-1)

		if (generateKeyFlag == 0) {// 文件读入形式产生p、q、e
			String pqeFileName = "src\\pqe.txt";
			try {
				FileReader fileReader = new FileReader(pqeFileName);
				BufferedReader bufferedReader = new BufferedReader(fileReader);
				for (int i = 0; i < 2; i++) {
					if (i == 0) {
						p = new BigInteger(bufferedReader.readLine());
					} else {
						q = new BigInteger(bufferedReader.readLine());
					}
				}
				bufferedReader.close();// 关闭输入流
				fileReader.close();
			} catch (FileNotFoundException e) {
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			}

			String[] tmp = { "p", "q" };
			BigInteger pq[] = { p, q };
			for (int i = 0; i < 2; i++) {// 判断p、q的选取是否符合要求
				if (isPrime(pq[i]) && pq[i].bitLength() >= PQMINLENGTH) {// 符合要求
					continue;
				} else if (!isPrime(pq[i]) && pq[i].bitLength() >= PQMINLENGTH) {
					throw new pqException(tmp[i] + "不是质数，不符合要求，请重新选择！");
				} else if (isPrime(pq[i]) && pq[i].bitLength() < PQMINLENGTH) {
					throw new pqException(tmp[i] + "长度为" + pq[i].bitLength() + "，小于" + PQMINLENGTH + "，不符合要求，请重新选择！");
				} else {
					throw new pqException(
							tmp[i] + "不是质数，且其长度" + pq[i].bitLength() + "小于" + PQMINLENGTH + "，不符合要求，请重新选择！");
				}
			}
		} else {// 随机产生
			if (pqLength < PQMINLENGTH) {
				throw new pqException("p、q长度小于" + PQMINLENGTH + "，请重新选择更长的质数！");
			}
			p = RSA.generateNBitRandomPrime(pqLength);
			q = RSA.generateNBitRandomPrime(pqLength);
		}

		n = p.multiply(q);
		φn = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
		d = RSA.extdGcd(e, φn)[1];// 利用扩展欧几里得算法求私钥d
		if (d.compareTo(BigInteger.ZERO) != 1) {// 私钥不可以小于0
			d = d.add(φn);
		}
	}

	/**
	 * RSA加密。
	 * 
	 * @param plainText 明文
	 * @return mArray 加密后的BigInteger类型的数组
	 * @throws UnsupportedEncodingException
	 */
	private BigInteger[] encryption(String plainText) throws UnsupportedEncodingException {
		String textNum = "";// 明文数字字符串表示形式
		BigInteger m = BigInteger.ZERO;// 明文数字表示形式
		byte[] textByte = plainText.getBytes("UTF-8");
		for (int i = 0; i < textByte.length; i++) {// 每个字节用3位数的整数表示，不够则在前面补0
			int bn = textByte[i] & 0xff;
			if (bn < 10) {
				textNum += "00" + bn;
			} else if (bn < 100) {
				textNum += "0" + bn;
			} else {
				textNum += bn;
			}
		}
		m = new BigInteger(textNum);

		BigInteger[] mArray = null;// 明文分组结果
		if (m.compareTo(n) == -1) {// m < n，可直接加密
			mArray = new BigInteger[1];
			mArray[0] = m;
		} else {
			int groupLength = n.toString().length() - 1;// 每组明文长度
			int mStringLength = m.toString().length();// 明文转化为字符串的长度
			while (groupLength % 3 != 0) {// 由于前面每个字节用3位整数表示，因此每组的长度必须为3的整数，避免恢复时错误
				groupLength--;
			}
			if (mStringLength % groupLength != 0) {// 如果最后一组的长度不足
				mArray = new BigInteger[mStringLength / groupLength + 1];
			} else {
				mArray = new BigInteger[mStringLength / groupLength];
			}

			String tmp;
			for (int i = 0; i < mArray.length; i++) {
				tmp = "";
				if (i != mArray.length - 1) {// 根据每组长度进行分割分组保存
					tmp = textNum.substring(groupLength * i, groupLength * i + groupLength);
				} else {
					tmp = textNum.substring(groupLength * i);
				}
				mArray[i] = new BigInteger(tmp);
			}
		}

		for (int i = 0; i < mArray.length; i++) {// 逐组加密并返回
			mArray[i] = expMod(mArray[i], e, n);
		}
		return mArray;
	}

	/**
	 * RSA解密。
	 * 
	 * @param c BigInteger数组类型表达的密文
	 * @return new String(result) 解密结果
	 */
	private String decryption(BigInteger[] c) {
		String cPadding = "";
		String mToString = "";
		int mToStringLengthMod = 0;
		BigInteger m = BigInteger.ZERO;
		for (int i = 0; i < c.length; i++) {// 逐组解密
			m = RSA.expMod(c[i], d, n);
			mToString = m.toString();
			mToStringLengthMod = m.toString().length() % 3;
			if (mToStringLengthMod != 0) {// 由于加密时String转BigInter时前者前面的0并不会计入，所以需要确认并补全
				for (int j = 0; j < 3 - mToStringLengthMod; j++) {
					mToString = "0" + mToString;
				}
			}
			cPadding += mToString;
		}

		int byteNum = cPadding.length() / 3;// 明文总字节数
		byte[] result = new byte[byteNum];
		for (int i = 0; i < byteNum; i++) {// 每三位数转化为byte型并返回该byte数组所表达的字符串
			result[i] = (byte) (Integer.parseInt(cPadding.substring(i * 3, i * 3 + 3)));
		}
		return new String(result);
	}

	/**
	 * 利用扩展欧几里得算法求出私钥d，使得de = kφ(n)+1，k为整数。
	 * 
	 * @param e  公钥
	 * @param φn =(p-1)(q-1)
	 * @return gdk BigInteger数组形式返回最大公约数、私钥d、k
	 */
	private static BigInteger[] extdGcd(BigInteger e, BigInteger φn) {
		BigInteger[] gdk = new BigInteger[3];

		if (φn.compareTo(BigInteger.ZERO) == 0) {
			gdk[0] = e;
			gdk[1] = BigInteger.ONE;
			gdk[2] = BigInteger.ZERO;
			return gdk;
		} else {
			gdk = extdGcd(φn, e.remainder(φn));
			BigInteger tmp_k = gdk[2];
			gdk[2] = gdk[1].subtract(e.divide(φn).multiply(gdk[2]));
			gdk[1] = tmp_k;
			return gdk;
		}
	}

	/**
	 * 利用米勒·罗宾算法判断一个数是否是质数。
	 * 
	 * @param p 要判断的数
	 * @return true/false
	 */
	private static boolean isPrime(BigInteger p) {
		if (p.compareTo(BigInteger.TWO) == -1) {// 小于2直接返回false
			return false;
		}
		if ((p.compareTo(BigInteger.TWO) != 0) && (p.remainder(BigInteger.TWO).compareTo(BigInteger.ZERO) == 0)) {// 不等于2且是偶数直接返回false
			return false;
		}

		BigInteger p_1 = p.subtract(BigInteger.ONE);
		BigInteger m = p_1;// 找到q和m使得p = 1 + 2^q * m
		int q = m.getLowestSetBit();// 二进制下从右往左返回第一次出现1的索引
		m = m.shiftRight(q);

		for (int i = 0; i < 5; i++) {// 判断的轮数，精度、轮数和时间三者之间成正比关系
			BigInteger b;
			do {// 在区间1~p上生成均匀随机数
				b = new BigInteger(String.valueOf(p.bitLength()));
			} while (b.compareTo(BigInteger.ONE) <= 0 || b.compareTo(p) >= 0);

			int j = 0;
			BigInteger z = RSA.expMod(b, m, p);
			while (!((j == 0 && z.equals(BigInteger.ONE)) || z.equals(p_1))) {
				if ((j > 0 && z.equals(BigInteger.ONE)) || ++j == q) {
					return false;
				}
				z = RSA.expMod(z, BigInteger.TWO, p);
			}
		}

		return true;
	}

	/**
	 * 随机产生n比特的素数。最高位是1，从高位开始随机产生共n-1个0和1（0和1的比例是随机的，不是
	 * 平均），并将每位所得值相加最终形成一个n位数。然后判断该数是否是素数，是则返回，否则重新开始产生新的数直至该数为素数为止。
	 * 
	 * @param n 比特数
	 * @return result 结果
	 */
	private static BigInteger generateNBitRandomPrime(int n) {
		BigInteger tmp = new BigInteger("2").pow(n - 1);// 最高位肯定是1
		BigInteger result = new BigInteger("2").pow(n - 1);
		Random random = new Random();
		int r1 = random.nextInt(101);// 产生0-100的整数，用于确定0和1的比例
		int r2;

		while (true) {// 循环产生数，直到该数为素数
			for (int i = n - 2; i >= 0; i--) {// 逐位产生表示数的0和1，并根据所在位计算结果相加起来
				r2 = random.nextInt(101);
				if (0 < r2 && r2 < r1) {// 产生的数为1
					result = result.add(BigInteger.TWO.pow(i));
				}
				continue;
			}

			if (RSA.isPrime(result)) {// 素数判断
				return result;
			}

			result = tmp;// 重新计算
		}
	}

	/**
	 * 蒙哥马利快速幂模运算，返回base^exponent mod module的结果。
	 * 
	 * @param base     底数
	 * @param exponent 指数
	 * @param module   模数
	 * @return result 结果
	 */
	private static BigInteger expMod(BigInteger base, BigInteger exponent, BigInteger module) {
		BigInteger result = BigInteger.ONE;
		BigInteger tmp = base.mod(module);

		while (exponent.compareTo(BigInteger.ZERO) != 0) {
			if ((exponent.and(BigInteger.ONE).compareTo(BigInteger.ZERO)) != 0) {
				result = result.multiply(tmp).mod(module);
			}
			tmp = tmp.multiply(tmp).mod(module);
			exponent = exponent.shiftRight(1);
		}

		return result;
	}

}
