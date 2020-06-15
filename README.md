#GMTool
全部基于国密算法开发的集哈希、加解密、签名验证、Mac码计算于一体的综合工具---Java语言版

课设要求：
用JAVA语言设计并实现一个国密算法综合工具，至少实现HASH值计算、对文件进行加解密、对文件进行数字签名和签名验证和MAC码计算四项功能：
1）	使用SM3算法计算文件和字符串的HASH值。
2）	使用流密码ZUC-128、ZUC-256分组密码SM4共三个算法对文件进行加密。要求：
	a)	基于用户输入的口令生成密钥。
	b)	加密时用户可以选择密码算法，解密时用户不需要选择密码算法，因此加密时需要将所用的密码算法信息存储在密文文件里，在解密时读出来用。
	c)	如果需要IV等算法参数，则加密时随机生成这些参数，并存储在密文文件里，在解密进读出来用。
	d)	完成文件被加密后，关闭并重新打开程序，可以正常解密。
3）	使用SHA256WITHSM2或SM3WITHSM2算法对文件进行数字签名和签名验证，要求：
	a)	签名之前先生成一个椭圆曲线公私钥对，并将其存入密钥库文件，密钥库文件格式应为PCKS12；
	b)	签名时从密钥库文件中获取私钥，对文件签名，签名值保存在一个专门的签名值文件中，签名值文件的文件名可以设成被签名文件的文件名后加.sig后缀；
	c)	生成签名之后，关闭并再次打开程序，再进行签名验证；
	d)	签名验证时，输入将被签名的文件名、签名值文件名和密钥库文件名，从密钥库文件中获取数字证书，从而获取公钥，然后验证签名；
	e)	在程序测试时，要求正常情况下签名验证成功，修改被签名文件或修改签名值文件后，签名验证都会失败。
4）	使用Mac算法ZUC-128、ZUC-256、ZUC-256-32、ZUC-256-64计算文件和字符串的Mac码。


All comprehensive tools based on the national secret algorithm that integrate hashing, encryption and decryption, signature verification, and Mac code calculation---Java version
Course requirements:
Design and implement a comprehensive national encryption algorithm tool in JAVA language, at least four functions: HASH value calculation, file encryption and decryption, file digital signature and signature verification, and MAC code calculation:
1) Use the SM3 algorithm to calculate the hash value of files and strings.
2) Encrypt files using three algorithms: stream ciphers ZUC-128 and ZUC-256 block cipher SM4. Claim:
	a) Generate a key based on the password entered by the user.
	b) The user can choose the password algorithm during encryption. The user does not need to select the password algorithm during decryption. Therefore, the encryption algorithm information needs to be stored in the cipher text file during encryption and read out during decryption.
	c) If algorithm parameters such as IV are required, these parameters are randomly generated during encryption and stored in the cipher text file for decryption and reading.
	d) After the file is encrypted, close and reopen the program to decrypt normally.
3) To use SHA256WITHSM2 or SM3WITHSM2 algorithm to digitally sign and verify the file, the requirements are:
	a) Before signing, first generate an elliptic curve public and private key pair and store it in the keystore file. The keystore file format should be PCKS12;
	b) Obtain the private key from the keystore file when signing, sign the file, and save the signature value in a special signature value file. The file name of the signature value file can be set to the file name of the signed file followed by .sig suffix ;
	c) After generating the signature, close and open the program again, and then verify the signature;
	d) During signature verification, enter the file name, signature value file name and keystore file name to be signed, obtain a digital certificate from the keystore file to obtain the public key, and then verify the signature;
	e) During program testing, signature verification is required to succeed under normal circumstances. After modifying the signed file or modifying the signature value file, signature verification will fail.
4) Use Mac algorithms ZUC-128, ZUC-256, ZUC-256-32, ZUC-256-64 to calculate Mac codes of files and character strings.