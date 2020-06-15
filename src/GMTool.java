import java.awt.BorderLayout;
import java.awt.EventQueue;
import java.awt.HeadlessException;

import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;
import javax.swing.JTabbedPane;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JTextField;
import javax.swing.JButton;
import javax.swing.JTextArea;
import javax.swing.border.TitledBorder;
import javax.swing.filechooser.FileNameExtensionFilter;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.crypto.macs.Zuc128Mac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.encoders.Hex;
import javax.swing.border.EtchedBorder;
import java.awt.Color;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.ImageIcon;
import javax.swing.JRadioButton;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.ButtonGroup;
import javax.swing.JPasswordField;
import javax.swing.JCheckBox;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.DigestInputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.UnrecoverableEntryException;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.awt.event.ActionEvent;

public class GMTool extends JFrame {

	private JPanel contentPane;
	private JTextField textFieldHashInput;
	private JTextField textFieldEncryptInput;
	private final ButtonGroup buttonGroup = new ButtonGroup();
	private JPasswordField passwordFieldEncryptPassword;
	private JTextField textFieldPendingFileInput;
	private JTextField textField_MacInput;
	private JTextField textField_Mac_ZUC_128_Output;
	private JTextField textField_Mac_ZUC_256_Output;
	private JTextField textField_Mac_ZUC_256_32_Output;
	private JTextField textField_Mac_ZUC_256_64_Output;
	private JTextField textFieldSigInput;
	private JTextField textFieldKeyStoreInput;

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		Security.addProvider(new BouncyCastleProvider());
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					GMTool frame = new GMTool();
					frame.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}

	/**
	 * Create the frame.
	 */
	public GMTool() {
		setTitle("\u56FD\u5BC6\u7B97\u6CD5\u5DE5\u5177\u5305");
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		setBounds(100, 100, 737, 344);
		contentPane = new JPanel();
		contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
		contentPane.setLayout(new BorderLayout(0, 0));
		setContentPane(contentPane);
		
		JTabbedPane tabbedPane = new JTabbedPane(JTabbedPane.TOP);
		contentPane.add(tabbedPane, BorderLayout.CENTER);
		
		JPanel panel_Hash = new JPanel();
		tabbedPane.addTab("\u54C8\u5E0C\u8BA1\u7B97", null, panel_Hash, null);
		panel_Hash.setLayout(null);
		
		JPanel panel = new JPanel();
		panel.setBorder(new TitledBorder(new EtchedBorder(EtchedBorder.LOWERED, new Color(255, 255, 255), new Color(160, 160, 160)), "\u9009\u62E9\u52A0\u5BC6\u7C7B\u578B", TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
		panel.setBounds(16, 21, 506, 237);
		panel_Hash.add(panel);
		panel.setLayout(null);
		
		JComboBox comboBox_HashType = new JComboBox();
		comboBox_HashType.setBounds(27, 27, 56, 23);
		panel.add(comboBox_HashType);
		comboBox_HashType.setModel(new DefaultComboBoxModel(new String[] {"\u6587\u4EF6", "\u5B57\u7B26\u4E32"}));

		textFieldHashInput = new JTextField();
		textFieldHashInput.setBounds(93, 28, 314, 21);
		panel.add(textFieldHashInput);
		textFieldHashInput.setColumns(10);

		JButton btnHashBrowse = new JButton("\u6D4F\u89C8");
		btnHashBrowse.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				JFileChooser fileChooser = new JFileChooser("D:/");
				if (fileChooser.showOpenDialog(null) == JFileChooser.APPROVE_OPTION) {
					
					String fileName = fileChooser.getSelectedFile().getPath();
					
					textFieldHashInput.setText(fileName);
				}
			}
		});
		btnHashBrowse.setBounds(417, 27, 64, 23);
		panel.add(btnHashBrowse);
		
		JTextArea textAreaHashOutput = new JTextArea();
		textAreaHashOutput.setEditable(false);
		textAreaHashOutput.setBounds(27, 94, 454, 101);
		panel.add(textAreaHashOutput);
		
		JLabel lblNewLabel = new JLabel("\u54C8\u5E0C\u503C\uFF1A");
		lblNewLabel.setBounds(25, 69, 58, 15);
		panel.add(lblNewLabel);
		
		JButton btnHashCalculate = new JButton("\u8BA1\u7B97");
		btnHashCalculate.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				textAreaHashOutput.setText("");			
				
				if (comboBox_HashType.getSelectedIndex() == 0) {
					String fileName = textFieldHashInput.getText();
					fileName = fileName.replace('\\', '/');
					try (FileInputStream fis = new FileInputStream(fileName)){						
							MessageDigest md = MessageDigest.getInstance("SM3");
							try (DigestInputStream dis = new DigestInputStream(fis, md)) {
								
								byte[] buffer = new byte[1024];
								while(dis.read(buffer) != -1);
							}
							textAreaHashOutput.setText(Hex.toHexString(md.digest()));												
					} catch (FileNotFoundException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					} catch (IOException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					} catch (NoSuchAlgorithmException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					}
				}else {
					String s = textFieldHashInput.getText();
					MessageDigest md = null;
					try {
						md = MessageDigest.getInstance("SM3");
					} catch (NoSuchAlgorithmException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					}
					textAreaHashOutput.setText(Hex.toHexString(md.digest(s.getBytes())));
				}
			}
		});
		btnHashCalculate.setBounds(560, 32, 97, 50);
		panel_Hash.add(btnHashCalculate);
		
		JPanel panel_Encryptor = new JPanel();
		tabbedPane.addTab("\u6587\u4EF6\u52A0\u89E3\u5BC6", null, panel_Encryptor, null);
		panel_Encryptor.setLayout(null);
		
		JPanel panel_2 = new JPanel();
		panel_2.setBorder(new TitledBorder(new EtchedBorder(EtchedBorder.LOWERED, new Color(255, 255, 255), new Color(160, 160, 160)), "\u9009\u62E9\u5F85\u5904\u7406\u6587\u4EF6", TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
		panel_2.setBounds(9, 28, 474, 214);
		panel_Encryptor.add(panel_2);
		panel_2.setLayout(null);
		
		textFieldEncryptInput = new JTextField();
		textFieldEncryptInput.setBounds(42, 22, 337, 21);
		panel_2.add(textFieldEncryptInput);
		textFieldEncryptInput.setColumns(10);
		
		JLabel lblNewLabel_1 = new JLabel("New label");
		lblNewLabel_1.setBounds(12, 17, 25, 30);
		panel_2.add(lblNewLabel_1);
		lblNewLabel_1.setIcon(new ImageIcon("img\\file.png"));
		
		JButton btnEncryptBrowse = new JButton("\u6D4F\u89C8");
		btnEncryptBrowse.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				JFileChooser fileChooser = new JFileChooser("D:/");
				if (fileChooser.showOpenDialog(null) == JFileChooser.APPROVE_OPTION) {
					//
					String fileName = fileChooser.getSelectedFile().getPath();
					//
					textFieldEncryptInput.setText(fileName);
				}
			}
		});
		btnEncryptBrowse.setBounds(389, 21, 63, 23);
		panel_2.add(btnEncryptBrowse);
		
		JPanel panelAlgorithmChooser = new JPanel();
		panelAlgorithmChooser.setBounds(6, 65, 446, 46);
		panel_2.add(panelAlgorithmChooser);
		panelAlgorithmChooser.setBorder(new TitledBorder(new EtchedBorder(EtchedBorder.LOWERED, new Color(255, 255, 255), new Color(160, 160, 160)), "\u52A0\u5BC6\u7B97\u6CD5", TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
		panelAlgorithmChooser.setLayout(null);
		
		JRadioButton rdbtnZUC_128 = new JRadioButton("ZUC-128");
		buttonGroup.add(rdbtnZUC_128);
		rdbtnZUC_128.setBounds(6, 17, 127, 23);
		panelAlgorithmChooser.add(rdbtnZUC_128);
		
		JRadioButton rdbtnZUC_256 = new JRadioButton("ZUC-256");
		buttonGroup.add(rdbtnZUC_256);
		rdbtnZUC_256.setBounds(135, 17, 127, 23);
		panelAlgorithmChooser.add(rdbtnZUC_256);
		
		JRadioButton rdbtnSM4 = new JRadioButton("SM4");
		buttonGroup.add(rdbtnSM4);
		rdbtnSM4.setBounds(264, 17, 127, 23);
		panelAlgorithmChooser.add(rdbtnSM4);
		
		JLabel lblEncryptPassword = new JLabel("\u53E3\u4EE4\uFF1A");
		lblEncryptPassword.setBounds(12, 132, 58, 15);
		panel_2.add(lblEncryptPassword);
		
		passwordFieldEncryptPassword = new JPasswordField();
		passwordFieldEncryptPassword.setBounds(12, 157, 440, 21);
		panel_2.add(passwordFieldEncryptPassword);
		
		JButton btnEncrypt = new JButton("\u52A0\u5BC6");
		btnEncrypt.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				// 
				String plainFileName = textFieldEncryptInput.getText();
				String cipherFileName = plainFileName + ".enc";
				String algorithm = null;   // 
				int algType = 0; // ZUC-128 = 0; ZUC-256 = 1; SM4 = 2;
				int ivSize = 16;
				char[] password = passwordFieldEncryptPassword.getPassword();				
				int keySize = 128;
				if (rdbtnZUC_128.isSelected()) {
					algType = 0;
					keySize = 128;
					ivSize = 16;
					algorithm = "ZUC-128";
				} else if (rdbtnZUC_256.isSelected()) {
					algType = 1;
					keySize = 256;
					ivSize = 25;
					algorithm = "ZUC-256";
				} else if (rdbtnSM4.isSelected()) {
					algType = 2;
					keySize = 128;
					ivSize = 16;
					algorithm = "SM4";
				}
				
				SecretKeySpec key = passwordToKey(new String(password), keySize);
				
				byte[] ivValue = new byte[ivSize];
				SecureRandom random = new SecureRandom();
				random.nextBytes(ivValue);
				IvParameterSpec iv = new IvParameterSpec(ivValue);
				try {
				
					Cipher cipher = Cipher.getInstance(algorithm, "BC");
					cipher.init(Cipher.ENCRYPT_MODE, key, iv);
					
					
					try (FileOutputStream fos = new FileOutputStream(cipherFileName)) {
						
						fos.write(algType);
						
						fos.write(keySize / 8);
						
						fos.write(ivSize);

						fos.write(ivValue);
						try (FileInputStream fis = new FileInputStream(plainFileName);
								CipherInputStream cis = new CipherInputStream(fis, cipher)) {
							byte[] buffer = new byte[2048];
							int n = 0;
							while((n = cis.read(buffer)) != -1) {
								fos.write(buffer, 0, n);
							}
							JOptionPane.showMessageDialog(null, "加密成功");
						}
					}
				} catch (InvalidKeyException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				} catch (HeadlessException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				} catch (NoSuchAlgorithmException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				} catch (NoSuchPaddingException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				} catch (InvalidAlgorithmParameterException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				} catch (FileNotFoundException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				} catch (IOException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				} catch (NoSuchProviderException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}
			}
		});
		btnEncrypt.setBounds(553, 46, 96, 60);
		panel_Encryptor.add(btnEncrypt);
		
		JButton btnDecrypt = new JButton("\u89E3\u5BC6");
		btnDecrypt.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				// 
				String cipherFileName = textFieldEncryptInput.getText(); // 
				String decryptedFileName = cipherFileName + ".dec";
				int algType = 0; // ZUC-128 = 0; ZUC-256 = 1; SM4 = 2;
				int keySize = 0; 
				int ivSize = 0;  
				String algorithm = "";
				char[] password = passwordFieldEncryptPassword.getPassword(); // 

				try(FileInputStream fis = new FileInputStream(cipherFileName)) {
					algType = fis.read();
					keySize = fis.read() * 8; 

					ivSize = fis.read(); 

					byte[] ivValue = new byte[ivSize]; 
					fis.read(ivValue);

					IvParameterSpec iv = new IvParameterSpec(ivValue);
					SecretKeySpec key = passwordToKey(new String(password), keySize);
					if (algType == 0 ) {
						algorithm = "ZUC-128";
					}else if (algType == 1) {
						algorithm = "ZUC-256";
					}else {
						algorithm = "SM4";
					}
					
					Cipher cipher = Cipher.getInstance(algorithm, "BC");
					cipher.init(Cipher.DECRYPT_MODE, key, iv);
					try (CipherInputStream cis = new CipherInputStream(fis, cipher);
							FileOutputStream fos = new FileOutputStream(decryptedFileName)) {
						byte[] buffer = new byte[1024];
						int n = -1;
						while((n = cis.read(buffer)) != -1) {
							fos.write(buffer, 0, n);
						}
						JOptionPane.showMessageDialog(null, "解密成功");
					} catch (IOException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					}
				} catch (NoSuchAlgorithmException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				} catch (NoSuchProviderException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				} catch (NoSuchPaddingException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				} catch (InvalidKeyException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				} catch (InvalidAlgorithmParameterException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				} catch (FileNotFoundException e2) {
					// TODO Auto-generated catch block
					e2.printStackTrace();
				} catch (IOException e2) {
					// TODO Auto-generated catch block
					e2.printStackTrace();
				}
			}
		});
		btnDecrypt.setBounds(553, 152, 97, 60);
		panel_Encryptor.add(btnDecrypt);
		
		JPanel panel_Signature = new JPanel();
		tabbedPane.addTab("\u7B7E\u540D\u9A8C\u8BC1", null, panel_Signature, null);
		panel_Signature.setLayout(null);
		
		JPanel panel_3 = new JPanel();
		panel_3.setBorder(new TitledBorder(new EtchedBorder(EtchedBorder.LOWERED, new Color(255, 255, 255), new Color(160, 160, 160)), "\u6587\u4EF6\u914D\u7F6E", TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
		panel_3.setBounds(16, 29, 501, 216);
		panel_Signature.add(panel_3);
		panel_3.setLayout(null);
		
		textFieldPendingFileInput = new JTextField();
		textFieldPendingFileInput.setBounds(6, 53, 356, 21);
		panel_3.add(textFieldPendingFileInput);
		textFieldPendingFileInput.setColumns(10);
		
		JLabel lblToSignFile = new JLabel("\u9009\u62E9\u5F85\u5904\u7406\u6587\u4EF6\uFF1A");
		lblToSignFile.setBounds(6, 28, 108, 15);
		panel_3.add(lblToSignFile);
		
		JLabel lblNewLabel_3 = new JLabel("\u9009\u62E9\u7B7E\u540D\u6587\u4EF6\uFF08.sig\uFF09\uFF1A");
		lblNewLabel_3.setBounds(6, 140, 150, 15);
		panel_3.add(lblNewLabel_3);
		
		textFieldSigInput = new JTextField();
		textFieldSigInput.setBounds(6, 165, 356, 21);
		panel_3.add(textFieldSigInput);
		textFieldSigInput.setColumns(10);
		
		JButton btnPendingFileBrowse = new JButton("\u6D4F\u89C8");
		btnPendingFileBrowse.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				JFileChooser fileChooser = new JFileChooser("D:/");
				if (fileChooser.showOpenDialog(null) == JFileChooser.APPROVE_OPTION) {
					String fileName = fileChooser.getSelectedFile().getPath();
					textFieldPendingFileInput.setText(fileName);
				}
			}
		});
		btnPendingFileBrowse.setBounds(393, 52, 76, 23);
		panel_3.add(btnPendingFileBrowse);       
		
		JButton btnSignatureSIGFileBrowse = new JButton("\u6D4F\u89C8");
		btnSignatureSIGFileBrowse.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				JFileChooser fileChooser = new JFileChooser("D:/");
				if (fileChooser.showOpenDialog(null) == JFileChooser.APPROVE_OPTION) {
					String fileName = fileChooser.getSelectedFile().getPath();
					textFieldSigInput.setText(fileName);
				}
			}
		});
		btnSignatureSIGFileBrowse.setBounds(393, 164, 76, 23);
		panel_3.add(btnSignatureSIGFileBrowse);
		
		JLabel lblKeyStoreInput = new JLabel("\u9009\u62E9\u5BC6\u94A5\u5E93\u6587\u4EF6\uFF1A");
		lblKeyStoreInput.setBounds(6, 84, 108, 15);
		panel_3.add(lblKeyStoreInput);
		
		textFieldKeyStoreInput = new JTextField();
		textFieldKeyStoreInput.setBounds(6, 109, 356, 21);
		panel_3.add(textFieldKeyStoreInput);
		textFieldKeyStoreInput.setColumns(10);
		
		JButton btnKeyStoreBrowse = new JButton("\u6D4F\u89C8");
		btnKeyStoreBrowse.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				JFileChooser fileChooser = new JFileChooser("D:/");
				if (fileChooser.showOpenDialog(null) == JFileChooser.APPROVE_OPTION) {
					String fileName = fileChooser.getSelectedFile().getPath();
					textFieldKeyStoreInput.setText(fileName);
				}
			}
		});
		btnKeyStoreBrowse.setBounds(393, 108, 76, 23);
		panel_3.add(btnKeyStoreBrowse);
		
		JButton btnCreateKeyStore = new JButton("\u521B\u5EFA\u5BC6\u94A5\u5E93");
		btnCreateKeyStore.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				try {
					textFieldKeyStoreInput.setText(createKeyStore());
				} catch (Exception e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}
			}
		});
		btnCreateKeyStore.setBounds(265, 80, 97, 23);
		panel_3.add(btnCreateKeyStore);
		
		JButton btnSignature = new JButton("\u7B7E\u540D");
		btnSignature.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				String toSignFileName = textFieldPendingFileInput.getText();
				String signFileName = toSignFileName + ".sig";
				String keyStoreName = textFieldKeyStoreInput.getText();
				char[] keyStorePassWD = JOptionPane.showInputDialog("密钥库口令:").toCharArray();
				KeyStore keyStore = null;			 
				try (FileInputStream fis = new FileInputStream(keyStoreName)){
					keyStore = KeyStore.getInstance("PKCS12");
					keyStore.load(fis, keyStorePassWD);
				} catch (FileNotFoundException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				} catch (IOException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				} catch (NoSuchAlgorithmException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				} catch (CertificateException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				} catch (KeyStoreException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}


				// 读取密钥对mysm2key中的公钥对应的自签名证书，打印证书内容和公钥值
				KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(keyStorePassWD);
				KeyStore.PrivateKeyEntry keyEntry = null;
				try {
					keyEntry = (PrivateKeyEntry) keyStore.getEntry("mysm2key", protParam);
				} catch (NoSuchAlgorithmException e2) {
					// TODO Auto-generated catch block
					e2.printStackTrace();
				} catch (UnrecoverableEntryException e2) {
					// TODO Auto-generated catch block
					e2.printStackTrace();
				} catch (KeyStoreException e2) {
					// TODO Auto-generated catch block
					e2.printStackTrace();
				}
				ECPrivateKey privateKey = (ECPrivateKey) keyEntry.getPrivateKey();

				try {
					signFile(toSignFileName, privateKey, signFileName);
				} catch (Exception e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}
				JOptionPane.showMessageDialog(null, "签名成功");
				
			}
		});
		btnSignature.setBounds(562, 57, 97, 47);
		panel_Signature.add(btnSignature);
		
		JButton btnVerification = new JButton("\u9A8C\u8BC1");
		btnVerification.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				Security.addProvider(new BouncyCastleProvider());
				String verifiedFileName = textFieldPendingFileInput.getText();
				String signFileName = textFieldSigInput.getText();
				String keyStoreName = textFieldKeyStoreInput.getText();
				
				ECPublicKey publicKey = null;
				
				KeyStore keyStore = null;
				try {
					keyStore = KeyStore.getInstance("PKCS12");
				} catch (KeyStoreException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}
				try (FileInputStream fis = new FileInputStream(keyStoreName)) {
					// 创建KeyStore对象，并从密钥库文件中读入内容
					Security.addProvider(new BouncyCastleProvider());
					char[] password = JOptionPane.showInputDialog("密钥库口令:").toCharArray();
					try {
						keyStore.load(fis, password);
					} catch (NoSuchAlgorithmException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					} catch (CertificateException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					}
					// 遍历并打印密钥库中的所有别名
					Enumeration<String> aliases = null;
					try {
						aliases = keyStore.aliases();
					} catch (KeyStoreException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					}
					Collections.list(aliases).forEach(System.out::println);

					// 读取密钥对mysm2key中的私钥，创建一个私钥对象，并打印其内容
					KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(
							password);
					KeyStore.PrivateKeyEntry keyEntry = null;
					try {
						keyEntry = (PrivateKeyEntry) keyStore
								.getEntry("mysm2key", protParam);
					} catch (NoSuchAlgorithmException | UnrecoverableEntryException | KeyStoreException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					}
					ECPrivateKey privateKey = (ECPrivateKey) keyEntry.getPrivateKey();

					// 读取密钥对mysm2key中的公钥对应的自签名证书，打印证书内容和公钥值
					X509Certificate certificate = null;
					try {
						certificate = (X509Certificate) keyStore.getCertificate("mysm2key");
					} catch (KeyStoreException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					}

					publicKey = (ECPublicKey) certificate.getPublicKey();
				} catch (FileNotFoundException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				} catch (IOException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}
				
				try {
					boolean result = verifyFile(verifiedFileName, publicKey, signFileName);
					if ( result == true ) {
						JOptionPane.showMessageDialog(null, "验证成功");
					}
					else JOptionPane.showMessageDialog(null, "验证失败");
					
				} catch (Exception e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}
				
			}
		});
		btnVerification.setBounds(562, 171, 97, 47);
		panel_Signature.add(btnVerification);
		
		JPanel panel_Mac = new JPanel();
		tabbedPane.addTab("Mac\u7801\u8BA1\u7B97", null, panel_Mac, null);
		panel_Mac.setLayout(null);
		
		JPanel panel_1 = new JPanel();
		panel_1.setBorder(new TitledBorder(new EtchedBorder(EtchedBorder.LOWERED, new Color(255, 255, 255), new Color(160, 160, 160)), "\u9009\u62E9\u6587\u4EF6", TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
		panel_1.setBounds(16, 17, 517, 222);
		panel_Mac.add(panel_1);
		panel_1.setLayout(null);
		
		JComboBox comboBox_Mac = new JComboBox();
		comboBox_Mac.setBounds(6, 17, 63, 23);
		panel_1.add(comboBox_Mac);
		comboBox_Mac.setModel(new DefaultComboBoxModel(new String[] {"\u6587\u4EF6", "\u5B57\u7B26\u4E32"}));
		
		textField_MacInput = new JTextField();
		textField_MacInput.setBounds(79, 18, 333, 21);
		panel_1.add(textField_MacInput);
		textField_MacInput.setColumns(10);

		JButton btnMacBrowse = new JButton("\u6D4F\u89C8");
		btnMacBrowse.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				JFileChooser fileChooser = new JFileChooser("D:/");
				if (fileChooser.showOpenDialog(null) == JFileChooser.APPROVE_OPTION) {
					String fileName = fileChooser.getSelectedFile().getPath();
					textField_MacInput.setText(fileName);
				}
			}
		});
		btnMacBrowse.setBounds(422, 17, 69, 23);
		panel_1.add(btnMacBrowse);
		
		JCheckBox chckbx_Mac_ZUC_128 = new JCheckBox("ZUC-128");
		chckbx_Mac_ZUC_128.setBounds(6, 68, 95, 23);
		panel_1.add(chckbx_Mac_ZUC_128);
		
		JCheckBox chckbxMac_ZUC_256 = new JCheckBox("ZUC-256");
		chckbxMac_ZUC_256.setBounds(6, 103, 95, 23);
		panel_1.add(chckbxMac_ZUC_256);
		
		JCheckBox chckbxMac_ZUC_256_32 = new JCheckBox("ZUC-256-32");
		chckbxMac_ZUC_256_32.setBounds(6, 134, 95, 23);
		panel_1.add(chckbxMac_ZUC_256_32);
		
		JCheckBox chckbxMac_ZUC_256_64 = new JCheckBox("ZUC-256-64");
		chckbxMac_ZUC_256_64.setBounds(6, 166, 95, 23);
		panel_1.add(chckbxMac_ZUC_256_64);
		
		textField_Mac_ZUC_128_Output = new JTextField();
		textField_Mac_ZUC_128_Output.setBounds(107, 69, 384, 21);
		panel_1.add(textField_Mac_ZUC_128_Output);
		textField_Mac_ZUC_128_Output.setEditable(false);
		textField_Mac_ZUC_128_Output.setColumns(10);
		
		textField_Mac_ZUC_256_Output = new JTextField();
		textField_Mac_ZUC_256_Output.setBounds(107, 104, 384, 21);
		panel_1.add(textField_Mac_ZUC_256_Output);
		textField_Mac_ZUC_256_Output.setEditable(false);
		textField_Mac_ZUC_256_Output.setColumns(10);
		
		textField_Mac_ZUC_256_32_Output = new JTextField();
		textField_Mac_ZUC_256_32_Output.setBounds(107, 135, 384, 21);
		panel_1.add(textField_Mac_ZUC_256_32_Output);
		textField_Mac_ZUC_256_32_Output.setEditable(false);
		textField_Mac_ZUC_256_32_Output.setColumns(10);
		
		textField_Mac_ZUC_256_64_Output = new JTextField();
		textField_Mac_ZUC_256_64_Output.setBounds(107, 167, 384, 21);
		panel_1.add(textField_Mac_ZUC_256_64_Output);
		textField_Mac_ZUC_256_64_Output.setEditable(false);
		textField_Mac_ZUC_256_64_Output.setColumns(10);
		
		JTextField[] textFields_Mac = {textField_Mac_ZUC_128_Output, textField_Mac_ZUC_256_Output, textField_Mac_ZUC_256_32_Output, textField_Mac_ZUC_256_64_Output};
		JCheckBox[] checkBoxs_Mac = {chckbx_Mac_ZUC_128, chckbxMac_ZUC_256, chckbxMac_ZUC_256_32, chckbxMac_ZUC_256_64};
		String[] macAlgs = {"ZUC-128", "ZUC-256", "ZUC-256-32", "ZUC-256-64"};
		String[] macAlgsType = {"ZUC-128", "ZUC-256", "ZUC-256", "ZUC-256"};
		int[] ivSize = {16, 25, 25, 25};
		JButton btnMacCacluate = new JButton("\u8BA1\u7B97");
		btnMacCacluate.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				// 清空输出
				for (JTextField textField : textFields_Mac) {
					textField.setText("");
				}
				// 判断类型
				if (comboBox_Mac.getSelectedIndex() == 0) {
					// 计算文件的Mac码
					String fileName = textField_MacInput.getText();
					fileName = fileName.replace('\\', '/');
					System.out.println(fileName);
					for (int i=0 ; i < checkBoxs_Mac.length; i++) {
					try (FileInputStream fis = new FileInputStream(fileName)){
						
							if (checkBoxs_Mac[i].isSelected()) {
								KeyGenerator keyGenerator = KeyGenerator.getInstance(macAlgsType[i], "BC");
								SecretKey secretKey = keyGenerator.generateKey();
								byte[] ivValue = new byte[ivSize[i]];
								SecureRandom random = new SecureRandom();
								random.nextBytes(ivValue);
								IvParameterSpec iv = new IvParameterSpec(ivValue);
								
								Mac mac = Mac.getInstance(macAlgs[i], "BC");
								mac.init(secretKey, iv);
								
									byte[] buffer = new byte[1024];
									int n = 0;
									while(fis.read(buffer) != -1) {
										mac.update(buffer, 0 ,n);
								}
							textFields_Mac[i].setText(Hex.toHexString(mac.doFinal()));						
							}
						}
					catch (FileNotFoundException e1) {
						e1.printStackTrace();
					} catch (IOException e1) {
						e1.printStackTrace();
					} catch (NoSuchAlgorithmException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					} catch (NoSuchProviderException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					} catch (InvalidKeyException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					} catch (InvalidAlgorithmParameterException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					}
					}
				
				} else {
					// 计算字符串的Mac码
					String s = textField_MacInput.getText();
						
						try {
							for (int i=0 ; i < checkBoxs_Mac.length; i++) {
								if (checkBoxs_Mac[i].isSelected()) {
									try {
										KeyGenerator keyGenerator = KeyGenerator.getInstance(macAlgsType[i], new BouncyCastleProvider());
										SecretKey secretKey = keyGenerator.generateKey();
										// 随机生成IV
										byte[] ivValue = new byte[ivSize[i]];
										SecureRandom random = new SecureRandom();
										random.nextBytes(ivValue);
										IvParameterSpec iv = new IvParameterSpec(ivValue);
										
										Mac mac = Mac.getInstance(macAlgs[i], "BC");
										mac.init(secretKey, iv);
										textFields_Mac[i].setText(Hex.toHexString(mac.doFinal(s.getBytes())));
									} catch (NoSuchAlgorithmException e1) {
										// TODO Auto-generated catch block
										e1.printStackTrace();
									}
								}
							}
						} catch (Exception e1) {
							// TODO Auto-generated catch block
							e1.printStackTrace();
						}

				}
			}
		});
		btnMacCacluate.setBounds(574, 103, 97, 52);
		panel_Mac.add(btnMacCacluate);
	}
		// 根据口令生成密钥
		private static SecretKeySpec passwordToKey(String password, int keySize) {
			MessageDigest md = null;
			try {
				md = MessageDigest.getInstance("SHA3-256");
			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			byte[] hashValue = md.digest(password.getBytes());
			SecretKeySpec key = new SecretKeySpec(hashValue, 0, keySize / 8, "AES");
			return key;
		}
		
		public static boolean verifyFile(String fileToVerify, PublicKey key, String signValueFile) throws Exception {
			// try-with-resource语句创建的流不需要手动关闭
			Security.addProvider(new BouncyCastleProvider());
			try (FileInputStream fisFileToVerify = new FileInputStream(fileToVerify);
					FileInputStream fisSignValueFile = new FileInputStream(signValueFile)) {
				// 创建数字签名对象
				Signature signature = Signature.getInstance("SM3withSM2");
				// 用公钥初始化数字签名对象，让它做签名验证工作
				signature.initVerify(key);
				// 将文件内容加载到数字签名对象上
				byte[] buffer = new byte[1024];
				int n = 0;
				while ((n = fisFileToVerify.read(buffer)) != -1) {
					signature.update(buffer, 0, n);
				}
				// 读取数字签名值
				byte[] signatureValue = new byte[fisSignValueFile.available()];
				fisSignValueFile.read(signatureValue);
				// 验证数字签名并返回验证结果
				return signature.verify(signatureValue);
			}
		}

		public static void signFile(String fileToSign, PrivateKey key, String signValueFile) throws Exception {
			// try-with-resource语句创建的流不需要手动关闭
			try (FileInputStream fis = new FileInputStream(fileToSign);
					FileOutputStream fos = new FileOutputStream(signValueFile)) {
				//创建数字签名对象
				Signature signature = Signature.getInstance("SM3withSM2");
				//用私钥初始化数字签名对象，让它做签名生成工作
				signature.initSign(key);
				// 将文件内容加载到数字签名对象上
				byte[] buffer = new byte[1024];
				int n = 0;
				while ((n = fis.read(buffer)) != -1) {
					signature.update(buffer, 0, n);
				}
				//计算数字签名值
				byte[] signaturValue = signature.sign();
				//存储数字签名值
				fos.write(signaturValue);
			}
		}
		
		public static String createKeyStore() throws Exception {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");
			ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec("secp256r1");
			keyPairGenerator.initialize(ecGenParameterSpec);
			KeyPair keyPair = keyPairGenerator.generateKeyPair();
			// 生成自签名数字证书
			String subjectDN = "CN = zhong OU = cauc O = cauc L = tj S = tj C = cn";
			String signatureAlgorithm = "SM3withSM2";
			Certificate certificate = selfSign(keyPair, subjectDN,
					signatureAlgorithm);		
			// 将密钥对（私钥和自签名数字证书）存入密钥库文件
			KeyStore keyStore = KeyStore.getInstance("pkcs12");
			char[] passWord = JOptionPane.showInputDialog("密钥库口令:").toCharArray();
			keyStore.load(null, passWord);
			keyStore.setKeyEntry("mysm2key", keyPair.getPrivate(), passWord,
					new Certificate[] { certificate });
			JFileChooser chooser = new JFileChooser("D:/");

			FileNameExtensionFilter filter = new FileNameExtensionFilter("密钥库文件(*.keystore)", "keystore");
			chooser.setFileFilter(filter);		
			String keyStorePath = null;
			File file = null;
			int option = chooser.showSaveDialog(null);
			if(option==JFileChooser.APPROVE_OPTION){	
				file = chooser.getSelectedFile();
				String fname = chooser.getName(file);	//从文件名输入框中获取文件名
				//假如用户填写的文件名不带我们制定的后缀名，那么我们给它添上后缀
				if(fname.indexOf(".keystore")==-1){
					file=new File(chooser.getCurrentDirectory(),fname+".keystore");
				}
				keyStorePath = file.getPath();
				FileOutputStream fos = new FileOutputStream(file);
				keyStore.store(fos, passWord);	
				JOptionPane.showMessageDialog(null, "密钥库创建成功");
			}
			return keyStorePath;
			
		}
		
		// 生成自签名数字证书
		public static Certificate selfSign(KeyPair keyPair, String subjectDN,
				String signatureAlgorithm) throws Exception {
			BouncyCastleProvider bcProvider = new BouncyCastleProvider();
			Security.addProvider(bcProvider);

			long now = System.currentTimeMillis();
			Date startDate = new Date(now);
			X500Name dnName = new X500Name(subjectDN);

			// Using the current time stamp as the certificate serial number
			BigInteger certSerialNumber = new BigInteger(Long.toString(now));

			Calendar calendar = Calendar.getInstance();
			calendar.setTime(startDate);
			calendar.add(Calendar.YEAR, 1); // <-- 1 Yr validity
			Date endDate = calendar.getTime();

			ContentSigner contentSigner = new JcaContentSignerBuilder(
					signatureAlgorithm).build(keyPair.getPrivate());

			JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
					dnName, certSerialNumber, startDate, endDate, dnName,
					keyPair.getPublic());

			// Extensions --------------------------
			// Basic Constraints true for CA, false for EndEntity
			BasicConstraints basicConstraints = new BasicConstraints(true);
			// Basic Constraints is usually marked as critical.
			certBuilder.addExtension(new ASN1ObjectIdentifier("2.5.29.19"), true,
					basicConstraints);

			return new JcaX509CertificateConverter().setProvider(bcProvider)
					.getCertificate(certBuilder.build(contentSigner));
		}

}
