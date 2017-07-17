package com.signer.crypto;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;

public final class P7Generator {

	private final String KEYSTORE = "/WEB-INF/teste.jks";
	private final String ALIAS_NAME = "signer";
	private final String PASSWORD = "serasa@123";
	private final String ALGORYTHM = "SHA256withRSA";

	public P7Generator() {
	}

	public KeyStore loadKeyStore() throws Exception {
		KeyStore keystore = KeyStore.getInstance("JKS");
		InputStream is = P7Generator.class.getClassLoader().getResourceAsStream(KEYSTORE);
		keystore.load(is, PASSWORD.toCharArray());
		return keystore;
	}

	public CMSSignedDataGenerator setUpProvider(final KeyStore keystore) throws Exception {

		Security.addProvider(new BouncyCastleProvider());

		Certificate[] certchain = (Certificate[]) keystore.getCertificateChain(ALIAS_NAME);

		final List<Certificate> certlist = new ArrayList<Certificate>();

		for (int i = 0, length = certchain == null ? 0 : certchain.length; i < length; i++) {
			certlist.add(certchain[i]);
		}

		@SuppressWarnings("rawtypes")
		Store certstore = new JcaCertStore(certlist);

		Certificate cert = keystore.getCertificate(ALIAS_NAME);

		ContentSigner signer = new JcaContentSignerBuilder(ALGORYTHM).setProvider("BC")
				.build((PrivateKey) (keystore.getKey(ALIAS_NAME, PASSWORD.toCharArray())));

		CMSSignedDataGenerator generator = new CMSSignedDataGenerator();

		generator.addSignerInfoGenerator(
				new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider("BC").build())
						.build(signer, (X509Certificate) cert));

		generator.addCertificates(certstore);

		return generator;
	}

	public byte[] signPkcs7(final byte[] content, final CMSSignedDataGenerator generator) throws Exception {

		CMSTypedData cmsdata = new CMSProcessableByteArray(content);
		CMSSignedData signeddata = generator.generate(cmsdata, true);
		return signeddata.getEncoded();
	}
}