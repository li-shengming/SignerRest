package com.signer.rest;

import java.security.KeyStore;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.core.Response;

import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.util.encoders.Base64;

import com.signer.crypto.P7Generator;

@Path("/sign")
public class SignerService {
	private static final String header = "-----BEGIN PKCS7-----";
	private static final String footer = "-----END PKCS7-----";

	@GET
	@Path("/{param}")
	public Response getP7(@PathParam("param") String conteudo) throws Exception {
		P7Generator signer = new P7Generator();
		KeyStore keyStore = signer.loadKeyStore();
		CMSSignedDataGenerator signatureGenerator = signer.setUpProvider(keyStore);
		byte[] signedBytes = signer.signPkcs7(conteudo.getBytes("UTF-8"), signatureGenerator);
		String signed = new String(Base64.encode(signedBytes));
		String parsedStr = signed.replaceAll("(.{64})", "$1\n");
		String pkcs7 = header + "\n" + parsedStr + "\n" + footer;
		return Response.status(200).entity(pkcs7).build();
	}

}
