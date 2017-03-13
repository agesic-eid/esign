package uy.com.agesic.firma;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.lang3.StringEscapeUtils;
import org.apache.tomcat.util.codec.binary.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

import com.gemalto.ics.rnd.egov.dss.sdk.create.api.RequestBuilderImpl;
import com.gemalto.ics.rnd.egov.dss.sdk.create.key.JCAKeyStoreSignatureKeyService;
import com.gemalto.ics.rnd.egov.dss.sdk.create.model.pades.VisibleSignature;
import com.gemalto.ics.rnd.egov.dss.sdk.create.signature.XmlDSigRequestSigner;

import groovy.lang.Grab;

@Grab("org.webjars:jquery:2.0.3-1")

@Controller
public class RequestDSSController {

	@RequestMapping(value = "/upload", method = RequestMethod.POST)
	public String handleFileUpload(@RequestParam("file") MultipartFile file, Model model) {

		String name = file.getOriginalFilename();

		if (!file.isEmpty()) {
			try {

				byte[] bytes = file.getBytes();

				BufferedOutputStream stream = new BufferedOutputStream(
						new FileOutputStream(new File("/Library/Tomcat/apache-tomcat-8.5.11/temp/" + name)));
				stream.write(bytes);
				stream.close();

				/*
				 * Inicio código del DSS
				 */

				Security.addProvider(new BouncyCastleProvider());
				InputStream ks = new FileInputStream(
						"/Users/rodrigo/Documents/AGESIC/Develop/TestDSSFiles/client-keystore.p12");
				JCAKeyStoreSignatureKeyService jcaKeyStoreSignatureKeyService = new JCAKeyStoreSignatureKeyService("BC",
						"PKCS12", ks, "123456", "sp-signing-key");

				XmlDSigRequestSigner xmlDSigRS = new XmlDSigRequestSigner();
				xmlDSigRS.setDigestMethod("http://www.w3.org/2001/04/xmlenc#sha256");
				xmlDSigRS.setSignatureMethod("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");

				RequestBuilderImpl requestBuilder = new RequestBuilderImpl(jcaKeyStoreSignatureKeyService, xmlDSigRS,
						"plataformafirma", "http://plataformafirma.gub.uy:8080/respuestaDSS");
				requestBuilder.setSignatureMethods(Collections.singletonList("SmartCard"));

				String requestData = "";

				String requestId = ""; // identifier of OASIS DSS request
				/* Generación de numero aleatorio */
				SecureRandom secureRandom = new SecureRandom();
				double random = secureRandom.nextDouble();
				requestId = "" + random;

				String targetURL = "https://test-eid.portal.gub.uy/dss/dss/post";

				// requestData = requestBuilder.buildCMSSignRequest(requestId,
				// "Texto a
				// firmar para el taller.".getBytes(), true);

				Path path = Paths.get("/Library/Tomcat/apache-tomcat-8.5.11/temp/" + name);
				byte[] documento = Files.readAllBytes(path);

				Map<String, byte[]> signedAttributes = new HashMap<String, byte[]>(); // Atributos

				String signatureForm = "urn:oasis:names:tc:dss:1.0:profiles:AdES:forms:BES";

				VisibleSignature vSignature = new VisibleSignature();
				requestData = requestBuilder.buildPAdESBasicSignRequest(requestId, documento, signedAttributes,
						signatureForm, vSignature);

				String newRequestData = StringEscapeUtils
						.escapeHtml4(Base64.encodeBase64String(requestData.getBytes("UTF-8")));

				model.addAttribute("requestData", newRequestData);
				model.addAttribute("targetURL", targetURL);

				return "sign";

				/*
				 * fin del código del DSS
				 */
			} catch (Exception e) {
				return "La carga del archivo falló" + " => " + e.getMessage();
			}
		} else {
			return "La carga del archivo falló porque estaba vacía";
		}
	}
}
