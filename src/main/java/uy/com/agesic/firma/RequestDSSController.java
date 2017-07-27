package uy.com.agesic.firma;

import java.io.FileInputStream;
import java.io.InputStream;
import java.security.Security;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Pattern;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.apache.commons.lang3.StringEscapeUtils;
import org.apache.tika.Tika;
import org.apache.tomcat.util.codec.binary.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.beans.factory.annotation.Value;
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

import uy.com.agesic.firma.datatype.UploadedFile;

@Controller
public class RequestDSSController {

	/*
	 * KeyStore configuration parameters
	 */

	@Value("${keystore.route}")
	private String keyStoreRoute;

	@Value("${keystore.key}")
	private String keyStoreKey;

	@Value("${keystore.alias}")
	private String keyStoreAlias;

	/*
	 * DSS request configuration parameters
	 */

	@Value("${dss.service.name}")
	private String dssServiceName;

	@Value("${dss.response.url}")
	private String dssResponseURL;

	@Value("${dss.target.url}")
	private String dssTargetURL;

	private final Logger log = LoggerFactory.getLogger(this.getClass());

	@RequestMapping(value = "/upload", method = RequestMethod.POST)
	public String handleFileUpload(@RequestParam("file") MultipartFile file, HttpServletRequest request, Model model) {

		String sessionId = request.getSession().getId();
		
		HttpSession session = request.getSession();

		TimeSingleton.getInstance().setFirstTime();

		log.info("IDENTIFICADOR DE SESION: " + sessionId);

		if (!file.isEmpty()) {
			try {

				// Detect file type, only pdf
				Tika tika = new Tika();
				try {
					if (!tika.detect(file.getBytes()).equals("application/pdf")) {
						log.info(sessionId + " NO SUBIO PDF");
						model.addAttribute("error", "Debes seleccionar un archivo tipo PDF");
						return "error";
					}
				} catch (Exception e) {
					log.info(sessionId + " NO PUDO SUBIR EL ARCHIVO");
					model.addAttribute("error", "Error al subir el archivo, intenta nuevamente");
					return "error";
				}

				log.info(sessionId + " SUBIO EL ARCHIVO CORRECTAMENTE");

				byte[] documento = file.getBytes();
				String uploadName = "";
				String originalName = file.getOriginalFilename();
				String[] splitName = originalName.split(Pattern.quote("."));

				for (int i = 0; i < splitName.length - 1; i++) {
					uploadName += splitName[i];
				}
				uploadName += "_firmado.pdf";

				Security.addProvider(new BouncyCastleProvider());
				InputStream ks = new FileInputStream(keyStoreRoute);
				JCAKeyStoreSignatureKeyService jcaKeyStoreSignatureKeyService = new JCAKeyStoreSignatureKeyService("BC",
						"PKCS12", ks, keyStoreKey, keyStoreAlias);

				XmlDSigRequestSigner xmlDSigRS = new XmlDSigRequestSigner();
				xmlDSigRS.setDigestMethod("http://www.w3.org/2001/04/xmlenc#sha256");
				xmlDSigRS.setSignatureMethod("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");

				RequestBuilderImpl requestBuilder = new RequestBuilderImpl(jcaKeyStoreSignatureKeyService, xmlDSigRS,
						dssServiceName, dssResponseURL);
				requestBuilder.setSignatureMethods(Collections.singletonList("SmartCard"));

				String requestData = "";

				// OASIS DSS request identifier
				String requestId = "";

				/* Generación de numero aleatorio para el request */
				requestId = UUID.randomUUID().toString();
				
				//Seteo en la web session
				UploadedFile uploadedFile = new UploadedFile(uploadName);
				session.setAttribute(requestId,uploadedFile);

				Map<String, byte[]> signedAttributes = new HashMap<String, byte[]>(); // Atributos

				String signatureForm = "urn:oasis:names:tc:dss:1.0:profiles:AdES:forms:BES";

				VisibleSignature vSignature = new VisibleSignature();
				requestData = requestBuilder.buildPAdESBasicSignRequest(requestId, documento, signedAttributes,
						signatureForm, vSignature);

				String newRequestData = StringEscapeUtils
						.escapeHtml4(Base64.encodeBase64String(requestData.getBytes("UTF-8")));

				model.addAttribute("requestData", newRequestData);
				model.addAttribute("targetURL", dssTargetURL);

				log.info(sessionId + " ENVIO REQUEST AL DSS");

				return "sign";

			} catch (Exception e) {
				log.info(sessionId + " NO PUDO SUBIR EL ARCHIVO");
				model.addAttribute("error", "Error al subir el archivo, intenta nuevamente");
				return "error";
			}
		} else {
			log.info(sessionId + " INTENTO SUBIR ARCHIVO VACIO");
			model.addAttribute("error", "Debes seleccionar un archivo PDF para firmar");
			return "error";
		}
	}
}
