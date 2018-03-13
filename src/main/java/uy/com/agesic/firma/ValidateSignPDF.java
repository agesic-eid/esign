package uy.com.agesic.firma;

import java.security.Security;
import java.security.cert.X509Certificate;
import javax.security.auth.x500.X500Principal;
import java.util.ArrayList;
import java.util.Date;


import java.io.IOException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.servlet.http.HttpServletRequest;

import org.apache.tika.Tika;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.itextpdf.text.pdf.AcroFields;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.security.PdfPKCS7;

public class ValidateSignPDF {
	
	@Value("${validate.certificateAuthorityMICA}")
	private String certificateAuthorityMICA;

	@Value("${validate.certificateAuthorityAbitab}")
	private String certificateAuthorityAbitab;

	@Value("${validate.certificateAuthorityCorreo}")
	private String certificateAuthorityCorreo;

	@Value("${validate.certificateAuthorityRevocationsMICA}")
	private String certificateAuthorityRevocationsMICA;

	@Value("${validate.certificateAuthorityRevocationsAbitab}")
	private String certificateAuthorityRevocationsAbitab;

	@Value("${validate.certificateAuthorityRevocationsCorreo}")
	private String certificateAuthorityRevocationsCorreo;

	private final Logger log = LoggerFactory.getLogger(this.getClass());

	public String[][] verifyDigitalSignature(byte[] document, boolean checkNonRepudiation, Date date) throws Exception {

		try {
			PdfReader reader = new PdfReader(document);
			AcroFields af = reader.getAcroFields();
			ArrayList names = af.getSignatureNames();
			String certificateAuthorityPath="Vacio";
			String certificateAuthorityRevocationsPath="Vacio";
			if (names.size() > 0) {
				Security.addProvider(new BouncyCastleProvider());

				// defino el arreglo de nombres
				String[][] certnames = new String[names.size()][2];
				for (int iterator = 0; iterator < names.size(); iterator++) {
					String name = (String) names.get(iterator);
					
					certnames[iterator][1] = null;
					PdfPKCS7 pk = af.verifySignature(name);
					X509Certificate cert = pk.getSigningCertificate();
					String caIssuer = cert.getIssuerX500Principal().toString();
					
					if (caIssuer.contains("Ministerio del Interior")) {
						log.info("------ Seee boludo, es del Ministerio del Interior --------");
						certificateAuthorityPath = certificateAuthorityMICA;
						certificateAuthorityRevocationsPath = certificateAuthorityRevocationsMICA;
					}
					else if(caIssuer.contains("Abitab")) {
						log.info("------ Seee boludo, es de Abitab --------");
						certificateAuthorityPath = certificateAuthorityAbitab;
						certificateAuthorityRevocationsPath = certificateAuthorityRevocationsAbitab;
					}
					else if(caIssuer.contains("Correo")) {
						log.info("------ Seee boludo, es del Correo --------");
						certificateAuthorityPath = certificateAuthorityCorreo;
						certificateAuthorityRevocationsPath = certificateAuthorityRevocationsCorreo;
					}
					log.info(certificateAuthorityPath+ " -- "+ certificateAuthorityRevocationsPath);
					log.info(certificateAuthorityMICA+ " -- "+ certificateAuthorityRevocationsMICA);
					DefaultVerifierKeyStoreStrategy defverifier = new DefaultVerifierKeyStoreStrategy(
							certificateAuthorityPath, certificateAuthorityRevocationsPath, "", true, date);

					certnames[iterator][0] = cert.getSubjectDN().toString();
					if (pk.verify()) {
						// The document has been validated using embedded
						// certificate signer.
						// We must ensure the validity of the signer's
						// certificate.
						try {
							defverifier.verifyCertificate(cert);
							// solo la ultima firma tiene que cubrir todo el
							// documento
							if ((iterator + 1) == names.size()) {
								if (!af.signatureCoversWholeDocument(name)) {
									throw new DocumentSignException("Documento corrupto");
								}
							}
						} catch (Exception ex) {
							certnames[iterator][1] = ex.getMessage();
						}
					} else {
						certnames[iterator][1] = "-1";
					}
				}
				return certnames;
			} else {
				throw new DocumentSignException("No se encontró un elemento de firma");
			}
		} catch (DocumentSignException ex) {
			throw ex;
		} catch (Exception ex) {
			throw new DocumentSignException("El documento está corrupto");
		}
	}
}
