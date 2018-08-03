package uy.com.agesic.firma;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Security;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.apache.tomcat.util.codec.binary.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

import com.gemalto.ics.rnd.egov.dss.sdk.verify.DSSResult;
import com.gemalto.ics.rnd.egov.dss.sdk.verify.DSSResultSuccess;
import com.gemalto.ics.rnd.egov.dss.sdk.verify.api.DefaultResponseParserFactory;
import com.gemalto.ics.rnd.egov.dss.sdk.verify.api.ResponseParser;
import com.gemalto.ics.rnd.egov.dss.sdk.verify.signature.JCAKeyStoreTrustStore;

import uy.com.agesic.firma.datatype.UploadedFile;

@Controller
public class ResponseDSSController {

	/*
	 * DSS response configuration parameters
	 */
	@Value("${dss.signed.document.path}")
	private String signedDocumentPath;

	/*
	 * DSS TrustStore configuration parameters
	 */
	@Value("${truststore.route}")
	private String trustStoreRoute;

	@Value("${truststore.key}")
	private String trustStoreKey;

	@Value("${truststore.alias}")
	private String trustStoreAlias;

	private static final int BUFFER_SIZE = 4096;

	private final Logger log = LoggerFactory.getLogger(this.getClass());

	/**
	 * Method for handling signed response from the DSS server
	 */
	@RequestMapping(value = "/respuestaDSS", method = RequestMethod.POST)
	public String response(@RequestParam("SignResponse") String[] signResponse, HttpServletRequest request,
			HttpServletResponse response, Model model) throws IOException {

		String sessionId = request.getSession().getId();
		HttpSession session = request.getSession();
		Security.addProvider(new BouncyCastleProvider());
		InputStream ts = new FileInputStream(trustStoreRoute);
		JCAKeyStoreTrustStore trustStore = new JCAKeyStoreTrustStore("BC", "PKCS12", ts, trustStoreKey,trustStoreAlias);
		ResponseParser responseParser = DefaultResponseParserFactory.getResponseParser(trustStore, null);
		String signResponseBase64 = signResponse[0];
		String responseDocument = new String(Base64.decodeBase64(signResponseBase64));
		DSSResult result = responseParser.parseAndGetResult(responseDocument);
		String requestId = result.getRequestId();
		//UploadedFile uploadedFile = (UploadedFile) session.getAttribute(requestId);

		if (result instanceof DSSResultSuccess) {
			byte[] documento = ((DSSResultSuccess) result).getDocumentData();
			// Convertir arreglo de bytes en archivo
			//FileOutputStream salida = new FileOutputStream(signedDocumentPath + uploadedFile.getFileName());
			FileOutputStream salida = new FileOutputStream(signedDocumentPath + requestId + ".pdf");
			salida.write(documento);
			salida.close();
		}

		log.info("| Response | "+ sessionId + " Recibió el archivo del DSS");
		
		model.addAttribute("requestId",requestId);

		return "respuestaDSS";
	}

	/**
	 * Method for handling file download request from client
	 */
	@RequestMapping(value = "/download", method = RequestMethod.GET)
	public void download(@RequestParam("requestId") String requestId, HttpServletRequest request, HttpServletResponse response) throws IOException {

		String sessionId = request.getSession().getId();
		
		UploadedFile uploadedFile = (UploadedFile) request.getSession().getAttribute(requestId);

		// construct the complete absolute path of the file
		//String fullPath = signedDocumentPath + uploadedFile.getFileName();
		String fullPath = signedDocumentPath + requestId + ".pdf";
		File downloadFile = new File(fullPath);
		FileInputStream inputStream = new FileInputStream(downloadFile);

		// get absolute path of the application
		ServletContext context = request.getServletContext();
		
		// get MIME type of the file
		String mimeType = context.getMimeType(fullPath);
		if (mimeType == null) {
			// set to binary type if MIME mapping not found
			mimeType = "application/octet-stream";
		}

		// set content attributes for the response
		response.setContentType(mimeType);
		response.setContentLength((int) downloadFile.length());

		// set headers for the response
		String headerKey = "Content-Disposition";
		//String headerValue = String.format("attachment; filename=\"%s\"", uploadedFile.getOriginalFileName());
		String headerValue = String.format("attachment; filename=\"%s\"", requestId + ".pdf");
		response.setHeader(headerKey, headerValue);

		// get output stream of the response
		OutputStream outStream = response.getOutputStream();

		byte[] buffer = new byte[BUFFER_SIZE];
		int bytesRead = -1;

		// write bytes read from the input stream into the output stream
		while ((bytesRead = inputStream.read(buffer)) != -1) {
			outStream.write(buffer, 0, bytesRead);
		}

		inputStream.close();
		outStream.close();
		
		log.info("| Response | "+ sessionId + " Descargó el archivo");

		TimeSingleton.getInstance().setFirstTime();

		TimeSingleton.getInstance().setSecondTime();
		if (TimeSingleton.getInstance().getCurrentTime()[0] != null) {

			Long timeResult = (TimeSingleton.getInstance().getCurrentTime()[1]
					- TimeSingleton.getInstance().getCurrentTime()[0]) / 1000;
			log.info("| Response | "+ sessionId + " tardó " + timeResult + "s en firmar el PDF");
		}	
			
	}

}
