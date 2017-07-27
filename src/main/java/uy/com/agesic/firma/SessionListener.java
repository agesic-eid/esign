package uy.com.agesic.firma;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Enumeration;

import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpSessionEvent;
import javax.servlet.http.HttpSessionListener;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import uy.com.agesic.firma.datatype.UploadedFile;

@Component
public class SessionListener implements HttpSessionListener {
	
	@Value("${dss.signed.document.path}")
	private String signedDocumentPath;

	@Override
	public void sessionDestroyed(HttpSessionEvent event) {
		HttpSession session = event.getSession();

		Enumeration<String> e = session.getAttributeNames();
		while(e.hasMoreElements()){
			String name = e.nextElement();
			if (session.getAttribute(name) instanceof UploadedFile ) {
				// borrarlo si existe en el disco
				UploadedFile uploadedFile = (UploadedFile) session.getAttribute(name);
				Path path = Paths.get(signedDocumentPath + uploadedFile.getFileName());
				try {
					Files.deleteIfExists(path);
				} catch (IOException e1) {
					//sino lo encuentro no hago nada
				}
			}
		}
	}

	@Override
	public void sessionCreated(HttpSessionEvent arg0) {
		// TODO Auto-generated method stub
		
	}

}
