package uy.com.agesic.firma;

import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.itextpdf.text.pdf.AcroFields;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.security.PdfPKCS7;


public class ValidateSignPDF {
	
	public String[][] verifyDigitalSignature(byte[] document,String certificateAuthorityPath, String certificateAuthorityRevocationsPath,
				boolean checkNonRepudiation, Date date) throws Exception{


		try {
            PdfReader reader = new PdfReader(document);
            AcroFields af = reader.getAcroFields();
            ArrayList names = af.getSignatureNames();
            if (names.size() > 0) {
                Security.addProvider(new BouncyCastleProvider());
                
                //defino el arreglo de nombres 
                String[][] certnames = new String[names.size()][2] ;
                
                for (int iterator = 0; iterator < names.size(); iterator++) {
                    String name = (String) names.get(iterator);
                    certnames[iterator][1] = null;

                    PdfPKCS7 pk = af.verifySignature(name);
                    X509Certificate cert = pk.getSigningCertificate();
                	DefaultVerifierKeyStoreStrategy defverifier = new DefaultVerifierKeyStoreStrategy(certificateAuthorityPath,certificateAuthorityRevocationsPath,"",true,date);
                    certnames[iterator][0] = cert.getSubjectDN().toString();
                    if (pk.verify()) {
                        // The document has been validated using embedded certificate signer.
                        // We must ensure the validity of the signer's certificate.
                    	try{
                    		defverifier.verifyCertificate(cert);
                    		//solo la ultima firma tiene que cubrir todo el documento
                    		if((iterator+1) == names.size()){
                    			if (!af.signatureCoversWholeDocument(name)) {
                    				throw new DocumentSignException("Documento corrupto");
                    			}
                    		}
                    	} catch(Exception ex){
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





