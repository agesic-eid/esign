package uy.com.agesic.firma;

import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.itextpdf.text.pdf.AcroFields;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.security.PdfPKCS7;

public class ValidateSignPDF 
{
	private final Logger log = LoggerFactory.getLogger(this.getClass());
	
	public String[][] verifyDigitalSignature(byte[] document, String[] pathCa, String[] pathCrl, boolean checkNonRepudiation, Date date) throws Exception 
	{
		try 
		{
			PdfReader reader = new PdfReader(document);
			AcroFields af = reader.getAcroFields();
			ArrayList names = af.getSignatureNames();

			if (names.size() > 0) 
			{
				Security.addProvider(new BouncyCastleProvider()); 		
				String[][] certnames = new String[names.size()][2]; 		// Defino el arreglo de nombres
				
				for (int iterator = 0; iterator < names.size(); iterator++) 
				{
					String name = (String) names.get(iterator);
					certnames[iterator][1] = null;
					PdfPKCS7 pk = af.verifySignature(name);
					X509Certificate cert = pk.getSigningCertificate();
					String[] paths = cargarPaths(pathCa, pathCrl, cert.getIssuerDN()+"");
					DefaultVerifierKeyStoreStrategy defverifier = new DefaultVerifierKeyStoreStrategy(paths[0], paths[1], "", true, date) ;
					certnames[iterator][0] = cert.getSubjectDN().toString();
					
					if (pk.verify()) 
					{
						// The document has been validated using embedded certificate signer.
						// We must ensure the validity of the signer's certificate.
						try 
						{
							defverifier.verifyCertificate(cert);
							// Sólo la ultima firma tiene que cubrir todo el documento
							if ((iterator + 1) == names.size()) 
							{
								if (!af.signatureCoversWholeDocument(name)) 
								{
									log.info("| Error | Documento corrupto");
									throw new DocumentSignException("Documento corrupto");
								}
							}
						} catch (Exception ex) 
						{
							certnames[iterator][1] = ex.getMessage();
						}
					} else 
					{
						certnames[iterator][1] = "-1";
					}
				}
				
				return certnames;
			
			} else 
			{
				log.info("| Error | No se encontró firma");
				throw new DocumentSignException("No se encontró un elemento de firma");
			}
		} catch (DocumentSignException ex) 
		{
			throw ex;
		} catch (Exception ex) 
		{
			log.info("| Error | Documento corrupto");
			throw new DocumentSignException("El documento está corrupto");
		}
	}
	
	String[] cargarPaths (String[] ca, String[] crl, String issuer) 
	{		
		log.info("| cargarPath | Issuer {} ", issuer);
		
		String[] paths = new String[2];
		if (issuer.equals("CN=Autoridad Certificadora del Ministerio del Interior,O=Ministerio del Interior,C=UY")) 
		{
			paths[0] = ca[0];
			paths[1] = crl[0];
		}else if (issuer.equals("CN=Correo Uruguayo - CA,O=Administración Nacional de Correos,C=UY")) 
		{
			paths[0] = ca[1];
			paths[1] = crl[1];
		}else if (issuer.equals("C=UY,L=Montevideo,O=Abitab S.A.,OU=ID digital,CN=Abitab")) 
		{
			paths[0] = ca[2];
			paths[1] = crl[2];
		}
		else
		{
			log.info("| cargarPath Error | No está firmado por una Autoridad Certificadora reconocida de confianza");
		}
		log.info("| cargarPath | CA path {} , CRL path {}", paths[0], paths[1]);		
		return paths;	
	}

}

//log.info(cert.getIssuerDN()+"-----");  //Esto imprime CN=Autoridad Certificadora del Ministerio del Interior,O=Ministerio del Interior,C=UY por ejemplo
//log.info(cert.toString()+"-----");   // Esto imprime todo el certificado
// log.info(certnames[iterator][0] + "---1---"); // imprime C=UY,SERIALNUMBER=DNI99999999,CN=***TEST NOMBRE NOMBRE ***TEST APELLIDO APELLIDO---1--
