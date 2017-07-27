package uy.com.agesic.firma;

//import configuration.Configuration;
import uy.com.agesic.firma.DocumentSignException;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;

public class DefaultVerifierKeyStoreStrategy{

    private String certificateAuthorityPath;
    private String certificateAuthorityRevocationsPath;
    private String signerCertificateFromCAPath;
    private boolean checkNonRepudiation;
    // truststore support
    private boolean usesTrustStore;
    private String certificateAuthorityTrustStorePassword;
    private String certificateAuthorityTrustStoreAlias;
    private Date date;

    public DefaultVerifierKeyStoreStrategy(String certificateAuthorityPath, String certificateAuthorityRevocationsPath,
            String signerCertificateFromCAPath, boolean checkNonRepudiation, Date date) {
        this.certificateAuthorityPath = certificateAuthorityPath;
        this.signerCertificateFromCAPath = signerCertificateFromCAPath;
        this.certificateAuthorityRevocationsPath = certificateAuthorityRevocationsPath;
        this.checkNonRepudiation = checkNonRepudiation;

        // truststore support
        this.usesTrustStore = false;

        Calendar cal1950 = new GregorianCalendar(1950, 1, 1);
        if (date.getTime() < cal1950.getTimeInMillis()) {
            this.date = null;
        } else {
            this.date = date;
        }
    }

    public DefaultVerifierKeyStoreStrategy(String certificateAuthorityTrustStorePath, String certificateAuthorityTrustStorePassword,
            String certificateAuthorityTrustStoreAlias, String certificateAuthorityRevocationsPath,
            String signerCertificateFromCAPath, boolean checkNonRepudiation, Date date) {
        this.certificateAuthorityPath = certificateAuthorityTrustStorePath;
        this.signerCertificateFromCAPath = signerCertificateFromCAPath;
        this.certificateAuthorityRevocationsPath = certificateAuthorityRevocationsPath;
        this.checkNonRepudiation = checkNonRepudiation;

        // truststore support
        this.usesTrustStore = true;
        this.certificateAuthorityTrustStorePassword = certificateAuthorityTrustStorePassword;
        this.certificateAuthorityTrustStoreAlias = certificateAuthorityTrustStoreAlias;

        Calendar cal1950 = new GregorianCalendar(1950, 1, 1);
        if (date.getTime() < cal1950.getTimeInMillis()) {
            this.date = null;
        } else {
            this.date = date;
        }
    }

    public final Certificate getSignerCertificateFromCA() throws DocumentSignException {
        return getCertificate(signerCertificateFromCAPath);
    }

    public final void verifyCertificate(Certificate signerCertificate) throws DocumentSignException {
        if (signerCertificate != null) {
            verifyX509Certificate((X509Certificate) signerCertificate);
        } else {
        	//No se ha definido un certificado
            throw new DocumentSignException("0");
        }
    }


    //********************************************************************************//
    //                            AUXILIARY FUNCTIONS                                 //
    //********************************************************************************//
    @SuppressWarnings("deprecation")
	private void verifyX509Certificate(X509Certificate signerCertificate) throws DocumentSignException {

        // Check if the certificate is signed by the Certificate Authority
        Certificate caCert;
        try {
            ////////// TODO : TrustStore
            if(usesTrustStore){
                caCert = getCertificateFromKeyStore(certificateAuthorityPath, certificateAuthorityTrustStorePassword, certificateAuthorityTrustStoreAlias);
            } else {
                caCert = getCertificate(certificateAuthorityPath);
            }
            
            signerCertificate.verify(caCert.getPublicKey());
            
        } catch (Exception ex) {
        	//El certificado no ha sido firmado por la Autoridad Certificadora
            throw new DocumentSignException("1", ex.getCause());
        }

        Certificate certFromCA = getSignerCertificateFromCA();
        boolean equals = signerCertificate.equals(certFromCA);
        if (certFromCA == null || equals) {
            /*
             * <pre>
             * KeyUsage ::= BIT STRING {
             *     digitalSignature        (0),
             *     nonRepudiation          (1),
             *     keyEncipherment         (2),
             *     dataEncipherment        (3),
             *     keyAgreement            (4),
             *     keyCertSign             (5),
             *     cRLSign                 (6),
             *     encipherOnly            (7),
             *     decipherOnly            (8) }
             * </pre>
             */
            boolean digitalSignature, nonRepudiation;
            try {
                digitalSignature = signerCertificate.getKeyUsage()[0];
                nonRepudiation = signerCertificate.getKeyUsage()[1];
            } catch (Exception ex) {
                digitalSignature = false;
                nonRepudiation = false;
            }

            if (digitalSignature && (!checkNonRepudiation || nonRepudiation)) {
                // Check if the certificate is revoked
                if (!isRevoke(caCert, signerCertificate)) {
                    // Check certificate validity period
                    try {
                        if (date != null) {
                        	Date validity = signerCertificate.getNotBefore();
                        	this.date.setHours(validity.getHours());
                        	this.date.setMinutes(validity.getMinutes());
                        	this.date.setSeconds(validity.getSeconds());
                            signerCertificate.checkValidity(date);
                        } else {
                            signerCertificate.checkValidity();
                        }
                    } catch (Exception ex) {
                    	//El período del certificado no es válido
                        throw new DocumentSignException("5", ex.getCause());
                    }
                } else {
                	//El certificado fue revocado
                    throw new DocumentSignException("4");
                }
            } else {
            	//El certificado no fue emitido para firmar
                throw new DocumentSignException("3");
            }
        } else {
        	//El certificado embebido en el documento no es el mismo que el dado por la Autoridad Certificadora
            throw new DocumentSignException("2");
        }
    }

    /**
     * The method checks if a given cetificate is revoked.
     * It analyzes the revoked list of the Certificate Authority.
     *
     * @param certificate. The certificate to be checked.
     * @return true if the certificate is revoked.
     */
    protected boolean isRevoke(Certificate caCert, X509Certificate certificate) {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            FileInputStream fis = new FileInputStream(certificateAuthorityRevocationsPath);
            X509CRL crl = (X509CRL) cf.generateCRL(fis);
            fis.close();
            return crl.isRevoked(certificate);
        } catch (Exception ex) {
            return true;
        }
    }

    protected Certificate getCertificate(String path) throws DocumentSignException {
        if (path == null || path.trim().equals("")) {
            return null;
        } else {
            FileInputStream fis = null;
            try {
                fis = new FileInputStream(path);
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                return (X509Certificate) cf.generateCertificate(fis);
            } catch (Exception ex) {
                try {
                    if (fis != null) {
                        fis.close();
                    }
                } catch (Exception ex2) { }
                throw new DocumentSignException("Error al obtener el certificado", ex.getCause());
            }
        }
    }

 

    protected final Certificate getCertificateFromKeyStore(String trustStorePath, String trustStorePass, String trusStoreAlias) throws DocumentSignException {
        KeyStore keyStore;
        try {
            keyStore = KeyStore.getInstance("JKS");
            FileInputStream privateKeyStream = new FileInputStream(trustStorePath);
            char password[] = trustStorePass.toCharArray();
            keyStore.load(privateKeyStream, password);
            privateKeyStream.close();

            return keyStore.getCertificate(trusStoreAlias);
        } catch (Exception ex) {
            try {
                keyStore = KeyStore.getInstance("PKCS12");
                FileInputStream privateKeyStream = new FileInputStream(trustStorePass);
                char password[] = trustStorePass.toCharArray();
                keyStore.load(privateKeyStream, password);
                privateKeyStream.close();

                return keyStore.getCertificate(trusStoreAlias);
            } catch (IOException exe) {
                throw new DocumentSignException("El archivo no se puede abrir con esta contraseña", exe.getCause());
            } catch (Exception exep) {
                throw new DocumentSignException("Error al abrir el almacén de claves", exep.getCause());
            }
        }
    }
}
