package uy.com.agesic.firma;

public class DocumentSignException extends Exception {

    public DocumentSignException(String message) {
        super(message);
    }

    public DocumentSignException(String message, Throwable cause) {
        super(message, cause);
    }
}
