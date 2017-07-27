package uy.com.agesic.firma.datatype;

import java.util.UUID;

public class UploadedFile {
	
	private String originalFileName;
	private String fileName;
	
	public UploadedFile(String originalFileName){
		this.originalFileName = originalFileName;
		this.fileName = UUID.randomUUID().toString();
	}
	
	public String getOriginalFileName(){
		return this.originalFileName;
	}
	
	public String getFileName(){
		return this.fileName;
	}
	
}
