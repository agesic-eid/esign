package uy.com.agesic.firma;

import java.io.IOException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.servlet.http.HttpServletRequest;

import org.apache.tika.Tika;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

@Controller
public class ValidateController {

	/*
	 * Validate PDF configuration parameters
	 */

	@Value("${validate.certificateAuthority}")
	private String certificateAuthority;

	@Value("${validate.certificateAuthorityRevocations}")
	private String certificateAuthorityRevocations;

	private final Logger log = LoggerFactory.getLogger(this.getClass());

	@RequestMapping(value = "/validate", method = RequestMethod.POST)
	public String handleFileUpload(@RequestParam("file") MultipartFile file, @RequestParam("date") String date, HttpServletRequest request, Model model) {
		
		//verifico que no este vacío
		if (!file.isEmpty()) {
			
			//Convierto el archivo a un arreglo de bytes 
			try {
				byte[] documento = file.getBytes();
				
				//Verifico que sea un PDF
				Tika tika = new Tika();
				if (tika.detect(documento).equals("application/pdf")){
					
					//Verifico que el texto sea una fecha
					try {
						Date dateverifi = new SimpleDateFormat("dd/MM/yyyy").parse(date);
						
						ValidateSignPDF validate = new ValidateSignPDF();
						
						//Valido el documento
						try{
							String[][] docvalido = validate.verifyDigitalSignature(documento, certificateAuthority, certificateAuthorityRevocations, true, dateverifi);
							
							//verifico que no hayan errores
							boolean hayerror = false;
							
							for (int i=0; i < docvalido.length; i++){
								
								if (docvalido[i][1] != null){
									hayerror = true;
								}
							}
							
							if(!hayerror){
								log.info("EL PDF ES VALIDO");
								return "valido";
							}else{
								log.info("ERROR EN ALGUN CERTIFICADO");
								
								//creo arreglo de chequeos
								String[] checks = new String[6];
								checks[0] = "Certificado definido";
								checks[1] = "Certificado firmado por la Autoridad Certificadora";
								checks[2] = "Certificado embebido en el documento corresponde con el dado por la Autoridad Certificadora";
								checks[3] = "Certificado emitido para firmar";
								checks[4] = "Certificado aprobado (no revocado)";
								checks[5] = "Período del certificado";
								
								//parseo los nombres de los certificados
								String pattern = "CN=[^,]+";
								// Creo al Pattern object
								Pattern r = Pattern.compile(pattern);
								for (int i=0; i < docvalido.length; i++){
									String nombre = docvalido[i][0];
									// creo el matcher object.
									Matcher m = r.matcher(nombre);
									if (m.find( )) {
										docvalido[i][0] = m.group(0).split("=")[1];
									}
								}
								
								model.addAttribute("checks",checks);
								model.addAttribute("erroresdoc",docvalido);
								return "error";
							}
						//error generico	
						}catch (Exception e){
							log.info("ERROR GENERICO DEL VERIFYDIGITALSIGNATURE");
							model.addAttribute("error", e.getMessage());
							return "error";
						}
					} catch (ParseException e1) {
						log.info("FECHA INVALIDA");
						model.addAttribute("error", "Debes ingresar una fecha valida");
						return "error";
					}
				}else {
					log.info("INTENTO SUBIR ARCHIVO DE OTRO TIPO");
					model.addAttribute("error", "Debes seleccionar un archivo PDF para validar");
					return "error";
				}
			} catch (IOException e1) {
				log.info("INTENTO SUBIR ARCHIVO VACIO");
				model.addAttribute("error", "Debes seleccionar un archivo PDF para validar");
				return "error";
			}
			
		}else {
			log.info("INTENTO SUBIR ARCHIVO VACIO");
			model.addAttribute("error", "Debes seleccionar un archivo PDF para validar");
			return "error";
		}
		
	}
}
