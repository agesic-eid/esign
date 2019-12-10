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
	private String[] pathCa = new String[3];
	private String[] pathCrl = new String[3];
	
	@Value("${validate.certificateAuthority}")
	private String certificateAuthority;	
	
	@Value("${validate.certificateAuthority1}")
	private String certificateAuthority1;
	
	@Value("${validate.certificateAuthority2}")
	private String certificateAuthority2;

	@Value("${validate.certificateAuthorityRevocations}")
	private String certificateAuthorityRevocations;
	
	@Value("${validate.certificateAuthorityRevocations1}")
	private String certificateAuthorityRevocations1;
	
	@Value("${validate.certificateAuthorityRevocations2}")
	private String certificateAuthorityRevocations2;
	
	private final Logger log = LoggerFactory.getLogger(this.getClass());
	
	@RequestMapping(value = "/validate", method = RequestMethod.POST)
	public String handleFileUpload(@RequestParam("file") MultipartFile file, @RequestParam("date") String date, HttpServletRequest request, Model model) 
	{		
		pathCa[0] = certificateAuthority;
		pathCa[1] = certificateAuthority1;		
		pathCa[2] = certificateAuthority2;
		pathCrl[0] = certificateAuthorityRevocations;
		pathCrl[1] = certificateAuthorityRevocations1;
		pathCrl[2] = certificateAuthorityRevocations2;
		
		
		if (!file.isEmpty())  			//Verifico que no este vacío
		{	
			try 
			{
				byte[] documento = file.getBytes(); 	// Convierto el archivo a un arreglo de bytes 
				
				
				Tika tika = new Tika(); 				// Verifico que sea un PDF
				if (tika.detect(documento).equals("application/pdf"))
				{			
					
					try  								//Verifico que el texto sea una fecha
					{
						Date dateverifi = new SimpleDateFormat("dd/MM/yyyy").parse(date);
						
						String resultado = validarIndividual(documento,dateverifi, model);	
						if (resultado == "valido") 
						{     
							return "valido";
						}
						else 
						{
							return "error";
						}
						
					} catch (ParseException e1) 
					{
						log.info("| Error | Fecha inválida");
						model.addAttribute("error", "Debes ingresar una fecha valida");
						return "error";
					}
				}else 
				{
					log.info("| Error | Documento no es PDF");
					model.addAttribute("error", "Debes seleccionar un archivo PDF para validar");
					return "error";
				}
			} catch (IOException e1) 
			{
				log.info("| Error | Documento está vacío");
				model.addAttribute("error", "Debes seleccionar un archivo PDF para validar");
				return "error";
			}	
		}else 
		{
			log.info("| Error | Documento está vacío");
			model.addAttribute("error", "Debes seleccionar un archivo PDF para validar");
			return "error";
		}
		
	}

	public String validarIndividual(byte[] documento, Date dateverifi, Model model)  	//Valido el documento
	{ 
		try
		{
			String[] checks = new String[6]; 		//Creo arreglo de chequeos
			checks[0] = "Certificado definido";
			checks[1] = "Está firmado por una Autoridad Certificadora reconocida de confianza";
			checks[2] = "Certificado embebido en el documento corresponde con el dado por la Autoridad Certificadora";
			checks[3] = "Certificado emitido para firmar";
			checks[4] = "Certificado aprobado (no revocado)";
			checks[5] = "Período del certificado";
			
			ValidateSignPDF validate = new ValidateSignPDF();
			String[][] docvalido = validate.verifyDigitalSignature(documento, pathCa, pathCrl, true, dateverifi);	
			boolean hayerror = false;			//Verifico que no hayan errores
			for (int i=0; i < docvalido.length; i++)
			{	
				if (docvalido[i][1] != null) hayerror = true;
			}
			if(!hayerror)
			{
				log.info("| validarIndividual | Documento válido");;
				String pattern = "CN=[^,]+"; 			// Parseo los nombres de los certificados		
				Pattern r = Pattern.compile(pattern); 	// Creo al Pattern object
				for (int i=0; i < docvalido.length; i++)
				{
					String nombre = docvalido[i][0];
					Matcher m = r.matcher(nombre); 		// Creo el matcher object.
					
					if ( m.find() ) docvalido[i][0] = m.group(0).split("=")[1];
				}
				
				model.addAttribute("checks",checks);
				model.addAttribute("erroresdoc",docvalido);
				return "valido";
			} 
			else
			{
				log.info("| validarIndividual Error | Error en algún certificado");
							
				String pattern = "CN=[^,]+"; 			// Parseo los nombres de los certificados		
				Pattern r = Pattern.compile(pattern); 	// Creo al Pattern object
				for (int i=0; i < docvalido.length; i++)
				{
					String nombre = docvalido[i][0];
					Matcher m = r.matcher(nombre); 		// Creo el matcher object.
					
					if ( m.find() ) docvalido[i][0] = m.group(0).split("=")[1];
				}
				
				model.addAttribute("checks",checks);
				model.addAttribute("erroresdoc",docvalido);
				return "error";
			}		
		} 
		catch (Exception e) 		//Error genérico
		{
			log.info("| validarIndividual Error | Error genérico VerifyDigitalSignature ");
			model.addAttribute("error", e.getMessage());
			return "error";
		}
	}
}
