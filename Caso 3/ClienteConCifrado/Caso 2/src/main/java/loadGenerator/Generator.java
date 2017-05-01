package loadGenerator;

import java.util.concurrent.TimeUnit;

import uniandes.gload.core.LoadGenerator;
import uniandes.gload.core.Task;

public class Generator {
	
	private LoadGenerator generator;
	
	
	public Generator(int numberOfTasks, int gapBetweenTasks){
		
		Task work = createTask();
		
		generator = new LoadGenerator("Prueba de carga del cliente con cifrado", numberOfTasks, work, gapBetweenTasks);
		generator.generate();
	}
	
	public Task createTask(){
		return new ClientServerTask();
	}

	public static void main(String... args) {

		int numberOfTasks = 80;
		int gapBetweenTasks = 100;
		
		@SuppressWarnings("unused")
		Generator gen = new Generator(numberOfTasks, gapBetweenTasks);
		try{
			TimeUnit.MILLISECONDS.sleep(numberOfTasks*gapBetweenTasks + 5000);
		}
		catch (InterruptedException e){
			
		}
		
//		int count = 0;
//		System.out.println("tiempo de autenticacion de un servidor");
//		for(Long t: ClientServerTask.tAuthServ){
//			System.out.println(count + " " + t);
//			count++;
//		}
//		count = 0;
//		System.out.println("tiempo de respuesta");
//		for(Long t: ClientServerTask.tAuthServ){
//			System.out.println(count + " " + t);
//			count++;
//		}
		
	}
}
