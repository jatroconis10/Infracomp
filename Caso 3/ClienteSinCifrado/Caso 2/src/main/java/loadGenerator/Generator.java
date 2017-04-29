package loadGenerator;

import uniandes.gload.core.LoadGenerator;
import uniandes.gload.core.Task;

import java.util.concurrent.TimeUnit;

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

		int numberOfTasks = 100;
		int gapBetweenTasks = 10;

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
