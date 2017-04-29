package loadGenerator;

import main.Main;
import uniandes.gload.core.Task;

import java.util.concurrent.CopyOnWriteArrayList;

public class ClientServerTask extends Task{

	public static CopyOnWriteArrayList<Long> tAuthServ = new CopyOnWriteArrayList<>();
	public static CopyOnWriteArrayList<Long> tResp = new CopyOnWriteArrayList<>();
	
	private Main cliente;
	
	@Override
	public void fail() {
		// TODO Auto-generated method stub
        System.out.println("f");
    }

	@Override
	public void success() {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void execute() {
		// TODO Auto-generated method stub
		String hostName = "localhost";
        int portNumber  = 8654;
        try {
            cliente = new Main();
            cliente.runCliente(hostName, portNumber);
            tAuthServ.add(cliente.tiemposAuthServ);
            tResp.add(cliente.tiemposResp);
        }catch (Exception e){
            fail();
        }
	}

}
