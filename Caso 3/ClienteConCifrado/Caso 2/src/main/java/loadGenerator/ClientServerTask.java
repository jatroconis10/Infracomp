package loadGenerator;

import java.net.ConnectException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.concurrent.CopyOnWriteArrayList;

import main.Main;
import uniandes.gload.core.Task;

public class ClientServerTask extends Task{

	public static java.util.concurrent.CopyOnWriteArrayList<Long> tAuthServ = new CopyOnWriteArrayList<>();
	public static java.util.concurrent.CopyOnWriteArrayList<Long> tResp = new CopyOnWriteArrayList<>();
	
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
		String hostName = "172.24.42.60";
        int portNumber  = 8900;
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
