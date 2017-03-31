package Excepciones;

/**
 * Created by ja.troconis10 on 31/03/2017.
 */
public class ProtocolException extends Exception {
    //Parameterless Constructor
    public ProtocolException() {}

    //Constructor that accepts a message
    public ProtocolException(String message)
    {
        super(message);
    }
}
