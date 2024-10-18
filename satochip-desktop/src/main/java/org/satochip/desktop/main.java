package org.satochip.desktop;

import org.satochip.client.*;
import org.satochip.io.*;

import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;

import java.util.List;
import java.io.IOException;
import java.io.*;
import java.nio.charset.Charset;

class Main {
    public static void main(String[] args) throws CardException, IOException, Exception {
        System.out.println("Hello World!"); 
				
		TerminalFactory tf = TerminalFactory.getDefault();
        List< CardTerminal> terminals = tf.terminals().list();
        System.out.println("Available Readers:");
        System.out.println(terminals + "\n");
        CardTerminal cardTerminal = (CardTerminal) terminals.get(0);
		System.out.println("Selected Reader:");
        System.out.println(cardTerminal + "\n");
        Card connection = cardTerminal.connect("*");
        CardChannel cardChannel = connection.getBasicChannel();
		
		//send select APDU:
		// byte[] SATOCHIP_AID= {0x53, 0x61, 0x74, 0x6f, 0x43, 0x68, 0x69, 0x70}; //5361746f43686970
		// CommandAPDU capdu= new CommandAPDU(0x00, 0xA4, 0x04, 0x00, SATOCHIP_AID);
		// byte[] raw= capdu.getBytes();
		
		// String HEXES = "0123456789ABCDEF";
		// final StringBuilder hex = new StringBuilder( 2 * raw.length );
        // for ( final byte b : raw ) {
           // hex.append(HEXES.charAt((b & 0xF0) >> 4))
         // .append(HEXES.charAt((b & 0x0F)));
        // }
        // System.out.println("capdu:" + hex.toString());
		// System.out.println("capdu:" + capdu.toString());
		// ResponseAPDU rapdu = cardChannel.transmit(capdu);
		// System.out.println("rapdu:" + rapdu.toString());
		
		// wrapper
		PCSCCardChannel channel= new PCSCCardChannel(cardChannel);
		SatochipCommandSet cc= new SatochipCommandSet(channel);
		
		APDUResponse resp1= cc.cardSelect();
		APDUResponse resp2= cc.cardGetStatus();
    
        String pinStr= "123456";
        byte[] pin= pinStr.getBytes(Charset.forName("UTF-8"));
        cc.setPin0(pin);
        APDUResponse resp3= cc.cardVerifyPIN();
    
		cc.cardGetAuthentikey();
    
        APDUResponse resp5= cc.cardResetSeed(pin, null);
        
        byte[] seed= new byte[32];
        APDUResponse resp6= cc.cardBip32ImportSeed(seed);

		System.out.println("Goodbye World !");
    }
}