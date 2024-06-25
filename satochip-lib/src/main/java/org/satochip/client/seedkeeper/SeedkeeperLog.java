package org.satochip.client.seedkeeper;

public class SeedkeeperLog {

    public static final int LOG_SIZE = 7; // bytes

    public int sw;
    public byte ins;
    public int sid1;
    public int sid2;

    public SeedkeeperLog(byte[] response) throws Exception {
        if (response.length < LOG_SIZE) {
            System.out.println("Log record has the wrong length " + response.length + ", should be " + LOG_SIZE);
            throw new Exception("Log record has the wrong length " + response.length + ", should be " + LOG_SIZE);
        }

        sw = (response[5] & 0xFF) * 256 + (response[6] & 0xFF);
        sid1 = (response[1] & 0xFF) * 256 + (response[2] & 0xFF);
        sid2 = (response[3] & 0xFF) * 256 + (response[4] & 0xFF);
        ins = response[0];
    }
}
